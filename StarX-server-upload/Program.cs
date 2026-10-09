using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.HttpOverrides;
using StarX.Licensing;

if (args.Contains("--self-test")) { SelfTests.Run(); return; }
var builder = WebApplication.CreateBuilder(new WebApplicationOptions {
    Args = args,
    WebRootPath = Path.Combine(AppContext.BaseDirectory, "wwwroot")
});
builder.Logging.AddFilter("Microsoft.AspNetCore", LogLevel.Warning);
builder.WebHost.ConfigureKestrel(options => options.Limits.MaxRequestBodySize = 65536);
bool development = Environment.GetEnvironmentVariable("STARX_DEVELOPMENT") == "1";
string Env(string name) => Environment.GetEnvironmentVariable(name) ?? "";
string origin = (Env("PUBLIC_BASE_URL") is { Length: > 0 } configuredOrigin
    ? configuredOrigin : Env("RENDER_EXTERNAL_URL")).TrimEnd('/');
if (!Uri.TryCreate(origin, UriKind.Absolute, out var publicAddress) ||
    (publicAddress.Scheme != "https" && !(development && publicAddress.IsLoopback)))
    throw new InvalidOperationException("Set PUBLIC_BASE_URL to your public HTTPS address.");
var settings = new PaymentSettings(origin, Env("STRIPE_SECRET_KEY"), Env("STRIPE_WEBHOOK_SECRET"),
    Env("STRIPE_LIFETIME_PRICE"), Env("STRIPE_MONTHLY_PRICE"), Env("STRIPE_THREE_DAY_PRICE"), Env("PAYMENTS_MODE") == "live", Env("STRIPE_WEEKLY_PRICE"));
string adminSecret = Env("ADMIN_SECRET");
if (adminSecret.Length < 64) throw new InvalidOperationException("ADMIN_SECRET needs at least 64 random characters.");
using var licenses = Env("SUPABASE_URL") is { Length: > 0 } supabaseUrl
    ? new LicenseStore(Env("LICENSING_SECRET"), new SupabaseStore(supabaseUrl, Env("SUPABASE_SECRET_KEY")))
    : new LicenseStore(Env("LICENSE_DATABASE") is { Length: > 0 } db ? db : "data/licenses.json", Env("LICENSING_SECRET"));
var payments = new Payments(settings, licenses);
builder.Services.Configure<ForwardedHeadersOptions>(options => {
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    if (IPAddress.TryParse(Env("TRUSTED_PROXY_IP"), out var proxy)) options.KnownProxies.Add(proxy);
});
builder.Services.AddRateLimiter(options => {
    options.RejectionStatusCode = 429;
    options.AddPolicy("requests", context => RateLimitPartition.GetFixedWindowLimiter(
        context.Connection.RemoteIpAddress?.ToString() ?? "unknown", _ => new FixedWindowRateLimiterOptions {
            PermitLimit = 30, Window = TimeSpan.FromMinutes(1), QueueLimit = 0, AutoReplenishment = true
        }));
});
var app = builder.Build();
app.UseForwardedHeaders();
app.Use(async (context, next) => {
    context.Response.Headers.CacheControl = "no-store";
    context.Response.Headers["Referrer-Policy"] = "no-referrer";
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["Content-Security-Policy"] = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; form-action 'self' https://checkout.stripe.com https://billing.stripe.com; frame-ancestors 'none'; base-uri 'none'";
    if (!development && !context.Request.IsHttps) { context.Response.StatusCode = 400; await context.Response.WriteAsync("HTTPS is required."); return; }
    try { await next(context); }
    catch (Exception exception) when (exception is not OperationCanceledException) {
        app.Logger.LogError("A StarX request failed ({Type}).", exception.GetType().Name);
        if (!context.Response.HasStarted) {
            context.Response.StatusCode = 503;
            await context.Response.WriteAsync("The license/payment service is temporarily unavailable. Try again later.");
        }
    }
});
app.UseRateLimiter();
app.UseDefaultFiles();
app.UseStaticFiles();
app.MapGet("/api/public-config", () => Results.Json(new {
    checkoutReady = settings.Configured, paymentsMode = settings.Live ? "live" : "test", supportEmail = Env("SUPPORT_EMAIL")
}));

string Page(string title, string body) => "<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>"
    + WebUtility.HtmlEncode(title) + " - StarX</title><style>body{background:#101116;color:#eee;font:17px system-ui;max-width:720px;margin:10vh auto;padding:24px}h1{color:#f04951}button{background:#af2031;color:white;border:0;border-radius:8px;padding:14px 22px;font:inherit;cursor:pointer}section{background:#1b1d25;border-radius:12px;padding:20px;margin:20px 0}code{display:block;overflow-wrap:anywhere;background:#272a33;padding:20px}a{color:#fb9ea4}small{color:#afb2bd}input{max-width:100%}</style><h1>STARX</h1>" + body + "</html>";
app.MapGet("/healthz", () => Results.Text("ok"));
app.MapGet("/", () => Results.Redirect("/purchase"));
app.MapGet("/purchase", () => {
    string mode = settings.Live ? "" : "<p><strong>Test checkout: no real money is charged.</strong></p>";
    string disabled = settings.Configured ? "" : " disabled";
    string Cards(string plan, string title, string price, string detail) => "<section><h2>" + title + "</h2><p>" + price
        + "</p><p>" + detail + "</p><form method=post action=/checkout><input type=hidden name=plan value='" + plan
        + "'><button" + disabled + ">Buy " + title + "</button></form></section>";
    string body = "<h2>Choose your StarX key</h2><p>Each key activates one Windows installation. Once redeemed, it cannot be shared or activated on another installation.</p>" + mode
        + (settings.Configured ? "" : "<p>Purchases are not connected yet. The seller needs to finish the payment setup.</p>")
        + Cards("three-day", "3 days", "AU$2.75 once", "72 hours from your first activation. No automatic renewal.")
        + Cards("weekly", "Weekly", "AU$5 per week", "Renews each week until canceled. One Windows installation.")
        + Cards("monthly", "Monthly", "AU$10 per month", "Renews each month until canceled. Manage renewal through the Stripe receipt link provided by the seller.")
        + Cards("lifetime", "Lifetime", "AU$25 once", "No scheduled expiry. Requires internet to verify the license.")
        + "<p>After confirmed payment, the next page shows your key. Save the key and your purchase receipt.</p>";
    return Results.Content(Page("Buy a key", body), "text/html; charset=utf-8");
}).RequireRateLimiting("requests");
app.MapPost("/checkout", async (HttpContext context) => {
    if (!settings.Configured) return Results.Text("Purchases are not connected yet.", statusCode: 503);
    var form = await context.Request.ReadFormAsync();
    string plan = form["plan"].ToString();
    if (plan is not ("lifetime" or "weekly" or "monthly" or "three-day")) return Results.BadRequest("Choose a valid plan.");
    string url = await payments.Checkout(plan);
    context.Response.StatusCode = 303;
    context.Response.Headers.Location = url;
    return Results.Empty;
}).RequireRateLimiting("requests");
app.MapGet("/purchase/success", async (HttpContext context) => {
    try {
        string key = await payments.Fulfill(context.Request.Query["session_id"].ToString());
        return Results.Content(Page("Your license", "<h2>Your StarX license key</h2><code>" + WebUtility.HtmlEncode(key)
            + "</code><p>Copy this key into StarX and click Activate. The first activation binds it to that Windows installation.</p><p>Save this page and your receipt. Your key must remain private.</p>"), "text/html; charset=utf-8");
    } catch (Exception exception) when (exception is InvalidOperationException or ArgumentException) {
        return Results.Content(Page("Purchase status", "<p>" + WebUtility.HtmlEncode(exception.Message) + "</p><p><a href=/purchase>Back to plans</a></p>"), "text/html; charset=utf-8", statusCode: 409);
    }
}).RequireRateLimiting("requests");
app.MapPost("/api/activate", async (HttpContext context) => {
    var form = await context.Request.ReadFormAsync();
    string? error = licenses.Activate(form["key"].ToString(), form["installation"].ToString(), DateTimeOffset.UtcNow.ToUnixTimeSeconds());
    return error is null ? Results.Text(settings.Live ? "STARX-ACTIVE\nLIVE\n" : "STARX-ACTIVE\nTEST\n")
                        : Results.Text(error, statusCode: 403);
}).RequireRateLimiting("requests");
app.MapPost("/webhooks/stripe", async (HttpContext context) => {
    using var body = new MemoryStream();
    await context.Request.Body.CopyToAsync(body);
    byte[] raw = body.ToArray();
    if (!WebhookSignature.Verify(raw, context.Request.Headers["Stripe-Signature"].ToString(), settings.WebhookSecret,
        DateTimeOffset.UtcNow.ToUnixTimeSeconds())) return Results.BadRequest("Invalid webhook signature.");
    using var document = JsonDocument.Parse(raw);
    await payments.Event(document.RootElement);
    return Results.Ok();
});
bool AdminAllowed(HttpContext context) {
    string supplied = context.Request.Headers.Authorization.ToString();
    if (!supplied.StartsWith("Bearer ", StringComparison.Ordinal)) return false;
    return CryptographicOperations.FixedTimeEquals(SHA256.HashData(Encoding.UTF8.GetBytes(adminSecret)),
        SHA256.HashData(Encoding.UTF8.GetBytes(supplied[7..])));
}
app.MapPost("/admin/issue", async (HttpContext context) => {
    if (!AdminAllowed(context)) return Results.Unauthorized();
    var form = await context.Request.ReadFormAsync();
    string plan = form["plan"].ToString();
    if (plan is not ("lifetime" or "three-day"))
        return Results.BadRequest("Manual keys support lifetime or three-day access. Monthly keys require a paid subscription.");
    string session = "manual_" + Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
    licenses.Issue(session, plan, null, null, null);
    return Results.Json(new { key = licenses.KeyForSession(session), plan });
}).RequireRateLimiting("requests");
foreach (string action in new[] { "revoke", "reset-installation" }) {
    string operation = action;
    app.MapPost("/admin/" + action, async (HttpContext context) => {
        if (!AdminAllowed(context)) return Results.Unauthorized();
        var form = await context.Request.ReadFormAsync();
        return licenses.AdminChange(form["key"].ToString(), operation == "reset-installation") ? Results.Ok() : Results.NotFound();
    }).RequireRateLimiting("requests");
}
app.Run();
