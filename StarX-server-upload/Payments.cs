using System.Net.Http.Headers;
using System.Text.Json;

namespace StarX.Licensing;

public sealed record PaymentSettings(string Origin, string SecretKey, string WebhookSecret,
                                     string LifetimePrice, string MonthlyPrice, string ThreeDayPrice, bool Live, string WeeklyPrice = "")
{
    public bool Configured => SecretKey.StartsWith(Live ? "sk_live_" : "sk_test_", StringComparison.Ordinal)
        && WebhookSecret.StartsWith("whsec_", StringComparison.Ordinal)
        && LifetimePrice.StartsWith("price_", StringComparison.Ordinal) && MonthlyPrice.StartsWith("price_", StringComparison.Ordinal)
        && ThreeDayPrice.StartsWith("price_", StringComparison.Ordinal) && WeeklyPrice.StartsWith("price_", StringComparison.Ordinal);
}

public sealed class Payments(PaymentSettings settings, LicenseStore licenses)
{
    private readonly HttpClient client = new() { BaseAddress = new Uri("https://api.stripe.com/v1/"), Timeout = TimeSpan.FromSeconds(20) };

    private async Task<JsonDocument> Request(string path, Dictionary<string, string>? form = null)
    {
        using var request = new HttpRequestMessage(form is null ? HttpMethod.Get : HttpMethod.Post, path);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", settings.SecretKey);
        if (form is not null) request.Content = new FormUrlEncodedContent(form);
        using var response = await client.SendAsync(request);
        if (!response.IsSuccessStatusCode) throw new InvalidOperationException("Payment provider request failed. Check the server configuration.");
        return JsonDocument.Parse(await response.Content.ReadAsStringAsync());
    }

    public async Task<string> Checkout(string plan)
    {
        if (!settings.Configured) throw new InvalidOperationException("Purchases are not connected yet.");
        if (plan is not ("lifetime" or "weekly" or "monthly" or "three-day")) throw new ArgumentException("Choose lifetime, weekly, monthly, or three-day.");
        using var session = await Request("checkout/sessions", new() {
            ["mode"] = plan is "monthly" or "weekly" ? "subscription" : "payment",
            ["line_items[0][price]"] = plan == "weekly" ? settings.WeeklyPrice : plan == "monthly" ? settings.MonthlyPrice : plan == "three-day" ? settings.ThreeDayPrice : settings.LifetimePrice,
            ["line_items[0][quantity]"] = "1", ["metadata[starx_plan]"] = plan,
            ["success_url"] = settings.Origin + "/purchase/success?session_id={CHECKOUT_SESSION_ID}",
            ["cancel_url"] = settings.Origin + "/purchase",
            ["billing_address_collection"] = "auto"
        });
        string url = session.RootElement.GetProperty("url").GetString()!;
        if (!Uri.TryCreate(url, UriKind.Absolute, out var location) || location.Scheme != "https" || location.Host != "checkout.stripe.com")
            throw new InvalidOperationException("Payment provider returned an invalid checkout address.");
        return url;
    }

    public async Task<string> Fulfill(string sessionId)
    {
        if (!settings.Configured || !sessionId.StartsWith("cs_", StringComparison.Ordinal) || sessionId.Length > 200)
            throw new ArgumentException("Invalid purchase reference.");
        using var document = await Request("checkout/sessions/" + Uri.EscapeDataString(sessionId) + "?expand%5B%5D=line_items");
        var session = document.RootElement;
        if (session.GetProperty("payment_status").GetString() != "paid") throw new InvalidOperationException("Payment is still processing. Refresh this page after payment completes.");
        if (session.GetProperty("livemode").GetBoolean() != settings.Live) throw new InvalidOperationException("Purchase mode does not match this server.");
        var items = session.GetProperty("line_items").GetProperty("data");
        if (items.GetArrayLength() != 1 || items[0].GetProperty("quantity").GetInt32() != 1)
            throw new InvalidOperationException("This purchase is not a StarX license.");
        string? price = items[0].GetProperty("price").GetProperty("id").GetString();
        string plan = price == settings.LifetimePrice ? "lifetime" : price == settings.MonthlyPrice ? "monthly"
            : price == settings.WeeklyPrice ? "weekly" : price == settings.ThreeDayPrice ? "three-day"
            : throw new InvalidOperationException("This purchase is not a configured StarX product.");
        var paidPrice = items[0].GetProperty("price");
        int expectedAmount = plan == "lifetime" ? 2500 : plan == "monthly" ? 1000 : plan == "weekly" ? 500 : 275;
        if (paidPrice.GetProperty("currency").GetString() != "aud" || paidPrice.GetProperty("unit_amount").GetInt32() != expectedAmount)
            throw new InvalidOperationException("The product price must match the configured AUD StarX prices.");
        if (session.GetProperty("mode").GetString() != (plan is "monthly" or "weekly" ? "subscription" : "payment"))
            throw new InvalidOperationException("The purchase type is incorrect.");
        if (plan is "monthly" or "weekly") {
            var recurring = paidPrice.GetProperty("recurring");
            if (recurring.GetProperty("interval").GetString() != (plan == "weekly" ? "week" : "month")
                || recurring.GetProperty("interval_count").GetInt32() != 1)
                throw new InvalidOperationException("The subscription billing interval is incorrect.");
        }
        string? subscription = OptionalId(session, "subscription"), payment = OptionalId(session, "payment_intent");
        long? expiry = null;
        if (plan is "monthly" or "weekly") {
            if (subscription is null) throw new InvalidOperationException("Subscription is missing.");
            var state = await SubscriptionState(subscription);
            if (!state.Active) throw new InvalidOperationException("This subscription is not active.");
            expiry = state.Expiry;
        }
        License license = licenses.Issue(sessionId, plan, subscription, payment, expiry);
        if (!license.Active || license.RevokedReason is not null) throw new InvalidOperationException("This purchase has been revoked. Contact the seller.");
        return licenses.KeyForSession(sessionId);
    }

    private async Task<(bool Active, long Expiry)> SubscriptionState(string id)
    {
        using var document = await Request("subscriptions/" + Uri.EscapeDataString(id));
        var subscription = document.RootElement;
        bool active = subscription.GetProperty("status").GetString() == "active";
        long expiry = subscription.TryGetProperty("current_period_end", out var legacy) ? legacy.GetInt64() : 0;
        foreach (var item in subscription.GetProperty("items").GetProperty("data").EnumerateArray()) {
            string? itemPrice = item.GetProperty("price").GetProperty("id").GetString(); if (itemPrice != settings.MonthlyPrice && itemPrice != settings.WeeklyPrice) continue;
            if (item.TryGetProperty("current_period_end", out var end)) expiry = end.GetInt64();
        }
        if (expiry <= 0) throw new InvalidOperationException("Could not verify the subscription billing period.");
        return (active, expiry);
    }

    public async Task Event(JsonElement stripeEvent)
    {
        string type = stripeEvent.GetProperty("type").GetString()!;
        var item = stripeEvent.GetProperty("data").GetProperty("object");
        if (stripeEvent.GetProperty("livemode").GetBoolean() != settings.Live) return;
        if (type is "checkout.session.completed" or "checkout.session.async_payment_succeeded") {
            if (item.GetProperty("payment_status").GetString() == "paid") await Fulfill(item.GetProperty("id").GetString()!);
        } else if (type is "customer.subscription.updated" or "customer.subscription.deleted" || type == "invoice.paid") {
            string? id = type.StartsWith("customer.subscription.", StringComparison.Ordinal) ? item.GetProperty("id").GetString() : OptionalId(item, "subscription");
            if (id is null && item.TryGetProperty("parent", out var parent) && parent.TryGetProperty("subscription_details", out var details)) id = OptionalId(details, "subscription");
            if (id is not null) { var state = await SubscriptionState(id); licenses.UpdateSubscription(id, state.Active, state.Expiry); }
        } else if (type is "charge.refunded" or "charge.dispute.created") {
            string? payment = OptionalId(item, "payment_intent");
            if (payment is null && OptionalId(item, "charge") is string charge) {
                using var document = await Request("charges/" + Uri.EscapeDataString(charge));
                payment = OptionalId(document.RootElement, "payment_intent");
            }
            if (payment is not null) licenses.RevokePayment(payment);
        }
    }

    private static string? OptionalId(JsonElement element, string name) => element.TryGetProperty(name, out var value)
        ? value.ValueKind == JsonValueKind.String ? value.GetString() : value.ValueKind == JsonValueKind.Object ? value.GetProperty("id").GetString() : null : null;
}
