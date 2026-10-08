using System.Security.Cryptography;
using System.Text;

namespace StarX.Licensing;

public static class SelfTests
{
    private static void Check(bool valid, string message) { if (!valid) throw new Exception("FAIL: " + message); }
    public static void Run()
    {
        TestSupabase();
        string root = Path.Combine(Path.GetTempPath(), "StarX-licenses-" + Guid.NewGuid().ToString("N"));
        string path = Path.Combine(root, "licenses.json"), secret = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        const long now = 2_000_000_000;
        string lifetimeKey, threeDayKey;
        using (var store = new LicenseStore(path, secret)) {
            store.Issue("manual_owner", "lifetime", null, null, null);
            string ownerKey = store.KeyForSession("manual_owner");
            Check(store.Activate(ownerKey, "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", now + 3_153_600_000) is null, "manual lifetime key has no scheduled expiry");
            Check(store.AdminChange(ownerKey, false), "administrator can revoke a manually issued key");
            Check(store.Activate(ownerKey, "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", now) is not null, "revoked manual key is rejected");
            store.Issue("cs_test_lifetime", "lifetime", null, "pi_lifetime", null);
            lifetimeKey = store.KeyForSession("cs_test_lifetime");
            var attempts = Enumerable.Range(0, 32).Select(index => Task.Run(() =>
                store.Activate(lifetimeKey, index.ToString("x32"), now))).ToArray();
            Task.WaitAll(attempts);
            int winner = Array.FindIndex(attempts, task => task.Result is null);
            Check(attempts.Count(task => task.Result is null) == 1, "exactly one installation wins simultaneous redemption");
            Check(store.Activate(lifetimeKey, winner.ToString("x32"), now) is null, "the same installation can validate again");
            Check(store.Activate(lifetimeKey, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", now) is not null, "a copied key cannot activate another installation");
            store.Issue("cs_test_three_day", "three-day", null, "pi_three_day", null);
            threeDayKey = store.KeyForSession("cs_test_three_day");
            Check(store.Activate(threeDayKey, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", now) is null, "3-day access starts on redemption");
            Check(store.Activate(threeDayKey, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", now + 259_199) is null, "3-day access works before expiry");
            Check(store.Activate(threeDayKey, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", now + 259_200) is not null, "3-day access expires after 72 hours");
            store.Issue("cs_test_monthly", "monthly", "sub_monthly", null, now + 100);
            string monthlyKey = store.KeyForSession("cs_test_monthly");
            Check(store.Activate(monthlyKey, "cccccccccccccccccccccccccccccccc", now + 100) is not null, "unrenewed monthly access expires");
            store.UpdateSubscription("sub_monthly", true, now + 500);
            Check(store.Activate(monthlyKey, "cccccccccccccccccccccccccccccccc", now + 110) is null, "paid renewal restores the same monthly key");
            store.UpdateSubscription("sub_monthly", false, now + 500);
            Check(store.Activate(monthlyKey, "cccccccccccccccccccccccccccccccc", now + 120) is not null, "an inactive subscription is rejected");
            store.RevokePayment("pi_lifetime");
            Check(store.Activate(lifetimeKey, winner.ToString("x32"), now) is not null, "refunded lifetime access is revoked");
            store.Issue("cs_test_lifetime", "lifetime", null, "pi_lifetime", null);
            Check(store.Activate(lifetimeKey, winner.ToString("x32"), now) is not null, "repeated fulfillment cannot undo revocation");
        }
        using (var store = new LicenseStore(path, secret)) {
            Check(store.Activate(threeDayKey, "dddddddddddddddddddddddddddddddd", now) is not null, "the installation binding survives server restart");
            Check(store.KeyForSession("cs_test_lifetime") == lifetimeKey, "the purchase key can be redisplayed without storing it in plaintext");
        }
        byte[] body = Encoding.UTF8.GetBytes("{\"id\":\"evt_test\"}");
        const string webhookSecret = "whsec_testing_signature_only";
        string signature = Convert.ToHexString(HMACSHA256.HashData(Encoding.UTF8.GetBytes(webhookSecret), Encoding.UTF8.GetBytes(now + "." + Encoding.UTF8.GetString(body))));
        Check(WebhookSignature.Verify(body, $"t={now},v1={signature}", webhookSecret, now), "authentic webhook signature is accepted");
        Check(!WebhookSignature.Verify(Encoding.UTF8.GetBytes("{}"), $"t={now},v1={signature}", webhookSecret, now), "modified webhook body is rejected");
        Check(!WebhookSignature.Verify(body, $"t={now},v1={signature}", webhookSecret, now + 301), "old webhook replay is rejected");
        Console.WriteLine("PASS: single-use/concurrent redemption, same-installation validation, durable binding, expiry, renewal, revocation, and webhook signatures.");
        Console.WriteLine("Temporary test database: " + root);
    }

    private static void TestSupabase()
    {
        var handler = new FakeSupabase();
        string secret = new string('a', 64);
        using var store = new LicenseStore(secret, new SupabaseStore("https://test.supabase.co", "sb_secret_test", handler));
        store.Issue("manual_remote", "lifetime", null, null, null);
        string key = store.KeyForSession("manual_remote");
        Check(handler.ConflictSeen, "Supabase version conflict was retried");
        Check(store.Activate(key, new string('a', 32), 100) is null, "Supabase key activates");
        using var other = new LicenseStore(secret, new SupabaseStore("https://test.supabase.co", "sb_secret_test", handler));
        Check(other.Activate(key, new string('b', 32), 100) is not null, "another server observes the stored binding");
        handler.Fail = true;
        bool rejected = false;
        try { other.Activate(key, new string('a', 32), 100); } catch (InvalidOperationException) { rejected = true; }
        Check(rejected, "Supabase outage cannot grant access");
    }

    private sealed class FakeSupabase : HttpMessageHandler
    {
        private Database data = new();
        private long version;
        public bool ConflictSeen, Fail;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Check(request.Headers.GetValues("apikey").Single() == "sb_secret_test", "Supabase server key header");
            if (Fail) return new HttpResponseMessage(System.Net.HttpStatusCode.ServiceUnavailable);
            object result;
            if (request.RequestUri!.AbsolutePath.EndsWith("starx_read")) result = new { version, data };
            else {
                using var body = System.Text.Json.JsonDocument.Parse(await request.Content!.ReadAsStringAsync(cancellationToken));
                if (!ConflictSeen) { ConflictSeen = true; version++; result = false; }
                else if (body.RootElement.GetProperty("expected_version").GetInt64() != version) result = false;
                else { data = System.Text.Json.JsonSerializer.Deserialize<Database>(body.RootElement.GetProperty("new_data"))!; version++; result = true; }
            }
            return new HttpResponseMessage(System.Net.HttpStatusCode.OK) {
                Content = new StringContent(System.Text.Json.JsonSerializer.Serialize(result), Encoding.UTF8, "application/json")
            };
        }
    }
}
