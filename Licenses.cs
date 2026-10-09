using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace StarX.Licensing;

public sealed class License
{
    public required string KeyHash { get; init; }
    public required string SessionId { get; init; }
    public required string Plan { get; init; }
    public string? SubscriptionId { get; init; }
    public string? PaymentIntent { get; init; }
    public string? DeviceHash { get; set; }
    public long? ExpiresAt { get; set; }
    public long? DurationSeconds { get; init; }
    public bool Active { get; set; } = true;
    public string? RevokedReason { get; set; }
}

public sealed class Database
{
    public Dictionary<string, License> Licenses { get; set; } = [];
    public HashSet<string> RevokedPayments { get; set; } = [];
}

// One server instance owns this durable store. Updates commit before success is returned.
public sealed class LicenseStore : IDisposable
{
    private readonly object gate = new();
    private readonly string path = "";
    private readonly byte[] secret;
    private readonly FileStream? processLock;
    private readonly SupabaseStore? remote;
    private Database database = new();

    public LicenseStore(string secret, SupabaseStore remote)
    {
        if (secret.Length < 64) throw new ArgumentException("LICENSING_SECRET must contain at least 64 random characters.");
        this.secret = Encoding.UTF8.GetBytes(secret);
        this.remote = remote;
    }

    public LicenseStore(string path, string secret)
    {
        if (secret.Length < 64) throw new ArgumentException("LICENSING_SECRET must contain at least 64 random characters.");
        this.path = Path.GetFullPath(path);
        this.secret = Encoding.UTF8.GetBytes(secret);
        Directory.CreateDirectory(Path.GetDirectoryName(this.path)!);
        processLock = new FileStream(this.path + ".lock", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        database = File.Exists(this.path) ? JsonSerializer.Deserialize<Database>(File.ReadAllText(this.path))
            ?? throw new InvalidDataException("License database is invalid.") : new Database();
    }

    public string KeyForSession(string sessionId) => "SX1-" + Convert.ToHexString(
        HMACSHA256.HashData(secret, Encoding.UTF8.GetBytes("license:" + sessionId)).AsSpan(0, 24));
    public static string KeyHash(string key) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(key.Trim().ToUpperInvariant())));
    private string DeviceHash(string device) => Convert.ToHexString(HMACSHA256.HashData(secret, Encoding.UTF8.GetBytes("installation:" + device)));

    private T Change<T>(Func<Database, T> action)
    {
        lock (gate) {
            if (remote is not null) {
                for (int attempt = 0; attempt < 20; attempt++) {
                    var snapshot = remote.Read();
                    T value = action(snapshot.Data);
                    if (remote.Commit(snapshot.Version, snapshot.Data)) return value;
                }
                throw new InvalidOperationException("License database is busy. Retry the request.");
            }
            var next = JsonSerializer.Deserialize<Database>(JsonSerializer.Serialize(database))!;
            T result = action(next);
            string temporary = path + ".new";
            byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(next);
            using (var file = new FileStream(temporary, FileMode.Create, FileAccess.Write, FileShare.None)) {
                file.Write(bytes);
                file.Flush(flushToDisk: true);
            }
            File.Move(temporary, path, overwrite: true);
            database = next;
            return result;
        }
    }

    public License Issue(string sessionId, string plan, string? subscription, string? payment, long? expires)
    {
        string hash = KeyHash(KeyForSession(sessionId));
        return Change(db => {
            if (db.Licenses.TryGetValue(hash, out var previous)) return previous;
            bool refunded = payment is not null && db.RevokedPayments.Contains(payment);
            var license = new License { KeyHash = hash, SessionId = sessionId, Plan = plan,
                SubscriptionId = subscription, PaymentIntent = payment, ExpiresAt = expires,
                DurationSeconds = plan switch {
                    "three-day" => 3 * 24 * 60 * 60,
                    "weekly-pass" => 7 * 24 * 60 * 60,
                    "monthly-pass" => 30 * 24 * 60 * 60,
                    _ => (long?)null
                },
                Active = !refunded, RevokedReason = refunded ? "Payment refunded or disputed." : null };
            db.Licenses.Add(hash, license);
            return license;
        });
    }

    public string[] IssueLifetimeBatch(string batchId, int count)
    {
        if (!Regex.IsMatch(batchId, "^[a-f0-9]{32}$") || count is < 1 or > 10000)
            throw new ArgumentException("Use a 32-character batch ID and a count between 1 and 10000.");
        string[] sessions = Enumerable.Range(0, count).Select(i => $"bulk_lifetime_{batchId}_{i}").ToArray();
        string[] keys = sessions.Select(KeyForSession).ToArray();
        return Change(db => {
            for (int i = 0; i < count; i++) {
                string hash = KeyHash(keys[i]);
                if (!db.Licenses.ContainsKey(hash))
                    db.Licenses.Add(hash, new License { KeyHash = hash, SessionId = sessions[i], Plan = "lifetime" });
            }
            return keys;
        });
    }

    public string? Activate(string key, string device, long now)
    {
        key = key.Trim().ToUpperInvariant();
        if (!Regex.IsMatch(key, "^SX1-[A-F0-9]{48}$")) return "Enter the complete StarX license key from your purchase.";
        if (!Regex.IsMatch(device, "^[a-f0-9]{32}$")) return "The installation identifier is invalid.";
        string hash = KeyHash(key), deviceHash = DeviceHash(device);
        return Change(db => {
            if (!db.Licenses.TryGetValue(hash, out var license)) return "This key was not found. Check your purchase key.";
            if (!license.Active || license.RevokedReason is not null || (license.ExpiresAt is long expiry && expiry <= now))
                return "This license is inactive or expired. Check your payment or contact the seller.";
            if (license.DeviceHash is not null && license.DeviceHash != deviceHash)
                return "This key is already redeemed on another Windows installation. It cannot be redeemed again.";
            license.DeviceHash ??= deviceHash;
            if (license.DurationSeconds is long duration && license.ExpiresAt is null) license.ExpiresAt = now + duration;
            return (string?)null;
        });
    }

    public void UpdateSubscription(string id, bool active, long expiry) => Change(db => {
        foreach (License license in db.Licenses.Values.Where(x => x.SubscriptionId == id)) {
            if (license.RevokedReason is not null) continue;
            license.Active = active;
            license.ExpiresAt = expiry;
        }
        return true;
    });

    public void RevokePayment(string payment) => Change(db => {
        db.RevokedPayments.Add(payment);
        foreach (License license in db.Licenses.Values.Where(x => x.PaymentIntent == payment)) {
            license.Active = false;
            license.RevokedReason = "Payment refunded or disputed.";
        }
        return true;
    });

    public bool AdminChange(string key, bool resetInstallation) => Change(db => {
        if (!db.Licenses.TryGetValue(KeyHash(key), out var license)) return false;
        if (resetInstallation) license.DeviceHash = null;
        else { license.Active = false; license.RevokedReason = "Revoked by the seller."; }
        return true;
    });
    public void Dispose() { processLock?.Dispose(); remote?.Dispose(); }
}

public static class WebhookSignature
{
    public static bool Verify(byte[] body, string header, string secret, long now)
    {
        if (secret.Length < 16) return false;
        var entries = header.Split(',').Select(x => x.Split('=', 2)).Where(x => x.Length == 2).ToArray();
        string? stamp = entries.FirstOrDefault(x => x[0] == "t")?[1];
        if (!long.TryParse(stamp, out long timestamp) || timestamp < now - 300 || timestamp > now + 300) return false;
        byte[] prefix = Encoding.ASCII.GetBytes(stamp + ".");
        byte[] payload = new byte[prefix.Length + body.Length];
        prefix.CopyTo(payload, 0); body.CopyTo(payload, prefix.Length);
        byte[] expected = HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), payload);
        foreach (var candidate in entries.Where(x => x[0] == "v1")) {
            try { if (CryptographicOperations.FixedTimeEquals(expected, Convert.FromHexString(candidate[1]))) return true; }
            catch (FormatException) { }
        }
        return false;
    }
}
