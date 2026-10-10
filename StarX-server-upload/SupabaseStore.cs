using System.Net.Http.Json;
using System.Text.Json;

namespace StarX.Licensing;

// Version checks in PostgreSQL prevent two server instances redeeming the same key.
public sealed class SupabaseStore : IDisposable
{
    private readonly HttpClient client;
    public SupabaseStore(string url, string key, HttpMessageHandler? handler = null)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme != "https" ||
            !string.IsNullOrEmpty(uri.UserInfo) || !string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment))
            throw new ArgumentException("SUPABASE_URL must be an HTTPS project URL.");
        if (!key.StartsWith("sb_secret_", StringComparison.Ordinal))
            throw new ArgumentException("Set SUPABASE_SECRET_KEY to a server-side Supabase secret key.");
        client = handler is null ? new HttpClient(new HttpClientHandler {
            AutomaticDecompression = System.Net.DecompressionMethods.All
        }) : new HttpClient(handler);
        client.BaseAddress = new Uri(url.TrimEnd('/') + "/rest/v1/rpc/");
        client.Timeout = TimeSpan.FromSeconds(20);
        client.DefaultRequestHeaders.Add("apikey", key);
    }
    private JsonDocument Call(string function, object body)
    {
        using var response = client.PostAsJsonAsync(function, body,
            new JsonSerializerOptions { PropertyNamingPolicy = null }).GetAwaiter().GetResult();
        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException("Supabase license storage request failed (HTTP " + (int)response.StatusCode + ").");
        return JsonDocument.Parse(response.Content.ReadAsStringAsync().GetAwaiter().GetResult());
    }
    public (long Version, Database Data) Read()
    {
        using var result = Call("starx_read", new { });
        return (result.RootElement.GetProperty("version").GetInt64(),
            result.RootElement.GetProperty("data").Deserialize<Database>() ?? throw new InvalidDataException("Invalid license database."));
    }
    public bool Commit(long version, Database data)
    {
        using var result = Call("starx_commit", new { expected_version = version, new_data = data });
        return result.RootElement.GetBoolean();
    }
    public License? ReadLicense(string hash)
    {
        if (hash.Length != 64 || hash.Any(c => !Uri.IsHexDigit(c))) throw new ArgumentException("Invalid key hash.");
        // PostgREST projects just this JSON property; never transfer the complete
        // inventory to validate an existing key. Existing table permissions apply.
        string select = Uri.EscapeDataString("license:data->Licenses->" + hash);
        using var response = client.GetAsync("../starx_state?id=eq.1&select=" + select).GetAwaiter().GetResult();
        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException("Supabase license lookup failed (HTTP " + (int)response.StatusCode + ").");
        using var result = JsonDocument.Parse(response.Content.ReadAsStringAsync().GetAwaiter().GetResult());
        if (result.RootElement.ValueKind != JsonValueKind.Array || result.RootElement.GetArrayLength() != 1)
            throw new InvalidDataException("License storage is unavailable.");
        var license = result.RootElement[0].GetProperty("license");
        return license.ValueKind == JsonValueKind.Null ? null : license.Deserialize<License>();
    }
    public void Dispose() => client.Dispose();
}
