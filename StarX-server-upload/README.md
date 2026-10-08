# StarX license server

The customer app needs a public HTTPS server before keys can activate. This project includes Docker Compose and Caddy for HTTPS. Run one licensing instance with durable storage; back up the license database and keep LICENSING_SECRET unchanged to preserve existing keys.

## Hosting setup

1. Obtain a domain and a server that can run Docker Compose. Point the domain's DNS to that server and allow ports 80 and 443.
2. Copy `.env.example` to `seller-config.env`. Set the real domain and public HTTPS URL. Generate independent random secrets of at least 64 characters for LICENSING_SECRET and ADMIN_SECRET. Keep this file private.
3. Set PAYMENTS_MODE=live for the production app. Manual key issuance works without Stripe. To sell keys through checkout, configure the Stripe credentials and price IDs too.
4. Run `docker compose up -d --build` from this directory. Confirm `/healthz` returns `ok` over HTTPS.
5. Configure the desktop build with `-DSTARX_LICENSE_SERVER=https://your-domain -DSTARX_LICENSE_TEST_MODE=OFF`, rebuild Release, and package that executable for customers.

## Issue your lifetime key

After the server is running, use PowerShell. Set `$env:STARX_ADMIN_SECRET` locally to the server's ADMIN_SECRET; never include it in the customer app or ZIP.

```powershell
$server = 'https://your-domain'
$headers = @{ Authorization = 'Bearer ' + $env:STARX_ADMIN_SECRET }
Invoke-RestMethod -Method Post -Uri "$server/admin/issue" -Headers $headers -Body @{plan='lifetime'}
```

The response contains a newly registered key with no scheduled expiry. Save it privately, then enter it in the app configured for this server. First activation binds it to one installation. `plan=three-day` issues a key valid for 72 hours from first activation. Monthly access uses paid subscriptions.

To revoke a key or allow activation after a reinstall, send an authenticated POST to `/admin/revoke` or `/admin/reset-installation` with form field `key`. Resetting a binding does not reactivate a revoked license.

## Validation

Run `dotnet run -- --self-test` to check concurrent redemption, device binding, lifetime and timed access, renewals, revocation, persistence, and webhook signatures. A local test server uses STARX_DEVELOPMENT=1, a loopback PUBLIC_BASE_URL, and PAYMENTS_MODE=test. Only desktop builds with STARX_LICENSE_TEST_MODE=ON accept test-server activation responses.
