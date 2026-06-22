# Operations

## Local Setup

```bash
python3 -m securitywatchdaily init
python3 -m securitywatchdaily create-admin
python3 -m securitywatchdaily validate
python3 -m securitywatchdaily serve
```

`create-admin` prompts for a local admin password and stores only a salted password hash in SQLite. For scripted local setup, pass
`--password-stdin` and provide the password through stdin instead of putting it on the command line.

After the server starts, open `http://127.0.0.1:8765` and log in with the admin user.

Login creates a server-side session stored in SQLite as a hash of the browser cookie token. The raw session token is not stored in the database. A new login replaces any prior admin session, logout deletes the active session, idle sessions expire after 8 hours, and all sessions expire after 24 hours.

Authenticated web forms include a per-session CSRF token. State-changing POST requests also require an `Origin` header matching the same local app URL, so stale pages, copied form submissions, or cross-origin requests return `403` and should be retried from the current browser page after logging in.

Use **Admin** in the web UI to add or delete local admin users after the first bootstrap account exists. New users use the same `admin` role and password rules as `create-admin`. Deleting an admin user also deletes that user's active sessions. The current account cannot delete itself from the web UI.

## Daily Run

For a scheduled task, run:

```bash
python3 -m securitywatchdaily run
```

Use this command from cron, launchd, Task Scheduler, or another local scheduler.

## Inventory Connectors

Use the local web UI at **Connectors** to view available inventory connectors, enable or disable them, test setup, and run syncs.

CSV import remains the fallback workflow. If a connector fails or a tenant API path is unclear, use **Assets > Import CSV** to keep impact matching available while connector setup is corrected.

Credentials and tenant-specific values are local environment variables, not tracked files:

```bash
export FRESHSERVICE_TENANT_URL="https://yourdomain.freshservice.com"
export FRESHSERVICE_API_KEY="local-api-key"
export FRESHSERVICE_TEST_PATH="/api/v2/assets"
export JAMF_BASE_URL="https://yourcompany.jamfcloud.com"
export INTUNE_TENANT_ID="tenant-id"
export INTUNE_CLIENT_ID="client-id"
export INTUNE_CLIENT_SECRET="local-client-secret"
```

Freshservice connector notes:

- `403` means the API key authenticated but is not authorized for the requested module.
- `404` usually means the endpoint path does not match the tenant or enabled module.
- Do not assume every tenant uses the same asset/software inventory endpoint.

Jamf connector notes:

- Keep Jamf credentials out of tracked files.
- Missing permissions, expired tokens, and wrong base URLs should be handled as setup errors before importing data.

Intune connector notes:

- Live sync is deferred until Microsoft Graph OAuth and tenant consent are designed.
- Use **Connectors > Microsoft Intune > Configure Intune** to save tenant/client metadata and the local environment variable names.
- Expected read permission is `DeviceManagementManagedDevices.Read.All`.
- The client secret value belongs only in the local environment variable named on the setup page.

## Troubleshooting

- If a source fails, check the dashboard source status. Other sources should still complete.
- Source URLs and connector setup-test URLs must use public HTTPS endpoints. Fetches that resolve to localhost, private networks, link-local ranges, multicast ranges, IPv6 unique-local/link-local ranges, or metadata services are blocked before connecting. Redirects are not followed; use the final HTTPS feed URL directly. External feed responses are limited to 5 MB and use a 20-second request timeout; oversized or timing-out sources are recorded as source failures while the rest of the run continues.
- If a connector fails, check its detail page for last failure, sync-run errors, and per-record import errors. Vulnerability collection and CSV import should still work.
- If a platform produces noisy matches, add exclude keywords and use more specific phrases.
- If the web UI shows an unexpected local error, the browser response intentionally omits internal details. Check the local terminal output and retry after fixing the underlying configuration or data issue.
- If the database cannot be opened, check write permissions in the project folder.
- If the UI is unreachable, confirm the local server printed `http://127.0.0.1:8765`.
- If login fails on a new database, confirm `python3 -m securitywatchdaily create-admin` has been run for that database path.

## Safety Notes

- Do not commit real API keys or customer secrets.
- Keep source URLs public unless secret handling has been designed.
- Do not commit generated databases, connector logs, imported asset data, customer exports, or trace/run output.
- Keep the server bound to `127.0.0.1` for local use.
- The web UI requires a local admin login. Passwords and raw session tokens are never stored in plaintext.
- Manage additional local admin users from **Admin** after creating the first bootstrap account.
- Session cookies are `HttpOnly`, `SameSite=Strict`, and scoped to `/`. They intentionally omit `Secure` for localhost HTTP until HTTPS or reviewed shared-mode support is added.
- Non-loopback hosts such as `0.0.0.0`, `::`, or LAN addresses are rejected in local mode. The `--shared`
  flag exists as an explicit future shared-mode request, but startup still fails closed until later shared-mode
  prerequisites such as browser security headers, upload hardening, audit events, and secure deployment settings
  are implemented.
