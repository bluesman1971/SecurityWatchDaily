# Operations

## Local Setup

```bash
python3 -m securitywatchdaily init
python3 -m securitywatchdaily validate
python3 -m securitywatchdaily serve
```

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
- If a connector fails, check its detail page for last failure, sync-run errors, and per-record import errors. Vulnerability collection and CSV import should still work.
- If a platform produces noisy matches, add exclude keywords and use more specific phrases.
- If the database cannot be opened, check write permissions in the project folder.
- If the UI is unreachable, confirm the local server printed `http://127.0.0.1:8765`.

## Safety Notes

- Do not commit real API keys or customer secrets.
- Keep source URLs public unless secret handling has been designed.
- Do not commit generated databases, connector logs, imported asset data, customer exports, or trace/run output.
- Keep the server bound to `127.0.0.1` for local use.
