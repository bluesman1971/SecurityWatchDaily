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

## Troubleshooting

- If a source fails, check the dashboard source status. Other sources should still complete.
- If a platform produces noisy matches, add exclude keywords and use more specific phrases.
- If the database cannot be opened, check write permissions in the project folder.
- If the UI is unreachable, confirm the local server printed `http://127.0.0.1:8765`.

## Safety Notes

- Do not commit real API keys or customer secrets.
- Keep source URLs public unless secret handling has been designed.
- Keep the server bound to `127.0.0.1` for local use.
