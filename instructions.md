# SecurityWatchDaily Instructions

SecurityWatchDaily is a local tool for watching vulnerability advisories and matching them against an asset inventory that you provide by CSV.

The app is designed for a simple first workflow:

1. Start the local app.
2. Import a CSV asset inventory.
3. Run a vulnerability check.
4. Review which findings may affect your assets.

## What You Need

- Python 3.11 or newer.
- A local copy of this repository.
- A CSV file with at least `hostname` and `product` columns.

No API keys, connectors, cloud accounts, Freshservice, Jamf, or Intune setup is required for this phase.

## Start The App

From the project folder, run:

```bash
python3 -m securitywatchdaily init
python3 -m securitywatchdaily run --sample --force-visible
python3 -m securitywatchdaily serve
```

Open:

```text
http://127.0.0.1:8765
```

If you see `OSError: [Errno 48] Address already in use`, another local server is already using that port. Start the app on a different port:

```bash
python3 -m securitywatchdaily serve --port 8891
```

Then open:

```text
http://127.0.0.1:8891
```

## Import Assets

1. Open the local web UI.
2. Click **Assets**.
3. Click **Import CSV**.
4. Upload a CSV file or paste CSV text into the box.
5. Click **Import CSV**.

If the CSV has problems, the app shows a table with the row, field, and issue to fix.

## CSV Template

Use this header:

```csv
hostname,owner,location,asset_type,vendor,product,version,platform,last_seen,component_type
```

Required fields:

- `hostname`
- `product`

Recommended fields:

- `vendor`
- `version`
- `platform`
- `last_seen`

## Field Guide

`hostname`

The asset name, device name, server name, service name, or other unique label.

Examples:

```text
laptop-1
fw-1
app-server-1
```

`owner`

The person, team, or group responsible for the asset.

Examples:

```text
IT
Network
Finance Apps
```

`location`

Where the asset belongs. Use whatever is useful for your team.

Examples:

```text
HQ
Remote
Datacenter A
```

`asset_type`

The kind of asset.

Examples:

```text
laptop
server
firewall
cloud service
```

`vendor`

The vendor or publisher of the product installed on the asset.

Examples:

```text
Microsoft
Palo Alto
Canonical
Cisco
```

`product`

The specific software, operating system, firmware, hardware product, package, or service installed on the asset.

Examples:

```text
Windows 11 Pro
PAN-OS
Ubuntu 24.04
Microsoft Office
Cisco IOS XE
```

`version`

The installed version when you know it.

Examples:

```text
10.0.22631
11.1.2
24.04
```

`platform`

The broader SecurityWatchDaily watch bucket. This helps the matcher connect inventory rows to the platform categories already being watched.

Examples:

```text
windows_11
palo_alto_pan_os
ubuntu_lts
office
cisco_meraki
```

You can leave `platform` blank if you are not sure. Vendor and product matching still helps.

`last_seen`

The date the asset or product was last observed. Use `YYYY-MM-DD`.

Examples:

```text
2026-06-20
2026-06-21
```

`component_type`

What kind of component the row describes.

Examples:

```text
operating system
software
firmware
service
package
```

## Product vs Platform

`product` is what the asset has.

`platform` is the SecurityWatchDaily watch bucket used to group vulnerability findings.

Example:

```csv
hostname,vendor,product,version,platform
laptop-1,Microsoft,Windows 11 Pro,10.0.22631,windows_11
firewall-1,Palo Alto,PAN-OS,11.1.2,palo_alto_pan_os
```

## Multiple Products On One Asset

Use one row per product or component.

Example:

```csv
hostname,owner,asset_type,vendor,product,version,platform,component_type
laptop-1,IT,laptop,Microsoft,Windows 11 Pro,10.0.22631,windows_11,operating system
laptop-1,IT,laptop,Microsoft,Microsoft Office,2405,office,software
```

When you re-import a hostname, the app replaces that asset's component list with the rows in the new CSV. This helps avoid stale software entries.

## Review Impacted Assets

After importing assets:

1. Run a vulnerability check from the dashboard, or use the sample run while testing.
2. Open **Findings**.
3. Click a finding to see impacted assets.
4. Open **Assets**.
5. Click an asset to see related findings.

## Match Confidence Labels

`confirmed affected`

The product matched and the asset version is inside a known affected range.

`likely affected`

The product matched, but the source does not provide enough structured version data.

`needs review`

The product matched and version data exists, but the asset is missing a version.

`not affected`

The product matched, but the asset version appears outside the known affected range.

`unknown`

The product matched, but the asset version could not be compared cleanly.

## Troubleshooting

`OSError: [Errno 48] Address already in use`

Another local server is using the port. Start on a different port:

```bash
python3 -m securitywatchdaily serve --port 8891
```

CSV import says `Hostname is required`

Add a value in the `hostname` field for that row.

CSV import says `Product is required for impact matching`

Add the installed product, software, operating system, firmware, package, or service name.

CSV import says `Use YYYY-MM-DD format`

Change dates to a format like:

```text
2026-06-22
```

No impacted assets appear

Check that:

- Assets were imported successfully.
- The vulnerability run has findings.
- Product names are close to the advisory product names.
- Vendor and platform values are not overly specific or misspelled.
- Versions are present where version-aware matching is needed.

## Safety Notes

- Do not import production secrets, passwords, tokens, or private keys.
- Do not commit real customer inventory files.
- Do not commit generated SQLite databases or run logs.
- Keep this local app bound to `127.0.0.1`.
- Do not expose the app to a network without a security review.
