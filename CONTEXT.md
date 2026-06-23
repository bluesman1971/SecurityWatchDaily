# SecurityWatchDaily Context

Shared domain language for SecurityWatchDaily, a local-first tool that watches vulnerability advisories for the products a team runs and flags which of their machines are likely affected. This file names the concepts so code, docs, and reviews use the same words.

## Language

### Inventory

**Asset**:
One tracked machine in the local inventory, identified uniquely by hostname.
_Avoid_: host, node, device, machine

**Component**:
A single piece of software, firmware, or operating system installed on an **Asset**. The thing an advisory is matched against.
_Avoid_: package, app, software (those are values inside a Component, not the concept)

**Inventory**:
The full local set of **Assets** and their **Components**.

**Inventory record**:
The one neutral shape that every import source translates into before anything is stored: a single **Asset**'s fields plus the list of **Components** on it, with optional source identifiers (e.g. a connector's external id) left blank when not applicable. CSV rows and connector responses are converted *into* Inventory records at the edges; the import core only ever sees Inventory records.
_Avoid_: row, entry, item

**Inventory import**:
The deep module that takes a batch of **Inventory records** and applies it to the **Inventory** — group by hostname, upsert **Assets**, replace their **Components**, normalize each Component, record connector mappings when present, and refresh **Impact matches**. CSV import and connector sync are thin adapters that build Inventory records and call this module.
_Avoid_: importer, loader, ingest service

### Findings and matching

**Finding**:
One vulnerability or advisory item collected during a **Run** and associated with a **Platform**. May carry one or more CVEs, but is not itself a CVE.
_Avoid_: vulnerability, alert, CVE

**Platform**:
A product or technology the team configures to watch, with its keywords, sources, and default priority.
_Avoid_: product, technology, target

**Source**:
An external advisory feed a **Run** collects **Findings** from (CISA, MSRC, Ubuntu, Palo Alto, Hacker News, etc.).
_Avoid_: provider, origin

**Impact match**:
A link between a **Finding** and a **Component** on an **Asset**, carrying a confidence label, that indicates the Asset is possibly exposed.
_Avoid_: hit, result, correlation

### Collection

**Run** (or **Watch run**):
One collection pass that gathers **Findings** from enabled **Sources**, applies **Trace suppression**, and stores the result.
_Avoid_: scan, job, check

**Trace suppression**:
Hiding a **Finding** on a **Run** when it has not changed since a previous Run, so repeat noise stays out of the visible list.
_Avoid_: dedup, filtering

**Connector**:
A read-only integration that pulls **Inventory** from a source-of-truth system (Intune, Jamf, Freshservice). Maps external inventory into the same **Asset**/**Component** model as CSV import.
_Avoid_: integration, plugin, sync source

**Connector sync**:
One execution of a **Connector** that produces **Inventory records** and runs them through **Inventory import**.

## Example dialogue

**Dev:** When someone uploads a CSV, do we store the rows straight away?

**Expert:** No — a CSV row isn't an Inventory record yet. Several rows with the same hostname are really one Asset with several Components, so the CSV adapter groups them into Inventory records first.

**Dev:** And a connector?

**Expert:** Same destination, different edge. The connector adapter turns each device from the API into an Inventory record, with the device's external id filled in. Both adapters then hand Inventory records to Inventory import.

**Dev:** Where do the impact matches get refreshed?

**Expert:** Inside Inventory import, after the Components are stored — so a CSV import and a connector sync refresh Impact matches the exact same way. The adapters don't do it themselves anymore.
