# PTxray

**See inside your IBM Power systems.** A free, **read-only** posture scan for
**IBM AIX and IBM i**. The AIX edition checks over 100 things across 9 catalog
categories (lifecycle/EOL, patch & CVE currency, storage & capacity,
performance, errors, availability, security & hardening, config hygiene,
monitoring gaps); see the [canonical count basis](docs/COUNT-BASIS.md).
Findings are scored red/amber/green in a
plain-English, print-ready HTML report (including a clean browser PDF) and a
stable JSON contract. Single ksh88 file, zero dependencies, no network calls.
*By [PowerTrue Systems](https://powertruesystems.com).*

> [Free engineer review: email your report to review@powertruesystems.com — a principal engineer will review it personally and follow up.](mailto:review@powertruesystems.com)

> **OPEN SOURCE — Apache-2.0.** PTxray is genuinely open source under
> Apache-2.0. Anyone may inspect, use, run, fork, modify, and redistribute it
> under the license terms, including for commercial purposes. Apache-2.0 also
> includes an express patent grant. PowerTrue Systems uses the same open-source
> assessment engine in its paid services; the code remains available to
> everyone under Apache-2.0.

> **FREE & OPEN ACQUISITION.** The source is public at
> [`PowerTrueSYS/ptxray-public`](https://github.com/PowerTrueSYS/ptxray-public),
> and the Apache-2.0 artifact has a
> [direct, ungated download](https://github.com/PowerTrueSYS/ptxray-public/releases/latest/download/ptxray-aix.sh).
> No email, form, login, or contact information is collected anywhere in the
> acquisition path. Optional newsletter and service contact remain separate.
> The report is the lead engine for anyone who wants PowerTrue Systems' help
> with the findings.

> IBM i download: [`ptxray-ibmi.sh`](https://github.com/PowerTrueSYS/ptxray-public/releases/latest/download/ptxray-ibmi.sh).

> 🔒 **Read-only. It inspects and reports — it changes nothing, installs nothing,
> restarts nothing, and sends nothing anywhere.** The report is written on *your*
> system; you decide what to share. Every line is here for you (or your security
> team) to read before you run it.

## IBM i quick start

Sign on as QSECOFR and run the IBM i edition from PASE:

```sh
/QOpenSys/usr/bin/ksh ./ptxray-ibmi.sh --html > ptxray-ibmi-report.html
```

Use `--json` for machine-readable output or `--text` for a terminal summary.
IBM i 7.4 and 7.5 use exact CIS IBM i v2.1.0 crosswalks. Other releases still
report the release-independent evidence they can assess, omit borrowed CIS
control numbers, and render as a compatibility scan when the release is before
7.x. A score is emitted only when measured coverage reaches the hard 80% floor
for both the security and currency pillars; adverse findings are always shown.

## AIX quick start

On the AIX system, become root, go to the directory containing
`ptxray-aix.sh`, and run this one command:

```sh
./ptxray-aix.sh --out .
```

On a terminal, PTxray first shows an interactive standard-selection menu (STIG,
CIS Level 1, FFIEC, or all of them — Enter accepts all); with `--out .` each
selected standard is written as its own
`aixray-<hostname>-<YYYY-MM-DD>-<standard>.html`. To get the single health
report described below instead, skip the menu:

```sh
./ptxray-aix.sh --no-menu --out .
```

PTxray scans read-only and writes a file named
`aixray-<hostname>-<YYYY-MM-DD>.html` in the current directory. When it
finishes, it tells you the exact file to open:

```text
Report ready: ./aixray-<hostname>-<YYYY-MM-DD>.html — open it in your browser. To save a PDF: Print -> Save as PDF.
```

Before transferring or emailing a report, create a separate review candidate:

```sh
./ptxray-review-pack.sh --pseudonymize aixray-<hostname>-<YYYY-MM-DD>.html
```

The helper performs an independent validation pass before it publishes any
`aixray-review-*.html`. A successful candidate is **pseudonymized, not
anonymized**, and its status is always **REVIEW REQUIRED**. Inspect the review
candidate and the item-level `aixray-local-removals-*.txt` manifest before
sharing. The mode-0600 `aixray-local-key-*.map` and local removals manifest
never leave this machine; send only the review candidate after inspection.

```text
Transfer in (workstation to AIX):
scp ptxray-aix.sh ptxray-review-pack.sh ptxray-review-validate.awk root@<aix-host>:/tmp/
Copy all three files from the same release; the helper enforces its validator contract.
Pseudonymize and inspect on AIX before transfer out.
Transfer out only after inspection (AIX to workstation):
scp root@<aix-host>:/tmp/aixray-review-<token>-<YYYY-MM-DD>.html .
```

Copy only the inspected `aixray-review-*.html` candidate to your workstation
if needed, then double-click it or open it in any browser. Do not transfer the
raw `aixray-<hostname>-*.html`, the `aixray-local-key-*.map`, or the
`aixray-local-removals-*.txt`. The review candidate is self-contained: it does
not need PTxray, fonts, internet access, or any other files beside it.

To make the PDF, open the HTML report, choose **Print**, then choose
**Save as PDF**. This browser workflow is the supported PDF path; there is
nothing to install on AIX. The report supplies print-safe colors, margins,
page breaks, and its own hostname/date/page header and footer. If your print
dialog would add a second header/footer, turn off its **Headers and footers**
option. Enable **Background graphics** for the closest color match.

No install, no scanner dependencies, and no network access. PTxray runs under
AIX `/bin/sh` (ksh88) — no bash, Python, browser, PDF tool, or GNU utility is
needed on the scanned system. You can inspect `ptxray-aix.sh` before running
it; the shipped scanner is one readable shell file.

If you need the public files first, clone them on a connected workstation and
copy the scanner, pseudonymization helper, and independent validator to the
AIX system through your normal approved transfer path:

```sh
git clone https://github.com/PowerTrueSYS/ptxray-public
```

Existing scripts can keep the stdout forms exactly as before:

```sh
./ptxray-aix.sh --html > report.html
./ptxray-aix.sh --json > report.json
./ptxray-aix.sh --compliance stig > compliance.html
```

### Check reference-data currency without assessing the host

The AIX artifact has an assessment-free currency readiness check:

```sh
./ptxray-aix.sh --currency-status
./ptxray-aix.sh --currency-status --json
./ptxray-aix.sh --currency-status \
  --flrtvc-ksh ./flrtvc.ksh --flrtvc-apar-csv ./apar.csv
```

It reads only the checksum-bound embedded registry and explicitly supplied
local FLRTVC inputs. It does not inspect the host, invoke FLRTVC, or access the
network. Text mode prints all eight required sources in stable order with
version/revision, as-of date, calendar-day age, limit, and status. JSON mode
prints the exact `aixray-currency-attestation/1` object used by reports.

The check exits `0` only when every required source is identified,
integrity/provenance verified, and current. Exit `3` is the expected
fail-closed result for stale, missing, unknown, invalid, or future-dated data;
`2` is invalid syntax or an invalid threshold override; `1` is an unexpected
read/serialization failure. A normal assessment still produces its report
when currency is unverified.

The default limits are 30 days for lifecycle, advisory, CVE, APAR, FLRTVC, and
firmware sources, and 180 days for CIS and DISA benchmark verification. A
repeatable override is available on assessment, status, Contract-v2 pipeline,
fleet, and executive commands:

```sh
./ptxray-aix.sh --currency-status \
  --currency-max-age ibm-apar-csv=45
```

Overrides are per-source and appear in the resulting attestation. Unknown
source IDs, negative/non-decimal values, and duplicate overrides are rejected
with exit `2`; no last-value-wins behavior is used.

**Optional off-box PDF automation for an operator:** on a Mac/Linux operator
workstation that has Chrome/Chromium or `wkhtmltopdf`, the included helper can
perform the same conversion without opening a print dialog:

```sh
tools/ptxray-pdf.sh report.html report.pdf
```

This helper is never required or invoked on the customer AIX system. The
HTML + browser Print -> Save as PDF workflow remains the primary customer path.

**Run as root.** PTxray requires root because patch, dump, boot,
SSH, password/account, audit, and service-policy evidence otherwise becomes
incomplete. An unprivileged production invocation exits with status 2 before
collecting evidence; it never produces a deceptively partial assessment.

## Verify what you run

Before running PTxray as root, follow
**[How to verify PTxray is safe](docs/VERIFY.md)**. The skeptical-admin
checklist gives exact commands to inspect likely network and mutating
primitives, run the egress and read-only command gates, reassemble the shipped
script byte for byte, print its SHA-256, and confirm IBM FLRTVC delivery inputs
are not bundled. [`SECURITY.md`](SECURITY.md) states the trust boundary and the
limits of each check.

## What you get

- **`--html`** — a red/amber/green report a person reads: per-finding status,
  severity, what was observed, what it means, and how to fix it, with per-category
  scores. Every report includes the complete eight-source currency attestation
  and marks itself **READ-ONLY**.
- **`--json`** — the same findings as a **stable, documented schema** (`id`,
  `category`, `label`, `status`, `severity`, `observed`, `meaning`, `fix`,
  `controls`) plus a required top-level `currency` object, summary, and
  per-category rollups. It does not mutate assessed system state and is
  byte-deterministic under fixture replay, making the output suitable for
  tooling or an AI agent. Live point-in-time CPU/memory samples may legitimately
  vary between runs and are disclosed by `capacity.snapshot`.
- **Interactive standard selection** — run on a terminal with no output-format
  flag (`--compliance`, `--json`, `--html`, `--currency-status`, `--flrt-export`,
  `--flrtvc-*`), PTxray shows a menu that asks which compliance standard(s) to
  assess: STIG, CIS Level 1, CIS Level 2, FFIEC, any space-separated combination,
  or all of them. The menu appears only when both stdin and stdout are a terminal
  — scripts, pipes, cron, and CI never see it and run exactly as before. `--no-menu`
  (or `AIXRAY_NO_MENU=1`) forces the non-interactive path on a terminal. The menu
  never triggers any download; the scanner has no network path.

The AIX JSON contract is version **1.1**. Its additive `facts` object promotes
already-captured identity, OS/lifecycle, firmware, capacity-snapshot, and
recovery values into typed fields while retaining the original findings and
`upgrade_readiness` block for compatibility. Every null is named in exactly one
of the owning block's `unreadable` (render as **NOT ASSESSED**) or
`not_applicable` (render as **n/a**) lists; an unread value is never emitted as
zero.

## CVE exposure — complete FLRTVC sweep in the delivery bundle

The committed public scanner ships a curated **seed** of headline security
APARs (e.g. CVE-2025-36250, the NIM nimesis RCE). Its FLRTVC embed slots are
deliberately empty: IBM's IPL-1.0 `flrtvc.ksh` and `apar.csv` are not committed
or publicly redistributed. A bare run of that public file therefore retains
the seed-only `apar_scan` WARN.

For an authorized customer delivery, an internet-connected admin box creates a
local, gitignored scanner containing freshly fetched and verified IBM inputs:

```sh
# Admin/delivery system only. This output is ignored and must never be
# committed, published, attached to a public release, or otherwise redistributed.
python3 tools/refresh-data.py bundle

# Deliver dist/aixray-aix.bundled.sh through the approved customer channel.
# It may be named ptxray-aix.sh at the destination; no FLRTVC flags are needed.
./ptxray-aix.sh --html > report.html
```

On the target, path 0 decodes both blobs only inside PTxray's private mode-700
scratch directory, verifies the decoded script and feed against their embedded
SHA256 values, checks the feed vintage, and invokes the verified script with
`-s -f -l -e -d '|'`. It uses no network. Any missing slot, decode failure,
hash mismatch, invalid/future vintage, capture gap, or unexpected FLRTVC result
fails closed to WARN/not-assessed; it never fabricates a clean PASS. Set
`AIXRAY_NO_BUNDLED_FLRTVC=1` to disable path 0 and restore the seed-only
fallback for that run.

Explicit `--flrtvc-ksh` plus `--flrtvc-apar-csv` remains path 1 and overrides a
present bundle. `--flrtvc-report` remains path 2 for parsing a report produced
elsewhere. PTxray wraps IBM's own FLRTVC matching engine in all complete-sweep
paths; it never re-implements the fileset/vulnerable-range decision.

**Air-gap bundle path (`--definitions-bundle <file>`):** an operator who cannot
run the `bundle` producer on the same machine can carry a single
`.aixray-defs` envelope instead. On a connected admin box,
`python3 tools/refresh-data.py fetch-bundle --out aixray-defs-YYYYMMDD.aixray-defs`
frames apar.csv, the pinned flrtvc.ksh, and the optional CISA KEV catalog into
one closed-text envelope with a footer SHA-256 and per-source payload digests
(docs/DATA-REFRESH.md). Copy that file to the isolated AIX box, verify it
(`openssl dgst -sha256 -r file`, compare with the fetch output), and run:

```sh
./ptxray-aix.sh --definitions-bundle /path/to/aixray-defs-YYYYMMDD.aixray-defs --json
```

The scanner validates the envelope and every payload digest entirely offline
(ksh88 + openssl), decodes the verified bytes into a private mode-700 scratch,
and invokes the decoded engine with `-s -f -l -e -d '|'` — the same offline
invoke used by path 1. Any framing, footer-digest, or per-source digest failure
refuses the whole bundle with a one-line reason on stderr and leaves the scan
exactly as if no bundle was supplied; nothing is partially ingested.
`--definitions-bundle` conflicts with `--flrtvc-ksh`/`--flrtvc-apar-csv`/
`--flrtvc-report` and composes with `--currency-status`, `--flrt-export`, and
`--out`.

**Precisely what writes, and where** (never "zero"): flrtvc.ksh itself, given
`-s -f -l -e`, makes no network calls and no writes of its own (verified by
reading the full script — the only such paths are on code paths this
invocation never takes). But the surrounding workflow *does* write, to paths
under your control only: the local delivery artifact (or path-1's fetched
`apar.csv`/`flrtvc.ksh`) and small private scratch files holding decoded inputs
plus this run's already-in-memory `lslpp`/`emgr` state. Scratch is removed
immediately after invocation. Nothing is written to the target system's own
config, filesets, or state — that's the read-only guarantee, made precise
rather than hand-waved.

A fallback path exists for boxes without ksh93: generate a report elsewhere
and supply it via `--flrtvc-report <file>` (the admin-side wrapper must append
a `# FLRTVC_EXIT=$?` trailer proving the real exit status — a weaker
attestation than the direct-invoke path, since PTxray cannot itself verify
that invocation used the enforced offline flags; the finding text always says
which path produced the result).

**PASS requires ALL of:** output matching flrtvc.ksh's own banner and exact
compact-report column schema, a valid non-future real-calendar vintage parsed
from line 2 (`2026-02-31`-style impossible dates are explicitly rejected, not
silently miscalculated), a completion proof (direct exit-status capture, or
the `FLRTVC_EXIT` trailer on the fallback path), and — when the exit code is 0
("clean") — a body that is *only* the recognized clean-exit text with zero
other/malformed rows (a corrupt report that happens to also contain that text
must not slip through). Any of those missing renders **WARN** ("not assessed"),
never PASS. Canonical source currency uses the 30-day APAR/FLRTVC limits: a
source-dependent clean result becomes WARN when its verified source is stale
and `NOT_ASSESSED` when identity, integrity, provenance, or date cannot be
verified; a real exposure remains FAIL. HTML and JSON disclose the canonical
source rows. The legacy `flrtvc_data` JSON object remains only as a compatibility
projection of those rows, never a second freshness decision.

`--json` carries one structured `exposures[]` entry per CVE/APAR the box is
exposed to: fileset, installed vs. vulnerable level, IBM's HIPER — High Impact
PERvasive — flag, an `apars` array (**all** APAR/ifix identifiers IBM's row
lists — these are often ifix labels like `"3013ma"`, not APAR numbers, so
they're never mislabeled a singular `"apar"`), bulletin URL, and CVSS, for
downstream tooling (e.g. PowerTrue Blueprint's remediation sequencing).
`fixed_at_or_above` is **read verbatim from flrtvc.ksh's own "Fixed In"
column, never re-derived** — real IBM data comes in both dotted VRMF
(`"7.2.5.200"`) and dash TL-SP (`"7100-05-10"`, `"7200-05-03-2136"`) shape, and
both are sourced as-is; it renders `null` only for a genuine non-answer (the
common `"See Bulletin"` placeholder), never a guess. Every string field is
JSON-escaped exactly like an ordinary finding — a report-derived value is
external IBM text, not an inherently safe token. Because IBM's own tool does
the fileset/version/coverage matching, PTxray never re-decides which installed
level is exposed or which efix already covers it — eliminating that whole
class of re-derivation bug by construction.

The JSON also carries a top-level `upgrade_readiness` block (current OS/TL,
firmware, VIOS, machine type, the documented upgrade path) — the on-box facts
a stepped upgrade plan needs. The full OS × firmware × VIOS × HMC compatibility
**matrix** is IBM FLRT web-service output, not on-box data;
`upgrade_readiness.flrt_compat_matrix` says so explicitly rather than guessing
at it.

## Compliance report — `--compliance stig|cis-l1|ffiec`

```sh
./ptxray-aix.sh --compliance stig > compliance.html
```

A second output with two layers: an auditor-shaped summary (control-by-control
status with observed evidence and an honest automation-coverage note) and a
Critical-first remediation worklist an engineer works through. Findings carry
control mappings in the JSON (`"controls": ["stig:V-215263", ...]`).

- **stig** — DISA STIG for AIX 7.x (granular V-ID mappings; the authoritative
  embedded source, public domain, attributed). Hardening depth is being built out
  against the full public STIG rule set via a data-driven rule engine — file
  permissions/ownership are the first family (each rule evaluated and reported per
  V-ID). See `docs/COVERAGE.md`.
- **cis-l1** — CIS Level-1 as an *alignment tag only* (no CIS text or section
  numbers — licensing).
- **ffiec** — FFIEC IT Handbook section tags (public domain; the credit-union
  overlay).

## Fleet & executive views

- **Fleet runner** (`tools/ptxray-fleet.py`, an admin box) — SSH a host list,
  aggregate every LPAR's JSON into one fleet report: per-host scorecard,
  category heatmap, cross-host worst findings. Targets need **nothing
  installed** — the script is streamed over SSH and run read-only.
  Currency is re-aged at the fleet report date; legacy, malformed, mixed, or
  unreachable hosts make the aggregate `UNVERIFIED`.
  `python3 tools/ptxray-fleet.py --hosts hosts.txt`
- **Executive report** (`tools/ptxray-exec.py`) — renders one host or a fleet
  into a decision-maker document: posture verdict, score, category bars, top
  risks in business language, no jargon or command output. It carries the same
  host/source attestation and never presents a would-be GREEN result as current
  when aggregate currency is unverified.
  `python3 tools/ptxray-exec.py report.json --out exec.html`

Both entry points accept repeatable
`--currency-max-age SOURCE_ID=DAYS` overrides and generate self-contained HTML
without remote font or asset requests.

## For AI agents (MCP)

An **MCP server** (`mcp/`) exposes the scan as tools any MCP-aware assistant can
call: `health_check`, `compliance_report`, and `about` (the safety guarantees to
relay). The supported assessment path runs the AIX edition.
Because the on-box scanner does not mutate assessed system state or
make network calls, an assistant can run “check this system's posture” without
granting it a remediation or upload path. AIX health results return the native
`currency` object unchanged, and compliance HTML contains the native visible
attestation rather than an MCP-specific interpretation. The selected report
path and any documented private FLRTVC scratch files are still local filesystem
writes.

## Trust boundaries

**What it inspects:** filesets and patch levels, TL/SP and firmware versions,
storage/filesystem/VG capacity, CPU/memory/paging performance counters, the
error report (`errpt`), network and SSH configuration, account/password/audit
policy, cron and service config —
all via standard read commands (`lslpp`, `oslevel`, `df`, `svmon`, `errpt`,
`sshd -T`, `lsuser`, etc.), never by reading arbitrary files off disk.

**What it never does:** it never installs, upgrades, or removes a fileset;
never edits a config file, device attribute, or security policy; never
starts, stops, or restarts a service; never reboots or shuts down; never
creates, locks, or deletes a user; never deletes or moves assessed system data.
It removes only its private scratch files and atomically moves its report
temporary file into the output path you selected. Every
`chmod`/`chsec`/`chdev`/`chuser`-style command you'll see in a
finding's *fix* text is advisory prose describing what **you** would run — the
scan itself never executes it. The report/export modes (`--html`, `--json`,
`--compliance`, `--out`, and `--flrt-export`) write only to the path or
redirection you choose; `--out` may create the directory you explicitly name
and writes the named HTML report there. When path 0 is present, or
`--flrtvc-ksh` and
`--flrtvc-apar-csv` are supplied, PTxray also creates a
temporary FLRTVC scratch directory under `${TMPDIR:-/tmp}` on the target; that
directory is removed on exit after normal completion or a handled signal. An
abrupt termination can leave private scratch debris to remove manually.
`--flrtvc-report` reads a pre-generated report without that scratch workflow.
It never writes system configuration.

- **Read-only to assessed system state.** Inspects and reports;
  changes/installs/restarts nothing. Local writes are limited to the explicit
  report/export and private scratch paths described above.
- **Zero on-box network egress.** The scanner uses embedded or explicitly
  side-loaded local reference data; the report never leaves your box unless
  you send it.
- **One inspectable file.** `ptxray-aix.sh` is plain ksh88 with base64 delivery
  data in the authorized customer build — no compiled code and no runtime
  fetches. A cautious admin can inspect and decode every byte before running it.
- **Least privilege.** Elevated reads are documented; unprivileged runs degrade
  loudly, never silently.

## Data currency

The tool never phones home, so its knowledge is **attested, not assumed**.
`data/source-registry.json` binds the exact static payloads and names all eight
required verdict-bearing sources. Runtime rows come from the exact local KEV,
APAR, FLRTVC, and firmware packages selected for the run. Missing identity,
digest, provenance, or date stays the literal `unknown`; filenames, mtimes,
assessment dates, and the wall clock never fill the gap. The legacy
`data_vintage` field remains for compatibility and is derived from the source
rows; it is not an evaluation input.

At the current base, the CIS and DISA benchmark vendor versions remain
`unknown` until a curator verifies the actual revisions behind the numeric-only
crosswalk and loaded rules. That intentionally makes the public release
readiness check nonzero rather than claiming current benchmark coverage from
comments or a content hash alone.

We keep source packages current on an **event-driven** cadence — when IBM ships
a bulletin or lifecycle change, we ship a data release (⭐ Watch → **Releases**
to get pinged). The refresh engine (`tools/refresh-data.py`) polls live feeds on
*our* side; assessment, status, rendering, fleet, and executive paths stay
offline. For **day-0 / actively-exploited** CVEs, the fast lane
(`tools/dayzero-monitor.py`) polls CISA KEV + IBM FLRT/PSIRT + Red Hat + NVD on
the acquisition side and proposes a curated dataset row. See
[`docs/DATA-REFRESH.md`](docs/DATA-REFRESH.md) and
[`docs/DAYZERO-FEED.md`](docs/DAYZERO-FEED.md).

## Docs

- [`docs/CHECK-CATALOG.md`](docs/CHECK-CATALOG.md) — the full check catalog (A–J).
- [`docs/COVERAGE.md`](docs/COVERAGE.md) — every catalog line mapped to finding
  IDs with an honest covered/thin/out status.
- [`docs/DATA-REFRESH.md`](docs/DATA-REFRESH.md) — the currency cadence: sources,
  the event-driven flow, and the zero-day path.
- [`docs/DAYZERO-FEED.md`](docs/DAYZERO-FEED.md) — the day-0 fast lane: CISA KEV +
  IBM PSIRT + Red Hat + NVD, high-frequency polling, alerts, curated dataset
  updates (detection only; remediation is out of scope).
- [`docs/SCHEDULING.md`](docs/SCHEDULING.md) — the self-serve nightly-cron recipe.

## Why it's free

PowerTrue Systems provides managed AIX and IBM Power administration, and PTxray is
the free, honest, inspectable version of the assessment we run for every
client — **you don't have to take our word for what it finds, and you don't
have to run it yourself either.**

The report, not an acquisition form, is the lead engine: it gives you useful
findings first and points to optional PowerTrue Systems help only if you want
it.

If you'd rather not run it: PowerTrue will run PTxray against **one system you
choose**, for free, and turn the findings into a **PowerTrue Blueprint** — a
prioritized, plain-English plan for what to fix and in what order. That's the
free offer; it costs you 20 minutes and nothing else. From there, most estates
have more than one system worth looking at — a **paid Blueprint** covers your
**whole IBM Power estate** (every AIX LPAR and IBM i partition, one priced and sequenced plan),
which is what typically precedes a scoped remediation engagement (we call
these **Fortify** and **Refresh**) and, for shops that want it handled on an
ongoing basis, our managed service (**Bulwark**). Start here:
[powertruesystems.com](https://powertruesystems.com).

## License

PTxray is open source under Apache-2.0. Use, modification, and redistribution
— including commercial use — are permitted under the license terms, including
the patent grant. Read-only tool; provided without warranty.
