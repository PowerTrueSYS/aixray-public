# AIXray: read-only IBM AIX and VIOS health, risk, and security assessment

AIXray is an open-source IBM AIX health check and VIOS posture assessment for administrators who need evidence before they change a system. Version 0.1.0 runs as a single ksh88 file under AIX `/bin/sh`, reads system state, makes zero network calls during assessment execution, and reports findings without remediating the host.

**Official page:** [powertruesystems.com/aixray](https://powertruesystems.com/aixray)

**Download:** [powertruesystems.com/aixray/](https://powertruesystems.com/aixray/)

**Guide:** [How to audit an IBM AIX / VIOS system](docs/auditing-aix.md) — a complete, vendor-honest checklist of what to check, why it matters, and what "good" looks like.

## What is AIXray?

AIXray answers: **“What is measurably true about this AIX or VIOS system right now?”**

It inspects lifecycle and support levels, patch currency, storage and capacity, performance signals, error history, resilience, security configuration, configuration hygiene, and monitoring readiness. The assembled scan produces HTML, JSON, or supported compliance views. It changes no system configuration and sends no assessment data away from the host.

AIXray is useful for:

- IBM AIX health checks and pre-change evidence
- VIOS risk and operational-readiness assessments
- IBM Power posture reviews
- AIX security audit preparation and configuration review
- storage, paging, mirror, MPIO, error-log, dump, and backup checks
- machine-readable assessment workflows that need explicit unknown states

## What is included?

- [`aixray-aix.sh`](aixray-aix.sh) — the complete AIX/VIOS v1 assessment, version 0.1.0
- [`aixray-review-pack.sh`](aixray-review-pack.sh) — the offline helper that creates a pseudonymized review copy and a separate local decoding key
- [`checks/`](checks/) — 35 standalone ksh check tools, each paired with its `manifest.json`
- [`catalog.json`](catalog.json) — a generated, sorted catalog of all 35 manifests with SHA-256 hashes
- [`SECURITY.md`](SECURITY.md) and [`docs/VERIFY.md`](docs/VERIFY.md) — the trust boundary, caveats, and repeatable public-repository verification commands
- [`site/index.html`](site/index.html) — the public download page for `powertruesystems.com/aixray`
- [`aixray.jsonld`](aixray.jsonld), [`llms.txt`](llms.txt), and [`robots.txt`](robots.txt) — machine and crawler discovery metadata

The 35 standalone tools are independently callable check modules. They are not a numerical claim about every finding produced by the larger assembled assessment.

## Why can a cautious AIX administrator inspect it first?

| Claim | Proof |
|---|---|
| Read-only on system configuration | The assembled script declares its capture boundary at the top of [`aixray-aix.sh`](aixray-aix.sh). Every public manifest records `"read_only": true` and lists the commands its standalone tool may run. Requested reports and a protected temporary FLRTVC scratch directory are the documented local writes; the scratch directory is removed on exit. |
| zero egress during the assessment | The shell artifacts contain the assessment logic and reference data locally. They do not fetch reference data or transmit results. Review the command surface in [`catalog.json`](catalog.json) and the executable source before running it. |
| single ksh88 file | The full scan is one inspectable [`aixray-aix.sh`](aixray-aix.sh) file. On AIX, `/bin/sh` provides the ksh88-compatible runtime used by the script; bash, Python, package installation, and GNU userland are not runtime requirements. |
| No fabricated assessment result | `NOT_ASSESSED` is a first-class output state. Missing, unreadable, malformed, ambiguous, or unsupported evidence is reported as unavailable rather than silently converted to `PASS`. Search the assembled source for `NOT_ASSESSED` to inspect each branch. |
| 35 standalone tools | [`catalog.json`](catalog.json) has `"check_count": 35`; each entry resolves to one paired script and manifest under [`checks/`](checks/). |
| Exact artifact identity | Each catalog entry carries the SHA-256 digest of its referenced standalone shell artifact. The catalog is sorted by check ID for deterministic review. |
| v1 only | The assembled script and all standalone scripts declare version `0.1.0`. This repository does not contain a v2 implementation. |

“Read-only” describes the tool’s effect on target system configuration. If you redirect output or request an export, AIXray writes the output path you selected. The optional offline FLRTVC mode also uses a private temporary directory and removes it on exit. “zero egress” describes assessment execution; obtaining the script is, of course, a separate download.

## Prerequisites

- IBM AIX 7.2 or 7.3, or VIOS
- AIX `/bin/sh` and standard AIX userland; bash, Python, GNU userland, and package installation are not required
- Root is recommended for the broadest read access; an unprivileged or non-root run continues, unavailable evidence is explicitly identified, and depending on the check may be reported as `WARN` or `NOT_ASSESSED`
- Plan for several minutes; runtime varies by system size and optional locally supplied FLRTVC data
- Nothing is installed, and the assessment makes no network calls

## How do I run AIXray?

Download the scanner from the [download page](https://powertruesystems.com/aixray/), review it, copy it to the AIX or VIOS host, then start with the easy HTML run:

```sh
chmod 700 aixray-aix.sh
./aixray-aix.sh
```

The bare run writes `aixray-<hostname>-<date>.html` in the current directory and prints this completion message:

```text
Report ready: ./aixray-<hostname>-<date>.html — open it in your browser. To save a PDF: Print -> Save as PDF.
```

Open the named report in a browser. Use **Print → Save as PDF** when you need a PDF copy. To write the named HTML report somewhere else, use `./aixray-aix.sh --out DIR`.

For advanced, explicit stdout output, redirect HTML or JSON yourself:

```sh
./aixray-aix.sh --html > aixray-report.html
./aixray-aix.sh --json > aixray-report.json
```

For a supported compliance view on stdout:

```sh
./aixray-aix.sh --compliance stig > aixray-stig.html
```

## Send a report safely for review

Before sending a generated HTML report, run the offline review helper beside
the report:

```sh
./aixray-review-pack.sh aixray-<hostname>-<date>.html
```

The helper produces a sendable `aixray-review-*.html` review file and a
separate mode-`0600` `aixray-local-key-*.map` decoding key that never leaves
this machine. Its output is pseudonymized, not anonymized: undiscovered
pure-alphabetic barewords are the documented residual. Inspect the review file
before sending it; never send the local decoding key. See the exact boundary
in [`SECURITY.md`](SECURITY.md#outbound-review-pack) and the review steps in
[`docs/VERIFY.md`](docs/VERIFY.md).

## Verify what you run

Published SHA-256 values for the launch artifacts:

```text
aixray-aix.sh
6829bd1aa6d24648c8c142287afc0aef730cc081716250d7eb79297c61ebaf52

aixray-review-pack.sh
8291000be2093176fc43164905958964d1e7bf9e197974abb54a25eabaab1ff4
```

The top-level `assembled_scanner` entry in [`catalog.json`](catalog.json)
binds the root and site scanner copies to the first hash. The top-level
`review_pack` entry binds the review helper to the second. Each sorted
`checks[]` entry records its standalone artifact and SHA-256; `check_count`
remains 35.

On a review workstation with `jq`, `rg`, and SHA-256 tooling:

```sh
jq '.tool_version, .check_count, .license' catalog.json
find checks -name manifest.json | wc -l
jq -e 'all(.checks[]; .read_only == true and .license == "Apache-2.0")' catalog.json
rg -n 'VERSION="0\.1\.0"|AIXRAY_STANDALONE_VERSION="0\.1\.0"' aixray-aix.sh checks --glob '*.ksh'
rg -n 'NOT_ASSESSED' aixray-aix.sh
cmp aixray-aix.sh site/aixray-aix.sh
sh tools/ci/egress-lint.sh aixray-aix.sh aixray-review-pack.sh checks/*/*.ksh
python3 tools/check-no-ibm-redistribution.py
sh tests/run-tests.sh
```

To verify a standalone artifact, compare its digest with the `sha256` value in its catalog entry. To audit behavior, inspect its manifest’s declared commands and then read the paired ksh file; both are adjacent by design.

## Output honesty and limitations

AIXray reports observable posture; it does not prove that a system is secure, compliant, recoverable, or free of defects. A `PASS` applies only to the evidence and rule implemented by that check. AIXray does not perform remediation. A backup record is not a restore test, and a configuration assessment is not a penetration test.

Reference data has a declared vintage in the assembled script. Review that value when deciding whether the result is current enough for your use.

## License

AIXray is open source under the [Apache License 2.0](LICENSE). Use, modification, and redistribution are permitted under the license's terms, including the patent grant. See the [NOTICE](NOTICE) file for attribution.

Machine-readable license expression: `Apache-2.0`.

The assembled report includes IBM Plex font data under the SIL Open Font License 1.1. See [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

Copyright © 2026 CJDM LLC, doing business as PowerTrue Systems.
