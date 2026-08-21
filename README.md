# PTxray: read-only IBM AIX and IBM i health, risk, and security assessment

PTxray is an open-source IBM AIX and IBM i health check and posture assessment for administrators who need evidence before they change a system. Version 1.3.0 runs as a single ksh88 file under AIX `/bin/sh` (and IBM i PASE ksh), reads system state, makes zero network calls during assessment execution, and reports findings without remediating the host.

**Official page:** [powertruesystems.com/aixray](https://powertruesystems.com/aixray)

**Download:** [powertruesystems.com/aixray/](https://powertruesystems.com/aixray/)

**Guide:** [How to audit an IBM AIX system](docs/auditing-aix.md) — a complete, vendor-honest checklist of what to check, why it matters, and what "good" looks like.

## What is PTxray?

PTxray answers: **“What is measurably true about this AIX or IBM i system right now?”**

It inspects lifecycle and support levels, patch currency, storage and capacity, performance signals, error history, resilience, security configuration, configuration hygiene, and monitoring readiness. The assembled scan produces HTML, JSON, or supported compliance views. It changes no system configuration and sends no assessment data away from the host.

PTxray is useful for:

- IBM AIX health checks and pre-change evidence
- IBM i posture and operational-readiness assessments
- IBM Power posture reviews
- AIX security audit preparation and configuration review
- storage, paging, mirror, MPIO, error-log, dump, and backup checks
- machine-readable assessment workflows that need explicit unknown states

## What is included?

- [`ptxray-aix.sh`](ptxray-aix.sh) — the complete AIX v1 assessment, version 1.3.0. The public release also publishes this as [`aixray-aix.sh`](aixray-aix.sh), a byte-identical alias, so existing download links and run commands keep working.
- [`ptxray-ibmi.sh`](ptxray-ibmi.sh) — the IBM i assessment, graded against the CIS IBM i benchmark on IBM i 7.4 and 7.5
- [`ptxray-review-pack.sh`](ptxray-review-pack.sh) — the offline helper that creates a pseudonymized review copy and a separate local decoding key
- [`checks/`](checks/) — 388 standalone ksh check tools, each paired with its `manifest.json`
- [`catalog.json`](catalog.json) — the generated, sorted manifest catalog with SHA-256 hashes and the declared check count
- [`SECURITY.md`](SECURITY.md) and [`docs/VERIFY.md`](docs/VERIFY.md) — the trust boundary, caveats, and repeatable public-repository verification commands
- [`site/index.html`](site/index.html) — the public download page for `powertruesystems.com/aixray`
- [`aixray.jsonld`](aixray.jsonld), [`llms.txt`](llms.txt), and [`robots.txt`](robots.txt) — machine and crawler discovery metadata

The standalone tools are independently callable check modules. Their inventory count is not a numerical claim about every finding produced by the larger assembled assessment.

## Standards coverage

PTxray evaluates selected controls against observed system state. Coverage is partial: a `PASS` applies only to the implemented rule and available evidence, not to the standard as a whole.

| Claim | Proof |
|---|---|
| **DISA STIG for IBM AIX 7.x coverage is partial: 66 distinct rule V-IDs receive an engine verdict.** This count is not a single-release coverage fraction. | The live `R_FILEPERM`, `R_SECATTR`, `R_NETTUNE`, and `R_SVCOFF` tables in [`ptxray-aix.sh`](ptxray-aix.sh) contain 66 distinct V-IDs. `checks_security` calls all four evaluators, and each emits per-rule `PASS`, `FAIL`, or `NA` evidence in JSON `rules[]`. `V-215399` is counted for its `clean_partial_conns` tunable verdict; the package-commit condition in that rule is not checked. Deferred `V-215429` is not in a live table and is not counted. |
| **Partial: 260 CIS L1-aligned checks** resolve to 209 distinct Level 1 control numbers of the CIS IBM AIX 7 Benchmark v1.2.0, which has 212 Level 1 controls. Their scope spans NFS exports, password hashing, file ownership and permissions, and network tunables, plus login policy, auditing, cron and at, home directories, system accounts, and the r-command services. The three controls with no mapping — 5.1.4, 5.1.5 and 7.1 — are not claimed. A mapping is not a verdict: a mapped control whose evidence is unreadable or absent renders `NOT_ASSESSED`, never `PASS`. This is an alignment cross-check, not a claim of completeness against CIS. | The numeric-only `cis_l1_map` in [`ptxray-aix.sh`](ptxray-aix.sh) names each source finding or STIG rule the cross-check reads, one per line as `source\|control`. Count its rows and its distinct control numbers directly from the file. The 212 denominator is the Level 1 control count of the benchmark itself; the benchmark PDF is licensed by CIS and is deliberately not redistributed here. The renderer resolves the mappings from the run's actual verdicts and emits no verdict for a control whose evidence is unavailable. |
| **Level 2 is reachable as `--compliance cis-l2`.** Its scope is narrower than Level 1 and is not summarised as a fraction here. | `--compliance cis-l2` is accepted by the argument parser in [`ptxray-aix.sh`](ptxray-aix.sh) and renders the same evidence-backed verdict states, `NOT_ASSESSED` included. |
| **IBM i alignment is release-scoped.** On IBM i 7.4 and 7.5 the IBM i assessment aligns to the CIS IBM i benchmark; other releases report release-independent evidence without borrowing control numbers. There is no DISA STIG for IBM i. | [`ptxray-ibmi.sh`](ptxray-ibmi.sh) reads system values and IFS state through IBM i services and grades them against the benchmark it declares, emitting `NOT_ASSESSED` when a probe is determinate-absent. |

## Why can a cautious AIX administrator inspect it first?

| Claim | Proof |
|---|---|
| Read-only on system configuration | The assembled script declares its capture boundary at the top of [`ptxray-aix.sh`](ptxray-aix.sh). Every public manifest records `"read_only": true` and lists the commands its standalone tool may run. Requested reports and a protected temporary FLRTVC scratch directory are the documented local writes; the scratch directory is removed on exit. |
| zero egress during the assessment | The shell artifacts contain the assessment logic and reference data locally. They do not fetch reference data or transmit results. Review the command surface in [`catalog.json`](catalog.json) and the executable source before running it. |
| single ksh88 file | The full scan is one inspectable [`ptxray-aix.sh`](ptxray-aix.sh) file. On AIX, `/bin/sh` provides the ksh88-compatible runtime used by the script; bash, Python, package installation, and GNU userland are not runtime requirements. |
| No fabricated assessment result | `NOT_ASSESSED` is a first-class output state. Missing, unreadable, malformed, ambiguous, or unsupported evidence is reported as unavailable rather than silently converted to `PASS`. Search the assembled source for `NOT_ASSESSED` to inspect each branch. |
| Declared standalone inventory | [`catalog.json`](catalog.json) records `check_count`; each entry resolves to one paired script and manifest under [`checks/`](checks/), and the public tests require all three counts to agree. |
| Exact artifact identity | Each catalog entry carries the SHA-256 digest of its referenced standalone shell artifact. The catalog is sorted by check ID for deterministic review. |
| v1 only | The assembled script and all standalone scripts declare version `1.3.0`. This repository does not contain a v2 implementation. |

“Read-only” describes the tool’s effect on target system configuration. If you redirect output or request an export, PTxray writes the output path you selected. The optional offline FLRTVC mode also uses a private temporary directory and removes it on exit. “zero egress” describes assessment execution; obtaining the script is, of course, a separate download.

## Prerequisites

- IBM AIX 7.2 or 7.3, or VIOS; the IBM i assessment runs on IBM i 7.4 or 7.5 through PASE
- AIX `/bin/sh` and standard AIX userland; bash, Python, GNU userland, and package installation are not required
- Root is recommended for the broadest read access; an unprivileged or non-root run continues, unavailable evidence is explicitly identified, and depending on the check may be reported as `WARN` or `NOT_ASSESSED`
- Plan for several minutes; runtime varies by system size and optional locally supplied FLRTVC data
- Nothing is installed, and the assessment makes no network calls

## How do I run PTxray?

Download the scanner from the [download page](https://powertruesystems.com/aixray/), review it, copy it to the AIX host, then start with the easy HTML run:

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

On IBM i, run the IBM i assessment the same way with `ptxray-ibmi.sh` under PASE ksh.

## Send a report safely for review

Before sending a generated HTML report, run the offline review helper beside
the report:

```sh
./ptxray-review-pack.sh aixray-<hostname>-<date>.html
```

The v1.0.0-and-later release bundle also supplies
`ptxray-review-validate.awk`; keep it beside `ptxray-review-pack.sh` when you
transfer or run the helper. The historical v0.1.0 helper is self-contained.

The helper produces a sendable `aixray-review-*.html` review file and a
separate mode-`0600` `aixray-local-key-*.map` decoding key that never leaves
this machine. Its output is pseudonymized, not anonymized: undiscovered
pure-alphabetic barewords are the documented residual. Inspect the review file
before sending it; never send the local decoding key. See the exact boundary
in [`SECURITY.md`](SECURITY.md#review-pack-sharing-boundary) and the review steps in
[`docs/VERIFY.md`](docs/VERIFY.md).

## Verify what you run

SHA-256 values for the artifacts in this repository revision are published in
[`SHA256SUMS`](SHA256SUMS), one line per released file, rather than pasted into
this page where they would rot. Verify every release payload against it.

When verifying a full repository tree (a `git clone` or tag archive), use:

```sh
sha256sum -c SHA256SUMS
```

When verifying only downloaded release assets, use:

```sh
sha256sum -c --ignore-missing SHA256SUMS
```

The `--ignore-missing` flag verifies only the files present in the directory;
it skips any `SHA256SUMS` entry whose file is absent without reporting it as a
failure.

On AIX, `csum -h SHA256 <file>` produces the same digest for a single file.

The top-level `assembled_scanner` entry in [`catalog.json`](catalog.json)
binds the root and site scanner copies to the scanner's `SHA256SUMS` line. The
top-level `review_pack` entry binds the review helper to its line. Each sorted
`checks[]` entry records its standalone artifact and SHA-256; `check_count`
must match that list and the paired files under `checks/`.

The published `v0.1.0` assets do not match its immutable tag. See the
[`v0.1.0` release-integrity note](docs/RELEASE-NOTES.md#v010-release-integrity-note)
for the exact commits and published-asset digests.

On a review workstation with `jq`, `rg`, and SHA-256 tooling:

```sh
jq '.tool_version, .check_count, .license' catalog.json
python3 tools/sync-release-shape.py --check
find checks -name manifest.json | wc -l
jq -e 'all(.checks[]; .read_only == true and .license == "Apache-2.0")' catalog.json
version=$(jq -r '.tool_version' catalog.json)
rg -n -F -e "VERSION=\"${version}\"" -e "AIXRAY_REVIEW_PACK_VERSION=\"${version}\"" -e "AIXRAY_STANDALONE_VERSION=\"${version}\"" ptxray-aix.sh ptxray-review-pack.sh checks --glob '*.ksh'
rg -n 'NOT_ASSESSED' ptxray-aix.sh
cmp ptxray-aix.sh site/ptxray-aix.sh
set -- ptxray-aix.sh ptxray-review-pack.sh checks/*/*.ksh
[ ! -f ptxray-review-validate.awk ] || set -- "$@" ptxray-review-validate.awk
sh tools/ci/egress-lint.sh "$@"
python3 tools/check-no-ibm-redistribution.py
sh tests/run-tests.sh
```

To verify a standalone artifact, compare its digest with the `sha256` value in its catalog entry. To audit behavior, inspect its manifest’s declared commands and then read the paired ksh file; both are adjacent by design.

## Output honesty and limitations

PTxray reports observable posture; it does not prove that a system is secure, compliant, recoverable, or free of defects. A `PASS` applies only to the evidence and rule implemented by that check. PTxray does not perform remediation. A backup record is not a restore test, and a configuration assessment is not a penetration test.

Reference data has a declared vintage in the assembled script. Review that value when deciding whether the result is current enough for your use.

## License

PTxray is open source under the [Apache License 2.0](LICENSE). Use, modification, and redistribution are permitted under the license's terms, including the patent grant. See the [NOTICE](NOTICE) file for attribution.

Machine-readable license expression: `Apache-2.0`.

The assembled report includes IBM Plex font data under the SIL Open Font License 1.1. See [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

Copyright © 2026 CJDM LLC, doing business as PowerTrue Systems.
