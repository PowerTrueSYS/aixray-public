# Release notes

## v1.2.0

A reference-data and inventory release. The standalone check-module count grows
from 324 to 387; the public package is the assembled monolith plus those 387
modules — 390 build outputs in all. If you downloaded v1.1.0, download v1.2.0,
verify it against `SHA256SUMS`, and run it again.

### Security APAR seed

A current AIX 7.3 TL4 (7300-04) system can now be judged against bundled
security APAR rows. v1.1.0 carried no 7300-04 seed row, so `ck-sec-apars`
refused with "no bundled security APAR rows apply". v1.2.0 adds `IJ59563`
(7300-04) and the sibling TL rows `IJ59564` (7300-03), `IJ59565` (7300-02) and
`IJ59566` (7200-05), all carrying CVE-2026-16923 (`bos.mp64` local privilege
escalation). The check still refuses when `instfix` cannot read the fix
database; that is evidence handling, not a missing table row.

Three HIPER rows for IBM node 7278066
(`devices.pciex.7710612214105006.com`) are now in the same seed: `IJ57378`
(7300-04), `IJ57303` (7300-03), `IJ57855` (7200-05). IBM publishes no CVE for
that node, so the display field carries the non-CVE token `HIPER-7278066`.

### Firmware floor table

The firmware floor table is now keyed on the full machine-type-model, so current
Power10 E1050 (`9043-*`) and E1080 (`9080-HEX`) systems resolve to a bundled
family instead of falling out of the type-only lookup. Power9 E980 (`9080-M9S`)
is listed. Scale-out 9105 and 9009 rows are globbed (`9105-*`, `9009-*`).

### Check inventory

Standalone check modules grow from 324 to 387. Each new module is a
self-contained `ck-*` tool; the public tag carries all 387 plus the assembled
monolith and the two review-pack helpers, which is the 390 build outputs above.
This is an inventory change, not a change of shape — AIXray is still one
inspectable script you read before it runs, with the standalone tools published
alongside it.

CIS Level 1 demonstrated coverage is unchanged from v1.1.0 at 208 of 212
mapped-and-rendered controls (209 mapped); `4.1.1.19` remains mapped but has
never rendered a determinate verdict on a committed fixture. The CIS Level 2
surface and the published count basis are otherwise unchanged.

### Reference data

Curator-verified `as_of` dates advance to 2026-08-18 for the IBM AIX lifecycle,
IBM security advisory, and CIS IBM AIX reference sources. The DISA STIG for IBM
AIX source stays at 2026-06-15 — that is DISA's publisher benchmark date, not a
curator stamp.

The 30-day lifecycle and security-advisory freshness thresholds start from
2026-08-18. A default installation renders those sources STALE after 2026-09-17
unless a later refresh ships.

Two post-vintage IBM advisories remain documented gaps, the same class as in
v1.1.0: IBM publishes no AIX Level→APAR table for them, so both stay on the
operator-supplied FLRTVC path.

### What did not change

**No remediation of findings, no configuration change.** AIXray reads and
reports. It does not remediate a host, install or remove software, change
configuration, restart services, alter accounts, or reboot the system.

**Zero network calls during assessment execution.** The scanner does not phone
home, fetch reference data, upload a report, perform a live DNS lookup, or open
an outbound network connection. Reports stay local unless an operator chooses to
transfer them. Obtaining the script is, as always, a separate download.

**The download is still the monolith plus the standalone `ck-*` tools.**

### Known limitations

The v1.0.0 and v1.1.0 known limitations all still apply:

- Run as root for the intended coverage. A non-root run is supported but
  incomplete, because several patch, dump, boot, account, audit, SSH and
  service-policy reads require privilege.
- The public scanner neither fetches nor bundles IBM's `flrtvc.ksh` or full
  `apar.csv`. A complete current CVE sweep requires an authorized, locally
  supplied FLRTVC report or inputs. Without them, source-dependent clean results
  remain incomplete.
- This is a point-in-time, bounded posture scan, not continuous monitoring or an
  exhaustive filesystem or application audit. Workload-specific tuning and
  controls outside a read-only in-LPAR view still require administrator review.
- A review-pack file is pseudonymized, not anonymized. It can retain operational
  detail and must be inspected locally before sharing; never send its separate
  decoding key with it.
- Producing a report writes the operator-selected output. Locally supplied
  FLRTVC inputs also use a private temporary directory; an abrupt termination
  can leave that directory for manual removal. Neither operation changes
  assessed AIX/VIOS configuration or state.

## v1.1.0

A defect-fix release. Zero new checks: the check-module count stays 324,
unchanged from v1.0.0. If you downloaded v1.0.0, download v1.1.0, verify it
against `SHA256SUMS`, and run it again.

### SRC parser fixes

The parser fixes are all in the shared SRC (`lssrc -a`) capture fragment consumed
by the 16 SRC/rctcpip service checks — writesrv, dt, piobe, qdaemon, and the 12
rc.tcpip subserver checks. Two parser defects are closed:

**Right-anchored SRC status parse.** The v1.0.0 parser accepted only two exact
`lssrc -a` row shapes: a four-field row ending in `active` and a three-field row
ending in `inoperative`. Subsystem rows without a group column — present in real
inventories, proven by live captures from two AIX boxes — fit neither shape, and
the parser fails closed: a single rejected row discarded the entire SRC
inventory, so the affected checks refused with `NOT_ASSESSED` rather than assess.
No wrong verdict was emitted. The status field is now right-anchored against the
known status vocabulary, and groupless rows are retained.

**Open SRC status vocabulary.** Transitional states `stopping` and `starting` now
classify as running; previously an unrecognized state — `stopping` was captured
live — discarded the whole inventory the same way, withholding SRC evidence from
all 16 checks.

In practical terms for a v1.0.0 operator: on systems whose `lssrc -a` inventory
contains a groupless or transitional-state row, the affected service checks
reported `NOT_ASSESSED`; v1.1.0 assesses them.

### Review-copy pseudonymizer fix

The `discover_after` extractor could not match identity labels ending in `=`;
the fail-closed layers held — no observed leak in eight probes, not an
exhaustive proof — and the fix restores the intended coverage.

### Reference data

The reference-data `as_of` advances to 2026-08-11 after a live-feed curation
review. Table content (lifecycle rows, security-advisory rows, the embedded
strict-seed APAR catalogue) is unchanged. Two post-vintage IBM security
advisories — for curl (maximum CVSS 9.8, eight CVEs) and for BIND (CVSS 7.5) —
remain documented gaps: IBM publishes no AIX Level→APAR table for either, so
both stay on the operator-supplied FLRTVC path, same as in v1.0.0.

### What did not change

**No remediation of findings, no configuration change.** AIXray reads and
reports; it does not remediate a host or alter its configuration.

**Zero network calls during assessment execution.** The assessment logic and
reference data are local to the script. Reports stay local unless the operator
transfers them. Obtaining the script is, as always, a separate download.

## v1.0.0

The first stable release. `catalog.json` declares `tool_version` `1.0.0` and
the assembled scanner reports `VERSION="1.0.0"`.

### What ships

Four release assets, up from two at `v0.1.0`:

```text
aixray-aix.sh              the assembled scanner
aixray-review-pack.sh      the review-copy helper
aixray-review-validate.awk the independent validator the helper runs
SHA256SUMS                 digests for every payload catalog.json declares
```

`SHA256SUMS` now covers the three top-level payloads **and** every standalone
check tool, not just the top-level files. `docs/VERIFY.md` derives the payload
set from `catalog.json`, so the documented verification recipe stays correct as
the catalog grows.

The repository ships 324 standalone check tools under `checks/<id>/`, each with
its own manifest, alongside the assembled single-file scanner. Every catalog
entry declares `read_only: true`; 88 of the 324 declare `requires_root`.

### Standards

Checks carry the standard tags they are written against. At this release the
catalog tag census is:

```text
cis-l1   252 checks
cis-l2    20 checks
ffiec      14 checks across II.C.11, II.C.15, II.C.22
stig        7 checks across V-245557 .. V-245569
```

A tag records which standard a check was written against. It is not a coverage
claim: consult the report's own auditor coverage table for what a given scan
actually assessed, including the controls it could not assess.

### Reporting posture

AIXray reports what it found. It does not tell you how to fix it — remediation
text is out of the report entirely, in `--html` and `--compliance` alike. The
executive summary opens with **Start here: top risks**, the five highest-impact
`FAIL`/`WARN` findings ranked by status then severity, each shown with the
evidence that produced it.

`NOT_ASSESSED` is a refusal, not a pass. Refusals are rendered, counted, and
carried into the auditor coverage table rather than folded into a clean bill.

### Review copies

The review helper produces a pseudonymized copy of a report for sharing, and an
independent validator (`aixray-review-validate.awk`) must clear it before any
artifact is written. A report now carries a privacy schema marker and a
per-field privacy annotation on every assessment cell; the validator refuses to
publish when a field cannot be proved de-identified.

When it refuses, the reason is written to a local
`aixray-local-pseudonymize-failed-*.txt` manifest, not to stderr — a reason
quotes the offending value, and that value must not leave the machine through a
terminal transcript or a CI log. stderr carries only the `NOT READY TO SHARE`
banner and a pointer to the manifest.

## v0.1.0 release-integrity note

The immutable `v0.1.0` tag points to commit
`d0587e17bc4fc387c11e8df317cc85e6aa8c2f4a`. The files attached to the
GitHub `v0.1.0` release are byte-identical to the same paths at the later
master commit `ed854a50801a050ebf9932ac99af522f76caa4a6`, which was the
master tip when the assets were uploaded. They are not byte-identical to the
tagged tree.

At that tagged revision, `aixray-review-pack.sh` is absent and
`aixray-aix.sh` has SHA-256
`e098e0b0f617649ba29fbf1626fefb55bcd2b467c09060bdcb4458b1340e5b16`.
The attached `v0.1.0` assets have these SHA-256 values:

```text
aixray-aix.sh
6829bd1aa6d24648c8c142287afc0aef730cc081716250d7eb79297c61ebaf52

aixray-review-pack.sh
8291000be2093176fc43164905958964d1e7bf9e197974abb54a25eabaab1ff4
```

### Text for the GitHub v0.1.0 release body

```text
Release-integrity note: the files attached to this release correspond to
commit ed854a50801a050ebf9932ac99af522f76caa4a6, not to the immutable
v0.1.0 tag at d0587e17bc4fc387c11e8df317cc85e6aa8c2f4a. The attached
aixray-aix.sh SHA-256 is
6829bd1aa6d24648c8c142287afc0aef730cc081716250d7eb79297c61ebaf52;
the attached aixray-review-pack.sh SHA-256 is
8291000be2093176fc43164905958964d1e7bf9e197974abb54a25eabaab1ff4.
The review helper is absent from the tagged tree, whose aixray-aix.sh
SHA-256 is
e098e0b0f617649ba29fbf1626fefb55bcd2b467c09060bdcb4458b1340e5b16.
```
