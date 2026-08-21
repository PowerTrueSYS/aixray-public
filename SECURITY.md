# Security and trust model

PTxray is intended to be inspected before it is run. A full assessment normally
runs as root on an AIX system, so the security boundary is the exact
revision of the on-box scanner, not a brand claim or a download page.

This document covers the assembled [`ptxray-aix.sh`](ptxray-aix.sh) scanner.
The repository also contains explicitly off-box administration tools, including
feed refreshers and a fleet runner, which may use declared network endpoints.
Those tools are not invoked by the on-box scanner and are outside its
zero-egress contract.

## On-box security contract

For `ptxray-aix.sh`:

- **Read-only means no assessed-system mutation.** The scanner reads posture
  evidence and renders a report. It does not remediate findings.
- **Zero network egress is a release requirement.** The scanner must not open an
  outbound network connection, perform a live DNS lookup, fetch reference data, send
  telemetry, or upload a report.
- **Outputs remain local.** PTxray writes only the report or export path chosen
  by the operator and, for a locally supplied FLRTVC run, a private temporary
  scratch directory. It removes that directory on normal exit and handled
  signals; abrupt termination can leave private scratch debris.
- **Missing evidence is not clean evidence.** Unavailable evidence is never
  promoted to `PASS`. Most unread or incomplete sources are surfaced as
  `NOT_ASSESSED` in the completeness model; some legacy or control-shaped rows
  retain `WARN` with explicit “needs root” wording. One known exception is the
  root-crontab `backup_job` row, which is omitted after an unprivileged read
  failure because separate backup evidence is reported elsewhere.

These are deliberately narrower statements than “the process has no side
effects.” Producing a report is a filesystem write, as is the bounded FLRTVC
scratch workflow described below.

## What it reads

The scanner uses standard AIX read or query commands and fixed,
reviewable configuration paths to inspect:

- host identity, AIX TL/SP, and firmware levels, filesets, interim fixes,
  and locally supplied vulnerability evidence;
- filesystems, volume groups, logical volumes, disks, paths, paging, CPU,
  memory, and performance counters;
- `errpt`, dump, boot, backup, availability, and monitoring posture;
- network interfaces, routes, listeners, resolver configuration, SSH,
  services, account/password/audit policy, scheduled work, and bounded file
  metadata checks.

The public check catalog is in [`docs/CHECK-CATALOG.md`](docs/CHECK-CATALOG.md),
and [`docs/HOW-TO-AUDIT.md`](docs/HOW-TO-AUDIT.md) maps the shipped artifact to
its smaller source units and command contracts.

## What it writes

The scanner can write only the following local artifacts:

- HTML, JSON, or compliance output sent to stdout or redirected by the
  operator;
- an HTML report under a directory explicitly selected with `--out` (the
  zero-argument convenience run selects the current directory), using a hidden
  same-directory temporary file before the final `mv`;
- two inventory files under a directory explicitly selected with
  `--flrt-export`. A private `umask` protects newly created files, but does not
  repair permissions on pre-existing files, and shell redirection can follow a
  pre-positioned symlink. Use a new, operator-owned, otherwise empty export
  directory; and
- when authorized FLRTVC inputs are supplied locally, private scratch files
  under `${TMPDIR:-/tmp}`. PTxray creates its scratch directory mode 700,
  restricts the input copies, and makes a best-effort removal on normal exit or
  a handled signal. An abrupt termination, including one during final cleanup,
  can leave the private directory behind for manual removal.

It does not execute a write to AIX configuration, ODM device configuration,
filesets, service state, security policy, accounts, boot state, or remediation
changes. The preserved real-AIX drill observed diagnostic ODM-class mtimes
advance without any corresponding scanner-tree open/write syscall and could not
attribute that housekeeping. PTxray therefore does not claim that no metadata
anywhere on a live system can move while read utilities run.

## What it never executes

The scan does not install, update, or remove software; edit configuration or
security policy; change device attributes; start, stop, or restart services;
create, lock, or delete users; or reboot or shut down the system. Commands such
as `chdev`, `chsec`, `chuser`, `chmod`, and `installp` appear in finding
remediation text because the report tells an administrator what they may choose
to do later. That prose is data; it is not executed by the scan.

## How zero egress is enforced

The zero-egress requirement is backed by layered, reviewable gates in
[`network-boundary.yml`](.github/workflows/network-boundary.yml), which runs on
every pull request and on pushes to `master`:

1. [`egress-lint.sh`](tools/ci/egress-lint.sh) rejects network-client command
   references in executable positions. Its regression suite includes the exact
   former `aix host_self host "$HOST"` invocation that once caused a live DNS
   lookup.
2. [`network-denial-check.sh`](tools/ci/network-denial-check.sh) compares
   successful fixture scans with and without a Linux network namespace. This
   proves no network dependency; it does not, by itself, prove no attempted
   egress.
3. [`egress-trace.sh`](tools/ci/egress-trace.sh) runs the scanner under
   `strace -f -e trace=network` and fails on an observed `AF_INET` or
   `AF_INET6`-family syscall in the traced process tree. CI installs `strace`
   and treats a missing tracer as a failure.

The scopes matter. The static lint is intentionally a tripwire, not a shell
parser. Both dynamic CI jobs set `AIXRAY_FIXTURES`; in that mode, `aix`, `aixv`,
and related wrappers replay repository files instead of executing their live
AIX query commands. The jobs therefore exercise the fixture-mode scanner
control flow, not the live AIX command tree. This is why the former wrapped
`host` resolver was not executed by those jobs; the real-AIX trace found it and
the static lint now carries its exact regression.

The Linux trace also does not cover inherited connected descriptors,
`AF_PACKET` or every other address family, a separate daemon acting through an
`AF_UNIX` request, or writes to a network-mounted filesystem. The harness
documents these limits in [`tools/ci/README.md`](tools/ci/README.md); source
review and a real-AIX trace remain part of the evidence.

The repository also preserves the
[`2026-07-14 real-AIX truss record`](docs/lab-acceptance/2026-07-14-zero-egress-lab-acceptance.md).
That record is intentionally a failed pre-fix drill: it found and attributed a
real DNS call. The current scanner replaced the live lookup with static
`/etc/hosts` evidence, and the static-lint regression prevents the former
command from returning. The failed record is not represented as a current
post-fix AIX pass. For the strongest assurance, repeat its documented AIX
`truss` method against the exact revision and AIX release you intend to run.

## Read-only enforcement and assembly identity

[`assembly-gate.yml`](.github/workflows/assembly-gate.yml) rebuilds the public
scanner, requires byte identity with the committed `ptxray-aix.sh`, and runs the
per-tool read-only command-contract gates. This makes review of the smaller
source units relevant to the exact shipped bytes. Shared monolith control flow
and its bounded report/scratch writes still require source review; the command
allowlist is not presented as a universal proof.

See [`docs/VERIFY.md`](docs/VERIFY.md) for exact commands to inspect likely
network and mutating primitives, run the egress and command-contract gates,
reassemble the scanner, and compare SHA-256 digests.

## Root and non-root runs

Run as root for the intended assessment coverage. Several security, patch,
dump, boot, account, audit, and service-policy reads require privilege. A
non-root run is a supported degraded run, not an equivalent assessment:
most unavailable evidence is disclosed as `NOT_ASSESSED` or an explicit
need-root `WARN`, and the report remains incomplete. The known exception is
`backup_job`: a failed non-root read of root's crontab omits that row instead of
emitting `NOT_ASSESSED`; it does not emit `PASS`. Do not interpret a non-root
result as proof that inaccessible or omitted controls are clean.

## IBM FLRTVC delivery data

The public scanner does not fetch or contain IBM's `flrtvc.ksh` or full
`apar.csv`. Its six delivery embed slots are empty. An authorized connected
admin system may fetch and verify those inputs and side-load them for an
offline target run; that local delivery artifact is ignored and must not be
committed or publicly redistributed.

[`tools/check-no-ibm-redistribution.py`](tools/check-no-ibm-redistribution.py)
fails CI if the Git index contains the case-insensitive basenames `flrtvc.ksh`
or `apar.csv`, a tracked `aixray-aix.bundled.sh`, a non-empty protected embed
slot assignment, the specific FLRTVC structure it checks (`ksh93` in the first
line, a version assignment, `parseLSLPP`, and `parseEFIX`), or its full-feed
signature (at least 100 lines, the exact header, and a vintage row). It is not a
general classifier for all IBM-derived content. Its exact scope, and a broader
candidate-file audit that remains necessary, are documented in
[`docs/VERIFY.md`](docs/VERIFY.md#confirm-that-ibm-delivery-data-is-not-bundled).

## Review-pack sharing boundary

> **Public copy:** An
> `ptxray-review-pack.sh` review file is **pseudonymized, not anonymized**. It
> can still contain operational and configuration details. Inspect the review
> file locally before deciding whether to share it. The separate local decoding
> key must not be sent with the review file. Creating either file performs no
> upload or send; sharing remains a deliberate user action.

The review-pack helper writes its output beside the input report through a
private scratch directory. This optional local transformation does not broaden
the scanner's assessed-system read-only boundary or its zero-egress boundary.
It is not proof that a review file is free of all identifying or sensitive
information.

## Reporting a security issue

Do not open a public issue for a suspected vulnerability. Email
[`review@powertruesystems.com`](mailto:review@powertruesystems.com) with the
subject **PTxray security report** and include:

- the exact Git commit or release tag;
- AIX release and whether the run was root or non-root;
- the invocation and the smallest reproduction that demonstrates the issue;
  and
- the observed impact and any relevant lint or trace evidence.

Do not attach a production scan, credentials, host identifiers, or other
sensitive system data to a vulnerability report unless a secure transfer method
has been agreed first. The generated report separately offers optional engineer
review at the same mailbox; that offer is not permission to send an unsanitized
production report. Sanitize it first, or email without the attachment to agree
a transfer method. Use the repository's GitHub Issues page only for
non-sensitive defects and documentation problems.
