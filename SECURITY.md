# Security and trust model

AIXray is intended to be inspected before it is run. A full assessment normally
runs as root on an AIX or VIOS system, so the security boundary is the exact
revision of the on-box [`aixray-aix.sh`](aixray-aix.sh) scanner—not a brand
claim, repository page, or download page.

This document covers the shipped scanner and the separate offline
[`aixray-review-pack.sh`](aixray-review-pack.sh) helper. Neither artifact
automatically transmits a report. The standalone tools under [`checks/`](checks/)
have declared command surfaces in [`catalog.json`](catalog.json).

## On-box scanner contract

For `aixray-aix.sh`:

- **Read-only means no assessed-system configuration mutation.** The scanner
  reads posture evidence and renders a report. It does not remediate findings.
- **Zero network egress is a release requirement.** The scanner must not open an
  outbound network connection, perform a live DNS lookup, fetch reference data,
  send telemetry, or upload a report.
- **Outputs remain local.** AIXray writes only the report or export path chosen
  by the operator and, for locally supplied FLRTVC inputs, a private temporary
  scratch directory. It removes that directory on normal exit and handled
  signals; abrupt termination can leave private scratch debris.
- **Missing evidence is not clean evidence.** Unavailable evidence is never
  promoted to `PASS`. Most unread or incomplete sources are surfaced as
  `NOT_ASSESSED`; some legacy or control-shaped rows retain `WARN` with
  explicit “needs root” wording. One known exception is the root-crontab
  `backup_job` row, which is omitted after an unprivileged read failure
  because separate backup evidence is reported elsewhere.

These are deliberately narrower statements than “the process has no side
effects.” Producing a report is a filesystem write, as is the bounded FLRTVC
scratch workflow.

## What the scanner reads

The scanner uses standard AIX/VIOS read or query commands and fixed,
reviewable configuration paths to inspect:

- host identity, AIX TL/SP, VIOS and firmware levels, filesets, interim fixes,
  and locally supplied vulnerability evidence;
- filesystems, volume groups, logical volumes, disks, paths, paging, CPU,
  memory, and performance counters;
- `errpt`, dump, boot, backup, availability, and monitoring posture;
- network interfaces, routes, listeners, resolver configuration, SSH,
  services, account/password/audit policy, scheduled work, and bounded file
  metadata checks; and
- VIOS SEA, NPIV, vSCSI, and CAA state when the host is a VIOS.

Review each standalone check's declared commands in
[`catalog.json`](catalog.json), then inspect the adjacent shell artifact.
Shared scanner control flow must be reviewed directly in
[`aixray-aix.sh`](aixray-aix.sh).

## What the scanner writes

The scanner can write only the following local artifacts:

- HTML, JSON, or compliance output sent to stdout or redirected by the
  operator;
- an HTML report under a directory explicitly selected with `--out` (the
  zero-argument run selects the current directory), using a hidden
  same-directory temporary file before the final `mv`;
- two inventory files under a directory explicitly selected with
  `--flrt-export`. A private `umask` protects newly created files but
  does not repair permissions on pre-existing files, and shell redirection can
  follow a pre-positioned symlink. Use a new, operator-owned, otherwise empty
  export directory; and
- when authorized FLRTVC inputs are supplied locally, private scratch files
  under `${TMPDIR:-/tmp}`. AIXray creates its scratch directory mode
  `700`, restricts the input copies, and makes a best-effort removal on
  normal exit or a handled signal. Abrupt termination, including during final
  cleanup, can leave the private directory behind for manual removal.

It does not execute a write to AIX configuration, ODM device configuration,
filesets, service state, security policy, accounts, boot state, or remediation
changes. A preserved real-AIX drill observed diagnostic ODM-class mtimes
advance without a corresponding scanner-tree open/write syscall and could not
attribute that housekeeping. AIXray therefore does not claim that no metadata
anywhere on a live system can move while read utilities run.

The scan does not install, update, or remove software; edit configuration or
security policy; change device attributes; start, stop, or restart services;
create, lock, or delete users; or reboot or shut down the system. Mutating
command names can appear in finding remediation text because the report tells
an administrator what they may choose to do later. That prose is data; it is
not executed by the scan.

## Root and non-root runs

Run as root for the intended assessment coverage. Several security, patch,
dump, boot, account, audit, and service-policy reads require privilege. A
non-root run is supported but degraded, not an equivalent assessment: most
unavailable evidence is disclosed as `NOT_ASSESSED` or an explicit
need-root `WARN`, and the report remains incomplete. The known
`backup_job` exception omits the row after a failed non-root read of root's
crontab; it does not emit `PASS`. Never interpret inaccessible or omitted
controls as clean.

## Zero-egress evidence and limits

The public repository ships
[`tools/ci/egress-lint.sh`](tools/ci/egress-lint.sh). It rejects known
network-client commands in executable positions and carries regressions for
direct and wrapped forms, including the former live resolver command. Run it
against both shipped shell artifacts as shown in
[`docs/VERIFY.md`](docs/VERIFY.md).

The static lint is intentionally a tripwire, not a shell parser or a runtime
trace. A pass does not prove that arbitrary shell has no egress path, nor does
it exercise the live AIX command tree. It does not establish the absence of
inherited connected descriptors, other address families such as
`AF_PACKET`, a separate daemon acting through an `AF_UNIX` request, or
writes to a network-mounted filesystem. Broad source review of the exact bytes,
and release-specific tracing on the AIX/VIOS version you intend to run, remain
stronger complementary evidence. A digest identifies reviewed bytes; it proves
authenticity only when compared with a digest from an independently trusted
channel.

## Outbound review pack

The review helper is a separate, offline ksh88 program. Given one marked
AIXray HTML report, it validates the report envelope and metadata, discovers
estate identifiers, and writes a pseudonymized review HTML plus a local
decoding map beside the input. It maps host, LPAR, network, hardware, path, and
user identifiers to stable per-report tokens; removes secret-shaped values and
GECOS free text; and replaces unresolved evidence with
`[redacted-evidence-line]`. Explicit diagnostic KEEP values such as AIX
levels, filesets, CVEs, control identifiers, and machine models remain useful.

This is pseudonymization, not guaranteed anonymization. The helper independently
re-scans its transformed output—including visible text, tag attribute values,
and HTML comments—for original values, residual identifier-shaped values
(including FQDN bases followed by `/` or `:` suffixes), unissued pseudotokens,
and evidence outside its allowlist. If validation or publication fails, it
exits nonzero and publishes no final review HTML. Strict validation can reject
a report rather than guess; contact PowerTrue without an attachment if that
occurs. Even after success, open and inspect the review HTML before sending it.

The helper creates an owner-only scratch directory beside the input and removes
its temporaries on normal or handled exit. On success it publishes both files
mode `0600`, the decoding map first and the validated HTML last. If final
HTML publication fails, it removes the new map. The map begins
“DO NOT SEND THIS FILE,” contains the real identifier mappings, and intentionally
uses the distinct `aixray-local-key-*.map` name. It does not retain secrets
or dropped GECOS text, but it is still sensitive. Send only
`aixray-review-*.html`; keep `aixray-local-key-*.map` local.

## IBM FLRTVC delivery data

The public scanner does not fetch or contain IBM's `flrtvc.ksh` or full
`apar.csv`. Its six protected delivery embed slots are empty. Authorized
operators may side-load inputs for an offline target run, but those local
delivery artifacts must not be committed or publicly redistributed.

[`tools/check-no-ibm-redistribution.py`](tools/check-no-ibm-redistribution.py)
fails if the Git index contains prohibited delivery basenames, a tracked
bundled-scanner filename, a non-empty protected embed slot, the specific
FLRTVC script structure it checks, or its full-feed signature. It is not a
general classifier for all IBM-derived content. Run the guard and the broader
candidate-file review in [`docs/VERIFY.md`](docs/VERIFY.md).

## Reporting a security issue

Do not open a public issue for a suspected vulnerability. Email
[`review@powertruesystems.com`](mailto:review@powertruesystems.com) with the
subject **AIXray security report** and include:

- the exact Git commit or release tag;
- AIX/VIOS release and whether the run was root or non-root;
- the invocation and the smallest reproduction that demonstrates the issue;
  and
- the observed impact and any relevant lint or trace evidence.

Do not attach a production scan, credentials, host identifiers, the local
decoding map, or other sensitive system data unless a secure transfer method
has been agreed first. The optional engineer-review offer at the same mailbox
is not permission to send an unsanitized report.
