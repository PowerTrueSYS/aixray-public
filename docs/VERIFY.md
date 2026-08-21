# How to verify PTxray is safe

No single grep, test, or trace proves that arbitrary code is safe. This
checklist gives a skeptical administrator repeatable evidence about one exact
revision of the on-box `ptxray-aix.sh` scanner. Read the evidence scopes in
[`SECURITY.md`](../SECURITY.md) before treating a pass as broader than it is.

PTxray is fully open under Apache-2.0. Its
[source](https://github.com/PowerTrueSYS/ptxray-public) and
[direct artifact](https://github.com/PowerTrueSYS/ptxray-public/releases/latest/download/ptxray-aix.sh)
are available without an email, form, login, or contact-information
requirement. The report is the lead engine; optional newsletter or service
contact stays separate from acquisition.

Run checkout code only in a disposable, credential-free review VM (preferred)
or a locked-down container with no sensitive mounts, host sockets, tokens, or
production data. These harnesses are tests, not containment: the denial check
first runs an unrestricted baseline, and the syscall trace detects an attempt
only after it occurs. Until review is complete, assume the revision could
egress. Do not run it first on the production AIX target.

## Pin the revision

```sh
git clone https://github.com/PowerTrueSYS/ptxray-public
cd ptxray-public
git rev-parse HEAD
git status --short
```

Record the commit ID. The status command should print nothing. For a release,
check out the trusted release tag or commit before continuing; all hashes and
results below are revision-specific.

## Inspect and test the zero-egress boundary

Start with a deliberately broad source search:

```sh
git grep -n -E '(^|[^[:alnum:]_])(curl|wget|ftp|telnet|nc|ssh|scp|host|nslookup|dig)([^[:alnum:]_]|$)|socket[[:space:]]*\(|connect[[:space:]]*\(' -- ptxray-aix.sh || true
```

This search is a review aid, not a pass/fail gate. The assembled script contains
network words in comments, STIG data, local-configuration reads, and remediation
text. Review every hit. Expected non-executable hits carry nearby explanations;
an unexplained executable client or socket call is a failure.

Run the command-position lint against the exact shipped scanner:

```sh
sh tools/ci/egress-lint.sh ptxray-aix.sh
```

Expected result: `egress-lint: PASS`. The lint catches the former wrapped DNS
client form as well as direct client commands. It is a fast static tripwire, not
complete proof.

On Linux with `ksh`, `unshare`, and `strace` installed, run the same denial and
syscall-trace harnesses used by CI:

```sh
export AIXRAY_FIXTURES=tests/fixtures/aix73-healthy
export AIXRAY_TODAY=2026-07-01
sh tools/ci/network-denial-check.sh -- ksh ./ptxray-aix.sh --json
sh tools/ci/egress-trace.sh -- ksh ./ptxray-aix.sh --json
```

The denial run must report byte-identical successful output. The trace must
report no observed `AF_INET`/`AF_INET6`-family syscall. A local `SKIP` because a
tool is unavailable is not evidence of a pass; in CI, a missing prerequisite is
a failure. Both commands above set `AIXRAY_FIXTURES`, so the scanner wrappers
replay fixture files instead of executing the live AIX query commands. These
runs cover fixture-mode scanner control flow, not the live AIX command tree.
Review the exact additional limitations in
[`tools/ci/README.md`](../tools/ci/README.md) and the workflow that installs the
prerequisites in
[`network-boundary.yml`](../.github/workflows/network-boundary.yml).

For a real AIX target, repeat the release-specific `truss` review described in
the preserved
[`AIX lab record`](lab-acceptance/2026-07-14-zero-egress-lab-acceptance.md). That
record found a now-removed DNS client at an older revision; it is evidence that
the real-target gate found a defect, not a post-fix pass for every AIX release.

## Inspect and test the read-only boundary

Search for commands that deserve special attention when a script runs as root:

```sh
git grep -n -E '(^|[^[:alnum:]_])(installp|rpm|dnf|yum|chdev|chsec|chuser|startsrc|stopsrc|reboot|shutdown|mkdir|mktemp|tee|rm|mv|cp|chmod|chown)([^[:alnum:]_]|$)' -- ptxray-aix.sh || true

git grep -n -E 'mkdir -m|mkdir -p|openssl base64 -d -out|cp "\$|chmod 0600|> "\$(FV_|FLRT_|REPORT_)|mv -f "\$REPORT_TMP"|rm -f "\$REPORT_TMP"|rm -rf "\$FV_' -- ptxray-aix.sh || true
```

The first search is broad and most mutating command names it finds are
remediation text that is never evaluated. The second search targets the current
filesystem writer sites, including shell redirections and OpenSSL's `-out`
option. Actual `mkdir`, `cp`, `chmod`, `rm`, `mv`, and redirect operations must
remain confined to the operator-selected report/export paths or the private
FLRTVC scratch path. Inspect their operands and control flow in the assembled
script; the variable names make the second search revision-specific, and neither
grep proves read-only behavior by itself.

Run the extracted tools' manifest and command-form check:

```sh
sh tests/test-tool-command-allowlist.sh
```

Expected result includes `command allowlist OK` and `direct-write guards`. This
check verifies query-only forms such as `bootlist` and `alt_rootvg_op` in the
extracted tools. Review shared scanner control flow separately, as mapped in
[`HOW-TO-AUDIT.md`](HOW-TO-AUDIT.md).

## Reassemble and hash the exact scanner

Prove that the smaller source units reproduce the committed scanner byte for
byte, then print both SHA-256 values:

```sh
verify_artifact=$(mktemp)
trap 'rm -f "$verify_artifact"' EXIT HUP INT TERM
sh build/assemble.sh --output "$verify_artifact"
cmp ptxray-aix.sh "$verify_artifact"

if command -v sha256sum >/dev/null 2>&1; then
  sha256sum ptxray-aix.sh "$verify_artifact"
elif command -v shasum >/dev/null 2>&1; then
  shasum -a 256 ptxray-aix.sh "$verify_artifact"
else
  openssl dgst -sha256 ptxray-aix.sh "$verify_artifact"
fi
```

`cmp` should print nothing and exit zero; the two displayed digests must match.
The digest identifies the reviewed bytes. It becomes an authenticity check only
when compared with a digest obtained through an independently trusted release
channel.

## Confirm that IBM delivery data is not bundled

First reject prohibited raw delivery filenames and the ignored bundled-artifact
name:

```sh
if git ls-files | grep -E '(^|/)(apar\.csv|flrtvc\.ksh|aixray-aix\.bundled\.sh)$'; then
  echo 'FAIL: prohibited IBM delivery filename is tracked' >&2
  exit 1
else
  echo 'OK: no prohibited IBM delivery filename is tracked'
fi
```

Then run the content-aware index guard. In addition to the prohibited basenames
and bundled-artifact name, it detects the exact renamed FLRTVC structural
signature and full-feed shape described in
[`SECURITY.md`](../SECURITY.md#ibm-flrtvc-delivery-data), plus non-empty protected
scanner slots. It is not a general IBM-content classifier:

```sh
python3 tools/check-no-ibm-redistribution.py
```

Expected result:

```text
no-IBM-redistribution OK: tracked index contains no raw IBM FLRTVC data or filled scanner slots
```

Finally, perform the broader candidate review that a filename deny-list cannot
replace:

```sh
git ls-files | grep -Ei '(^|/).*apar.*\.csv$|(^|/).*flrtvc.*$' || true
```

Important current-revision audit result: this broad search finds
`tests/dayzero/feeds/flrt-apar.csv`. It is a three-row offline test fixture, not
a full IBM feed. Two rows are explicitly marked synthetic; one legacy OpenSSL
row is IBM-shaped, and the repository does not independently establish that
row's provenance. Treat it as a public-release review item. This documentation
change flags it and does not delete or alter the fixture. The search also finds
synthetic malformed-report fixtures, captured FLRTVC report outputs, tests, and
documentation; none of those paths is a bundled `flrtvc.ksh` or full
`apar.csv` delivery input.

## Run the complete regression suite

With `ksh` and Python 3 available:

```sh
sh tests/run-tests.sh
```

Require a zero exit status and the final `ALL TESTS PASSED` line. This suite
exercises the assembled artifact, internal missing-authority branches, read-only command
contracts, egress regressions, empty public FLRTVC slots, and the
no-redistribution guard. Passing tests complement source review; they do not
expand the claims made by the tests.
