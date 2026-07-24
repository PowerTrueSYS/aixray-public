# How to verify AIXray is safe

No single grep, digest, test, or trace proves arbitrary code safe. This
checklist gives a skeptical administrator repeatable evidence about one exact
public revision of the on-box `aixray-aix.sh` scanner and the offline
`aixray-review-pack.sh` helper. Read the evidence scopes in
[`SECURITY.md`](../SECURITY.md) before treating any pass as broader than it
is.

Run checkout code only in a disposable, credential-free review VM or a
locked-down container without sensitive mounts, host sockets, tokens, or
production data. Until review is complete, assume the revision could egress.
Do not run it first on a production AIX/VIOS target.

## Pin the public revision

```sh
git clone https://github.com/PowerTrueSYS/aixray-public
cd aixray-public
git rev-parse HEAD
git status --short
```

Record the commit ID. The status command should print nothing. For a release,
check out the trusted release tag or commit before continuing; every digest and
result below is revision-specific.

## Verify byte identity and published hashes

First require the root and site scanner payloads to be byte-identical:

```sh
cmp aixray-aix.sh site/aixray-aix.sh
```

`cmp` should print nothing and exit zero. Then validate the catalog,
README, every standalone artifact, and the sorted 35-check schema from the
repository root:

```sh
python3 - <<'PY'
import hashlib
import json
from pathlib import Path

root = Path(".")
catalog = json.loads((root / "catalog.json").read_text(encoding="utf-8"))
readme = (root / "README.md").read_text(encoding="utf-8")

def sha256(relative):
    return hashlib.sha256((root / relative).read_bytes()).hexdigest()

scanner = sha256("aixray-aix.sh")
review = sha256("aixray-review-pack.sh")
assert sha256("site/aixray-aix.sh") == scanner
assert catalog["assembled_scanner"] == {
    "artifact": "aixray-aix.sh",
    "site_artifact": "site/aixray-aix.sh",
    "sha256": scanner,
}
assert catalog["review_pack"] == {
    "artifact": "aixray-review-pack.sh",
    "sha256": review,
}
assert scanner in readme
assert review in readme

checks = catalog["checks"]
assert catalog["check_count"] == len(checks) == 35
assert [entry["id"] for entry in checks] == sorted(entry["id"] for entry in checks)
for entry in checks:
    assert sha256(entry["artifact"]) == entry["sha256"], entry["id"]

print("scanner", scanner)
print("review", review)
print("catalog/hash verification OK")
PY
```

For this launch revision the printed artifact digests are:

```text
scanner 6829bd1aa6d24648c8c142287afc0aef730cc081716250d7eb79297c61ebaf52
review 8291000be2093176fc43164905958964d1e7bf9e197974abb54a25eabaab1ff4
```

A digest identifies the reviewed bytes. It becomes an authenticity check only
when compared with a digest obtained through an independently trusted release
channel.

## Inspect and test the zero-egress boundary

Start with a deliberately broad source search against both shell artifacts:

```sh
git grep -n -E '(^|[^[:alnum:]_])(curl|wget|ftp|tftp|telnet|nc|socat|ssh|scp|sftp|rcp|rsh|rexec|ping|traceroute|sendmail|host|nslookup|dig)([^[:alnum:]_]|$)|/dev/(tcp|udp)|socket[[:space:]]*\(|connect[[:space:]]*\(' -- aixray-aix.sh aixray-review-pack.sh || true
```

This is a review aid, not a pass/fail gate. The artifacts contain network words
in comments, local-configuration reads, report text, and remediation text.
Review every hit. An unexplained executable client or socket call is a failure.

Run the shipped command-position lint against both exact artifacts:

```sh
sh tools/ci/egress-lint.sh aixray-aix.sh
sh tools/ci/egress-lint.sh aixray-review-pack.sh
```

Both commands must exit zero. An artifact with no candidate references reports
`egress-lint: PASS`; reviewed scanner text can instead produce explicit
`ALLOWED` lines. Any `FAIL` line or nonzero exit is a failure. The lint
catches direct and wrapped network-client forms. It is a static tripwire, not a
complete shell parser or live AIX runtime trace. Its limits—including inherited
descriptors, other address families, cooperating daemons, and network-mounted
output paths—are described in
[`SECURITY.md`](../SECURITY.md#zero-egress-evidence-and-limits).

## Inspect the read-only and local-write boundary

Search for commands that deserve special attention when shell runs as root:

```sh
git grep -n -E '(^|[^[:alnum:]_])(installp|rpm|dnf|yum|chdev|chsec|chuser|startsrc|stopsrc|reboot|shutdown|mkdir|mktemp|tee|rm|rmdir|mv|ln|cp|chmod|chown)([^[:alnum:]_]|$)' -- aixray-aix.sh aixray-review-pack.sh || true

git grep -n -E 'REPORT_TMP|FLRT_|FV_|SCRATCH|HTML_(TMP|OUT)|MAP_(TMP|OUT)|--flrt-export|--out' -- aixray-aix.sh aixray-review-pack.sh || true
```

The first search is intentionally noisy: most mutating command names in the
scanner are remediation prose that is never evaluated. The second highlights
the current local writer variables. Inspect each actual `mkdir`, `cp`,
`chmod`, `ln`, `rm`, `mv`, and redirection operand. Scanner
writes must remain confined to operator-selected report/export paths or private
FLRTVC scratch. Review-helper writes must remain beside the selected report,
inside private scratch or the final mode-`0600` review/map paths. Neither
grep proves read-only behavior by itself.

Also inspect each check's `commands`, `read_only`, and
`requires_root` fields in [`catalog.json`](../catalog.json), then read
the paired shell file under [`checks/`](../checks/).

## Verify the review-pack boundary

The helper must be executable and valid under both available shell parsers:

```sh
test -x aixray-review-pack.sh
sh -n aixray-review-pack.sh
ksh -n aixray-review-pack.sh
```

For a report you own, run:

```sh
./aixray-review-pack.sh aixray-<hostname>-<date>.html
```

Success creates one owner-only `aixray-review-*.html` and one owner-only
`aixray-local-key-*.map`. Open the review HTML and inspect it. Send only
the review HTML. The map starts with a DO-NOT-SEND warning and contains the
local token-to-identifier mapping; keep it mode `0600` and local. A
successful pseudonymization is not a claim of anonymity. A nonzero exit with no
final review HTML is the helper's fail-closed behavior, not permission to send
the raw report.

## Confirm IBM delivery data is not bundled

Reject prohibited raw delivery filenames and the bundled-artifact name:

```sh
if git ls-files | grep -E '(^|/)(apar\.csv|flrtvc\.ksh|aixray-aix\.bundled\.sh)$'; then
  echo 'FAIL: prohibited IBM delivery filename is tracked' >&2
  exit 1
else
  echo 'OK: no prohibited IBM delivery filename is tracked'
fi
```

Run the content-aware Git-index guard:

```sh
python3 tools/check-no-ibm-redistribution.py
```

Expected result:

```text
no-IBM-redistribution OK: tracked index contains no raw IBM FLRTVC data or filled scanner slots
```

The guard checks the exact filenames, protected empty scanner slots, and the
specific script/feed signatures documented in
[`SECURITY.md`](../SECURITY.md#ibm-flrtvc-delivery-data). It is not a
general IBM-content classifier. Perform the broader candidate-name review too:

```sh
git ls-files | grep -Ei '(^|/).*apar.*\.csv$|(^|/).*flrtvc.*$' || true
```

Review every result rather than assuming a renamed file is harmless.

## Run the public regression suite

With `ksh` and Python 3 available:

```sh
PYTHONDONTWRITEBYTECODE=1 sh tests/run-tests.sh
```

Require a zero exit status plus both `public funnel launch contracts OK` and
`outbound review-pack redaction profile OK`. Without an explicitly supplied
AIX scanner-fixture directory, fixture-dependent scanner cases may report
`skipped`; all seven portable review-pack tests must pass. Passing tests
complement source review and do not expand the claims made by the tests.
