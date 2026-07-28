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

## Run the release-integrity gate

Before pushing a release tag, run the tree-only gate from the committed
candidate revision. Replace `v0.1.0` with the tag being prepared:

```sh
python3 tools/verify-release-integrity.py --tag v0.1.0
```

Before uploading assets, place exactly `aixray-aix.sh` and
`aixray-review-pack.sh` in a separate directory and compare them with the same
candidate tree:

```sh
python3 tools/verify-release-integrity.py --tag v0.1.0 \
  --assets-dir release-assets
```

The gate checks the required tree paths, all catalog digests, root/site scanner
identity, artifact version declarations, the exact release asset set, and
asset bytes. Any `FAIL` line blocks the release.

## Verify byte identity and catalog hashes

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
from pathlib import Path, PurePosixPath

root = Path(".")
resolved_root = root.resolve(strict=False)
guidance = (
    "check out the intended release tag or commit and retry with clean files "
    "from that revision"
)

def fail(message):
    raise SystemExit(f"artifact verification failed: {message}; {guidance}")

def require_file(relative):
    candidate = PurePosixPath(relative)
    if (
        candidate.is_absolute()
        or ".." in candidate.parts
        or relative in ("", ".")
    ):
        fail(f"unsafe required path {relative!r}")
    path = root
    components = []
    for part in candidate.parts:
        path /= part
        components.append(part)
        try:
            is_symlink = path.is_symlink()
        except OSError as exc:
            fail(f"could not inspect required path {relative}: {exc}")
        if is_symlink:
            component = PurePosixPath(*components).as_posix()
            fail(
                f"required path {relative} traverses symlink component "
                f"{component}"
            )
    try:
        resolved_path = path.resolve(strict=False)
        resolved_path.relative_to(resolved_root)
    except ValueError:
        fail(f"required path {relative} resolves outside the repository")
    except (OSError, RuntimeError) as exc:
        fail(f"could not resolve required path {relative}: {exc}")
    if not path.is_file():
        fail(f"missing required file {relative}")
    return path

def read_bytes(relative):
    path = require_file(relative)
    try:
        return path.read_bytes()
    except OSError as exc:
        fail(f"could not read {relative}: {exc}")

def read_text(relative):
    content = read_bytes(relative)
    try:
        return content.decode("utf-8")
    except UnicodeDecodeError as exc:
        fail(f"{relative} is not valid UTF-8: {exc}")

def sha256(relative):
    return hashlib.sha256(read_bytes(relative)).hexdigest()

def require_equal(actual, expected, message):
    if actual != expected:
        fail(message)

try:
    catalog = json.loads(read_text("catalog.json"))
except json.JSONDecodeError as exc:
    fail(f"catalog.json is not valid JSON: {exc}")
if not isinstance(catalog, dict):
    fail("catalog.json root is not an object")
readme = read_text("README.md")

scanner = sha256("aixray-aix.sh")
review = sha256("aixray-review-pack.sh")
site_scanner = sha256("site/aixray-aix.sh")
require_equal(
    site_scanner,
    scanner,
    "byte mismatch between aixray-aix.sh and site/aixray-aix.sh "
    f"(sha256 {scanner} != {site_scanner})",
)

expected_scanner = {
    "artifact": "aixray-aix.sh",
    "site_artifact": "site/aixray-aix.sh",
    "sha256": scanner,
}
require_equal(
    catalog.get("assembled_scanner"),
    expected_scanner,
    "catalog.json assembled_scanner does not match aixray-aix.sh and "
    f"site/aixray-aix.sh; expected {expected_scanner!r}, "
    f"found {catalog.get('assembled_scanner')!r}",
)

expected_review = {
    "artifact": "aixray-review-pack.sh",
    "sha256": review,
}
require_equal(
    catalog.get("review_pack"),
    expected_review,
    "catalog.json review_pack does not match aixray-review-pack.sh; "
    f"expected {expected_review!r}, found {catalog.get('review_pack')!r}",
)
if scanner not in readme:
    fail(f"README.md does not contain the aixray-aix.sh digest {scanner}")
if review not in readme:
    fail(
        "README.md does not contain the aixray-review-pack.sh digest "
        f"{review}"
    )

checks = catalog.get("checks")
if not isinstance(checks, list):
    fail("catalog.json checks is not a list")
require_equal(
    catalog.get("check_count"),
    len(checks),
    "catalog.json check_count does not match the checks list "
    f"({catalog.get('check_count')!r} != {len(checks)})",
)
require_equal(
    len(checks),
    35,
    f"catalog.json contains {len(checks)} checks; expected 35",
)
if not all(isinstance(entry, dict) for entry in checks):
    fail("catalog.json contains a check entry that is not an object")
ids = [entry.get("id") for entry in checks]
if not all(isinstance(check_id, str) for check_id in ids):
    fail("catalog.json contains a check without a string id")
require_equal(
    ids,
    sorted(ids),
    "catalog.json checks are not sorted by id",
)
for entry in checks:
    artifact = entry.get("artifact")
    if not isinstance(artifact, str) or not artifact:
        fail(f"catalog check {entry.get('id')!r} has no artifact path")
    expected = entry.get("sha256")
    actual = sha256(artifact)
    require_equal(
        actual,
        expected,
        f"catalog digest mismatch for {artifact} "
        f"(catalog sha256 {expected!r}, file sha256 {actual})",
    )

print("scanner", scanner)
print("review", review)
print("catalog/hash verification OK")
PY
```

For this repository revision the printed artifact digests are:

```text
scanner c8b7b67e0b24ff0087eb12b8796118c77ea8dfb454594d755a62ba113cc1f362
review f7fa42539cb1f9f9e6ec4a9bfa6c367bd11bcef623b8aa6ab986697f18268bf7
```

The published `v0.1.0` assets have a documented tag/asset discrepancy. See the
[`v0.1.0` release-integrity note](RELEASE-NOTES.md#v010-release-integrity-note)
before comparing that release.

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
