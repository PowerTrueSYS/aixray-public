# Release Integrity Gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add one local and CI release gate that binds AIXray release assets, catalog digests, mirrored scanner bytes, and declared versions to a `v*` tag, while documenting the immutable `v0.1.0` discrepancy.

**Architecture:** A standard-library Python CLI owns the validation contract and accepts a candidate tree plus an optional downloaded-asset directory. Unit tests exercise synthetic trees; GitHub Actions supplies the checked-out tag and, for release events, assets downloaded by `gh`. The verification guide keeps a self-contained, fail-closed digest block for skeptical readers.

**Tech Stack:** Python 3 standard library, `unittest`, POSIX shell, GitHub Actions, GitHub CLI.

---

### Task 1: Lock the release gate behavior with failing tests

**Files:**

- Create: `tests/test-release-integrity.py`
- Modify: `tests/run-tests.sh`

- [ ] **Step 1: Build a minimal release fixture**

Create a `unittest.TestCase` helper that writes scanner, site scanner, review
helper, one standalone check, a matching `catalog.json`, and the two expected
assets under a temporary directory. Use `hashlib.sha256` to populate catalog
digests.

- [ ] **Step 2: Add one assertion per required behavior**

Invoke:

```python
subprocess.run(
    [
        "python3",
        str(ROOT / "tools" / "verify-release-integrity.py"),
        "--tag",
        "v0.1.0",
        "--repo-root",
        str(tree),
        "--assets-dir",
        str(assets),
    ],
    text=True,
    capture_output=True,
    check=False,
)
```

Assert a correct fixture passes. In isolated tests, assert clear failures for a
missing review helper, mismatched scanner asset, bad catalog digest,
scanner/site divergence, version mismatch, missing asset, and unexpected
asset.

- [ ] **Step 3: Run the test and verify RED**

Run:

```sh
python3 tests/test-release-integrity.py -v
```

Expected: failures because `tools/verify-release-integrity.py` does not exist.

- [ ] **Step 4: Add the new suite to the existing runner**

Append:

```sh
python3 "$ROOT/tests/test-release-integrity.py" "$@" || FAILED=1
```

to `tests/run-tests.sh`.

### Task 2: Implement the local release-integrity gate

**Files:**

- Create: `tools/verify-release-integrity.py`

- [ ] **Step 1: Implement the CLI and validation result collector**

Accept required `--tag`, optional `--repo-root` defaulting to `.`, and optional
`--assets-dir`. Normalize no user path into a different checkout and report all
expected validation failures without tracebacks.

- [ ] **Step 2: Implement tree, catalog, digest, mirror, and version checks**

Keep the release paths as the fixed tuple:

```python
RELEASE_ARTIFACTS = ("aixray-aix.sh", "aixray-review-pack.sh")
```

Require the scanner's `VERSION="<tag without v>"` and the review helper's
`AIXRAY_REVIEW_PACK_VERSION="<tag without v>"`. Check `tool_version`, all
cataloged standalone digests, the two top-level catalog records, and exact
root/site scanner identity. Reject absolute or parent-relative catalog paths,
every symlinked path component beneath the candidate root, and any resolved
path outside that root.

- [ ] **Step 3: Implement optional exact asset-set comparison**

When `--assets-dir` is supplied, require exactly the two expected regular file
names and compare SHA-256 plus bytes against the candidate tree.

- [ ] **Step 4: Run the focused tests and verify GREEN**

Run:

```sh
python3 tests/test-release-integrity.py -v
```

Expected: all release-integrity tests pass.

### Task 3: Make the review helper and verification guide self-identifying

**Files:**

- Modify: `aixray-review-pack.sh`
- Modify: `docs/VERIFY.md`
- Modify: `tests/test-public-funnel.py`

- [ ] **Step 1: Add failing tests for the documented block**

Extract the first Python heredoc from `docs/VERIFY.md`. Run it from the current
tree and require success. Run it from a minimal copy missing
`aixray-review-pack.sh` and require a nonzero result that names the file,
contains checkout guidance, and does not contain `Traceback`.

- [ ] **Step 2: Verify the documentation test is RED**

Run:

```sh
python3 tests/test-public-funnel.py -v
```

Expected: the missing-artifact case fails because the current block emits a
`FileNotFoundError` traceback.

- [ ] **Step 3: Add the review helper version declaration**

Add:

```sh
AIXRAY_REVIEW_PACK_VERSION="0.1.0"
```

near the top of `aixray-review-pack.sh`.

- [ ] **Step 4: Replace assertions with actionable checks**

In the documented Python block, check each required path before reading,
replace bare assertions with named comparisons, and terminate through:

```python
def fail(message):
    raise SystemExit(f"artifact verification failed: {message}")
```

On mismatch, tell the reader to confirm the checked-out release tag or commit
and obtain clean files from that revision.

- [ ] **Step 5: Recompute the genuinely changed review-helper digest**

Update only `catalog.json`'s `review_pack.sha256`, the two public digest
locations in `README.md` and `docs/VERIFY.md`, and release-note current-version
references that depend on the changed bytes. Do not modify unrelated catalog
content.

- [ ] **Step 6: Run the documentation and gate tests**

Run both Python test files. Expected: all portable cases pass.

### Task 4: Wire the same gate into GitHub Actions

**Files:**

- Modify: `.github/workflows/public-checks.yml`
- Modify: `tests/test-public-funnel.py`

- [ ] **Step 1: Extend the workflow contract test**

Require a `v*` push trigger, release publication/edit triggers, checkout with
full history, a tree-only gate invocation for tag pushes, a `gh release
download` step for release events, and an asset-directory gate invocation.

- [ ] **Step 2: Verify the workflow test is RED**

Run:

```sh
python3 tests/test-public-funnel.py -v
```

Expected: the workflow assertions fail because tag and release hooks are
absent.

- [ ] **Step 3: Extend the workflow without duplicating gate logic**

Retain existing checks. Add `push.tags: ["v*"]` and
`release.types: [published, edited, released]`. Check out the release tag for
release events, run the local script against tag pushes, download all release
assets for release events, and pass that directory to the same script.

- [ ] **Step 4: Re-run the workflow contract test**

Expected: the focused test passes.

### Task 5: Document the historical release discrepancy

**Files:**

- Create: `docs/RELEASE-NOTES.md`
- Modify: `README.md`

- [ ] **Step 1: Add the exact factual note**

State the immutable tag commit, matching later master commit, and both
published asset digests. Include a short block explicitly labeled as text for
the existing GitHub `v0.1.0` release body.

- [ ] **Step 2: Link the note from the verification section**

Add one sentence in `README.md` directing `v0.1.0` users to the release
integrity note. Do not add claims, promises, customer names, or platform
support statements.

### Task 6: Prove teeth and complete one pushed commit

**Files:**

- Verify all modified files.

- [ ] **Step 1: Run separate failing demonstrations**

Using temporary directories, run the gate once with a scanner asset whose
bytes differ from the candidate tree and once with the review helper absent
from the candidate tree. Capture both nonzero outputs.

- [ ] **Step 2: Run the passing demonstration**

Run the gate with a correct tree and exact two-file asset directory. Capture
the zero-exit output.

- [ ] **Step 3: Demonstrate the documented block**

Run the extracted block against a missing-helper tree and the current good
tree. Capture the clear failure and success outputs.

- [ ] **Step 4: Run all requested verification**

Run:

```sh
PYTHONDONTWRITEBYTECODE=1 sh tests/run-tests.sh
sh tools/ci/egress-lint.sh aixray-aix.sh aixray-review-pack.sh checks/*/*.ksh
python3 tools/check-no-ibm-redistribution.py
sh -n aixray-aix.sh
sh -n aixray-review-pack.sh
ksh -n aixray-aix.sh
ksh -n aixray-review-pack.sh
```

Also run the exact prohibited-claim grep from the task specification. Require
that grep to be empty and every check command above to exit zero.

- [ ] **Step 5: Review and publish exactly one commit**

Inspect `git diff --check`, the complete diff, and status. Stage only intended
paths, make one commit, push `feat/release-integrity-gate`, verify the remote
branch points at the new commit, and do not merge or open a pull request.
