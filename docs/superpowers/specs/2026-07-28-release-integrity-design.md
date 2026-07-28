# Release integrity gate design

## Purpose

Bind every AIXray release asset to one immutable tagged tree. The same
validation must run locally before a tag is pushed and in GitHub Actions when
the tag or release is created. Historical `v0.1.0` remains unchanged; its
release discrepancy is documented factually.

## Contract

The release asset set is deliberately independent of `catalog.json`:

- `aixray-aix.sh`
- `aixray-review-pack.sh`

Both paths must exist as regular files in the candidate tree. Every required
or cataloged path must be relative, traverse no symlink component beneath the
candidate root, and resolve within that root. This independent list prevents a
stale or incomplete catalog from silently redefining what a release is
expected to ship.

The gate accepts a tag name, a repository-tree directory, and optionally a
directory containing release assets. It validates:

1. the tag starts with `v`, and its remaining text is the expected version;
2. both release files exist in the tree;
3. `catalog.json` is valid and its `tool_version` matches the tag;
4. every cataloged check artifact exists and matches its SHA-256;
5. the assembled scanner, site scanner, and review helper paths and SHA-256
   values match their catalog records;
6. root and site scanner bytes are identical;
7. each released shell artifact's declared version matches the tag; and
8. when an asset directory is supplied, its regular-file names are exactly the
   expected release asset set and every asset is byte-identical to the same
   relative path in the tree.

All validation errors are collected and printed as
`release-integrity: FAIL: <actionable detail>`. Missing files are reported
before any read, so an administrator never receives a Python traceback for an
expected validation failure. Success prints the tag, both release digests, and
`release-integrity: PASS`.

## CI data flow

Pull requests and pushes to `master` retain the existing public checks. A
`v*` tag push checks the tagged tree before a release is published. GitHub
release publication or edit checks out the release's tag, downloads all
uploaded assets, and invokes the same script with the asset directory. This
separates the pre-publication invariant from the post-upload byte comparison
without duplicating validation logic.

## Documentation

The inline Python procedure in `docs/VERIFY.md` remains independently
copyable. Small `require_file`, `require_equal`, and `fail` helpers replace
raw reads and assertions, producing a one-line explanation naming the failed
path and directing the reader to verify the checked-out revision.

`docs/RELEASE-NOTES.md` records that the immutable `v0.1.0` tag points to
`d0587e17bc4fc387c11e8df317cc85e6aa8c2f4a`, while its uploaded assets match
the later master commit `ed854a50801a050ebf9932ac99af522f76caa4a6`.
It gives both published SHA-256 values and text suitable for the existing
GitHub release body. The live release and tag are not modified.

## Tests

Standard-library unit tests build a minimal valid release tree and asset
directory. Separate cases prove rejection of a missing shipped file, a
different asset, a bad catalog digest, scanner/site divergence, version
divergence, a catalog path under a symlinked parent, and an incomplete or extra
asset set. The same fixture proves the correct set passes.

Contract tests extract the Python block from `docs/VERIFY.md`, run it against
the current tree, and run it against a copy missing the review helper. The
missing-file case must name `aixray-review-pack.sh`, offer corrective guidance,
and contain no traceback. A separate fixture proves the documented block also
rejects a catalog path that traverses a symlinked parent.
