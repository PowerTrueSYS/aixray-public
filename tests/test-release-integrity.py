#!/usr/bin/env python3
"""Release-integrity contract tests using isolated synthetic release trees."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "tools" / "verify-release-integrity.py"
TAG = "v0.2.0"
VERSION = "0.2.0"
PAYLOAD_ARTIFACTS = (
    "ptxray-aix.sh",
    "ptxray-review-pack.sh",
    "ptxray-review-validate.awk",
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ReleaseIntegrityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="aixray-release-integrity-"
        )
        self.base = Path(self.temporary.name)
        self.tree = self.base / "tree"
        self.assets = self.base / "assets"
        (self.tree / "site").mkdir(parents=True)
        (self.tree / "checks" / "ck-example").mkdir(parents=True)
        self.assets.mkdir()

        scanner = (
            "#!/bin/sh\n"
            f'VERSION="{VERSION}"\n'
            "printf '%s\\n' \"$VERSION\"\n"
        ).encode()
        review = (
            "#!/bin/sh\n"
            f'AIXRAY_REVIEW_PACK_VERSION="{VERSION}"\n'
            "exit 0\n"
        ).encode()
        validator = b'BEGIN { print "validated" }\n'
        check = (
            "#!/bin/ksh\n"
            f'AIXRAY_STANDALONE_VERSION="{VERSION}"\n'
            "exit 0\n"
        ).encode()

        (self.tree / "ptxray-aix.sh").write_bytes(scanner)
        (self.tree / "site" / "ptxray-aix.sh").write_bytes(scanner)
        (self.tree / "ptxray-review-pack.sh").write_bytes(review)
        (self.tree / "ptxray-review-validate.awk").write_bytes(validator)
        (
            self.tree / "checks" / "ck-example" / "ck-example.ksh"
        ).write_bytes(check)
        (self.assets / "ptxray-aix.sh").write_bytes(scanner)
        (self.assets / "ptxray-review-pack.sh").write_bytes(review)
        (self.assets / "ptxray-review-validate.awk").write_bytes(validator)
        self.write_catalog()
        self.write_sha256sums()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_catalog(self, *, version: str = VERSION) -> None:
        scanner = self.tree / "ptxray-aix.sh"
        review = self.tree / "ptxray-review-pack.sh"
        check = self.tree / "checks" / "ck-example" / "ck-example.ksh"
        catalog = {
            "schema_version": 1,
            "tool_version": version,
            "check_count": 1,
            "checks": [
                {
                    "id": "ck-example",
                    "artifact": "checks/ck-example/ck-example.ksh",
                    "sha256": sha256(check),
                }
            ],
            "assembled_scanner": {
                "artifact": "ptxray-aix.sh",
                "site_artifact": "site/ptxray-aix.sh",
                "sha256": sha256(scanner),
            },
            "review_pack": {
                "artifact": "ptxray-review-pack.sh",
                "sha256": sha256(review),
            },
        }
        (self.tree / "catalog.json").write_text(
            json.dumps(catalog, indent=2) + "\n",
            encoding="utf-8",
        )

    def write_sha256sums(
        self,
        *,
        artifacts: tuple[str, ...] = PAYLOAD_ARTIFACTS
        + ("checks/ck-example/ck-example.ksh",),
        digest_overrides: dict[str, str] | None = None,
    ) -> None:
        digest_overrides = digest_overrides or {}
        content = "".join(
            f"{digest_overrides.get(relative, sha256(self.tree / relative))}  "
            f"{relative}\n"
            for relative in artifacts
        )
        (self.tree / "SHA256SUMS").write_text(content, encoding="utf-8")
        (self.assets / "SHA256SUMS").write_text(content, encoding="utf-8")

    def run_gate(
        self, *, with_assets: bool = True, tag: str = TAG
    ) -> subprocess.CompletedProcess[str]:
        command = [
            "python3",
            str(GATE),
            "--tag",
            tag,
            "--repo-root",
            str(self.tree),
        ]
        if with_assets:
            command.extend(("--assets-dir", str(self.assets)))
        return subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )

    def assert_failed_with(self, expected: str) -> subprocess.CompletedProcess[str]:
        result = self.run_gate()
        combined = result.stdout + result.stderr
        self.assertNotEqual(0, result.returncode, combined)
        self.assertIn(expected, combined)
        self.assertNotIn("Traceback", combined)
        return result

    def test_correct_release_tree_and_assets_pass(self) -> None:
        result = self.run_gate()
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("release-integrity: PASS: v0.2.0", result.stdout)
        self.assertIn(
            f"ptxray-aix.sh sha256={sha256(self.tree / 'ptxray-aix.sh')}",
            result.stdout,
        )
        self.assertIn(
            "ptxray-review-pack.sh "
            f"sha256={sha256(self.tree / 'ptxray-review-pack.sh')}",
            result.stdout,
        )
        self.assertIn(
            "ptxray-review-validate.awk "
            f"sha256={sha256(self.tree / 'ptxray-review-validate.awk')}",
            result.stdout,
        )
        self.assertIn(
            f"SHA256SUMS sha256={sha256(self.tree / 'SHA256SUMS')}",
            result.stdout,
        )

    def test_tree_only_preflight_passes_without_asset_directory(self) -> None:
        result = self.run_gate(with_assets=False)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("release-integrity: PASS: v0.2.0", result.stdout)

    def test_missing_shipped_file_fails_with_its_path(self) -> None:
        (self.tree / "ptxray-review-validate.awk").unlink()
        result = self.assert_failed_with(
            "required release artifact is missing from tagged tree: "
            "ptxray-review-validate.awk"
        )

    def test_different_release_asset_fails_with_both_digests(self) -> None:
        different = b"#!/bin/sh\nVERSION=\"0.2.0\"\n# different bytes\n"
        (self.assets / "ptxray-aix.sh").write_bytes(different)
        result = self.assert_failed_with(
            "release asset differs from tagged tree: ptxray-aix.sh"
        )
        combined = result.stdout + result.stderr
        self.assertIn(
            f"tagged sha256={sha256(self.tree / 'ptxray-aix.sh')}",
            combined,
        )
        self.assertIn(
            f"asset sha256={sha256(self.assets / 'ptxray-aix.sh')}",
            combined,
        )

    def test_catalog_digest_mismatch_names_cataloged_artifact(self) -> None:
        catalog_path = self.tree / "catalog.json"
        catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
        catalog["checks"][0]["sha256"] = "0" * 64
        catalog_path.write_text(
            json.dumps(catalog, indent=2) + "\n",
            encoding="utf-8",
        )
        self.assert_failed_with(
            "catalog digest mismatch for "
            "checks/ck-example/ck-example.ksh"
        )

    def test_catalog_artifact_cannot_traverse_symlinked_parent(self) -> None:
        check_directory = self.tree / "checks" / "ck-example"
        external_directory = self.base / "external-check"
        check_directory.rename(external_directory)
        check_directory.symlink_to(external_directory, target_is_directory=True)
        self.assert_failed_with(
            "tagged-tree path traverses symlink: "
            "checks/ck-example/ck-example.ksh "
            "(component checks/ck-example)"
        )

    def test_root_and_site_scanner_divergence_is_rejected(self) -> None:
        (self.tree / "site" / "ptxray-aix.sh").write_bytes(
            b"#!/bin/sh\nVERSION=\"0.2.0\"\n# divergent site copy\n"
        )
        self.assert_failed_with(
            "scanner copies differ: ptxray-aix.sh != site/ptxray-aix.sh"
        )

    def test_artifact_version_must_match_tag(self) -> None:
        scanner = b"#!/bin/sh\nVERSION=\"9.9.9\"\nexit 0\n"
        (self.tree / "ptxray-aix.sh").write_bytes(scanner)
        (self.tree / "site" / "ptxray-aix.sh").write_bytes(scanner)
        (self.assets / "ptxray-aix.sh").write_bytes(scanner)
        self.write_catalog()
        self.assert_failed_with(
            "version mismatch in ptxray-aix.sh: VERSION declares 9.9.9; "
            "tag v0.2.0 requires 0.2.0"
        )

    def test_review_helper_version_must_match_tag(self) -> None:
        review = (
            b"#!/bin/sh\n"
            b'AIXRAY_REVIEW_PACK_VERSION="9.9.9"\n'
            b"exit 0\n"
        )
        (self.tree / "ptxray-review-pack.sh").write_bytes(review)
        (self.assets / "ptxray-review-pack.sh").write_bytes(review)
        self.write_catalog()
        self.assert_failed_with(
            "version mismatch in ptxray-review-pack.sh: "
            "AIXRAY_REVIEW_PACK_VERSION declares 9.9.9; "
            "tag v0.2.0 requires 0.2.0"
        )

    def test_catalog_version_must_match_tag(self) -> None:
        catalog_path = self.tree / "catalog.json"
        catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
        catalog["tool_version"] = "9.9.9"
        catalog_path.write_text(
            json.dumps(catalog, indent=2) + "\n",
            encoding="utf-8",
        )
        self.assert_failed_with(
            "catalog.json tool_version is 9.9.9; "
            "tag v0.2.0 requires 0.2.0"
        )

    def test_missing_release_asset_is_rejected(self) -> None:
        (self.assets / "SHA256SUMS").unlink()
        self.assert_failed_with(
            "required release asset is missing: SHA256SUMS"
        )

    def test_unexpected_release_asset_is_rejected(self) -> None:
        (self.assets / "notes.txt").write_text("not a shipped artifact\n")
        self.assert_failed_with("unexpected release asset: notes.txt")

    def test_sha256sums_requires_exact_payload_set(self) -> None:
        payloads = PAYLOAD_ARTIFACTS + (
            "checks/ck-example/ck-example.ksh",
        )
        self.write_sha256sums(artifacts=payloads[:-1])
        self.assert_failed_with(
            "SHA256SUMS payload set mismatch: missing "
            "checks/ck-example/ck-example.ksh"
        )

    def test_sha256sums_digest_must_match_tagged_payload(self) -> None:
        self.write_sha256sums(
            artifacts=PAYLOAD_ARTIFACTS
            + ("checks/ck-example/ck-example.ksh",),
            digest_overrides={"ptxray-review-validate.awk": "0" * 64},
        )
        self.assert_failed_with(
            "SHA256SUMS digest mismatch for ptxray-review-validate.awk"
        )

    def test_v010_legacy_two_asset_surface_still_passes(self) -> None:
        legacy_version = "0.1.0"
        scanner = (
            "#!/bin/sh\n"
            f'VERSION="{legacy_version}"\n'
            "exit 0\n"
        ).encode()
        review = (
            "#!/bin/sh\n"
            f'AIXRAY_REVIEW_PACK_VERSION="{legacy_version}"\n'
            "exit 0\n"
        ).encode()
        for directory in (self.tree, self.assets):
            (directory / "ptxray-aix.sh").write_bytes(scanner)
            (directory / "ptxray-review-pack.sh").write_bytes(review)
            (directory / "ptxray-review-validate.awk").unlink()
            (directory / "SHA256SUMS").unlink()
        (self.tree / "site" / "ptxray-aix.sh").write_bytes(scanner)
        self.write_catalog(version=legacy_version)

        result = self.run_gate(tag="v0.1.0")

        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("release-integrity: PASS: v0.1.0", result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
