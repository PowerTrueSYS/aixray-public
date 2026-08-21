#!/usr/bin/env python3
"""Validate that release assets are exact products of one tagged tree."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys
from typing import Any


SCANNER_PATH = "ptxray-aix.sh"
IBMI_SCANNER_PATH = "ptxray-ibmi.sh"
SITE_SCANNER_PATH = "site/ptxray-aix.sh"
REVIEW_HELPER_PATH = "ptxray-review-pack.sh"
REVIEW_VALIDATOR_PATH = "ptxray-review-validate.awk"
CHECKSUM_MANIFEST_PATH = "SHA256SUMS"
CURRENT_PAYLOAD_ARTIFACTS = (
    SCANNER_PATH,
    IBMI_SCANNER_PATH,
    REVIEW_HELPER_PATH,
    REVIEW_VALIDATOR_PATH,
)
CURRENT_RELEASE_ARTIFACTS = (
    *CURRENT_PAYLOAD_ARTIFACTS,
    CHECKSUM_MANIFEST_PATH,
)
LEGACY_RELEASE_ARTIFACTS = {
    "0.1.0": (SCANNER_PATH, REVIEW_HELPER_PATH),
}
# Byte-copy transition aliases published as release assets only (rebrand R2).
# An alias is NOT a SHA256SUMS payload and NOT a required tagged-tree file: it
# carries no manifest line, so pre-rename download links keep resolving without
# changing what SHA256SUMS proves. Each alias MUST be byte-identical to the
# release payload it mirrors; validate_assets asserts that same-bytes invariant.
# Mirrors tools/render-public-release.py RELEASE_ASSET_ALIASES. Retire at 2.0.
CURRENT_RELEASE_ASSET_ALIASES = {
    "aixray-aix.sh": SCANNER_PATH,
}
VERSION_VARIABLES = {
    SCANNER_PATH: "VERSION",
    REVIEW_HELPER_PATH: "AIXRAY_REVIEW_PACK_VERSION",
}


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def release_artifacts_for_version(version: str | None) -> tuple[str, ...]:
    return LEGACY_RELEASE_ARTIFACTS.get(version, CURRENT_RELEASE_ARTIFACTS)


def release_asset_aliases_for_version(version: str | None) -> dict[str, str]:
    # The immutable v0.1.0 surface predates the rename and ships no alias.
    if version in LEGACY_RELEASE_ARTIFACTS:
        return {}
    return dict(CURRENT_RELEASE_ASSET_ALIASES)


class Validator:
    """Collect every actionable release-integrity error in one run."""

    def __init__(
        self,
        *,
        tag: str,
        root: Path,
        assets_dir: Path | None,
    ) -> None:
        self.tag = tag
        self.root = root
        self.assets_dir = assets_dir
        self.errors: list[str] = []
        self.contents: dict[str, bytes] = {}
        self.failed_reads: set[str] = set()
        self.version = self._version_from_tag()
        self.release_artifacts = release_artifacts_for_version(self.version)
        self.release_asset_aliases = release_asset_aliases_for_version(
            self.version
        )

    def fail(self, message: str) -> None:
        self.errors.append(message)

    def _version_from_tag(self) -> str | None:
        match = re.fullmatch(r"v([0-9][0-9A-Za-z.+-]*)", self.tag)
        if match is None:
            self.fail(
                f"invalid release tag {self.tag!r}; expected v followed by "
                "a version, for example v0.1.0"
            )
            return None
        return match.group(1)

    def _tree_path(self, relative: str) -> Path | None:
        candidate = PurePosixPath(relative)
        if (
            candidate.is_absolute()
            or ".." in candidate.parts
            or relative in ("", ".")
        ):
            self.fail(f"catalog contains unsafe artifact path: {relative!r}")
            return None

        path = self.root
        component_parts: list[str] = []
        for part in candidate.parts:
            path /= part
            component_parts.append(part)
            try:
                is_symlink = path.is_symlink()
            except OSError as exc:
                self.fail(f"cannot inspect tagged-tree path {relative}: {exc}")
                return None
            if is_symlink:
                component = PurePosixPath(*component_parts).as_posix()
                self.fail(
                    f"tagged-tree path traverses symlink: {relative} "
                    f"(component {component})"
                )
                return None

        try:
            resolved_root = self.root.resolve(strict=False)
            resolved_path = path.resolve(strict=False)
            resolved_path.relative_to(resolved_root)
        except ValueError:
            self.fail(
                f"tagged-tree path resolves outside candidate root: {relative}"
            )
            return None
        except (OSError, RuntimeError) as exc:
            self.fail(f"cannot resolve tagged-tree path {relative}: {exc}")
            return None
        return path

    def read_tree_file(
        self,
        relative: str,
        *,
        missing_message: str | None = None,
    ) -> bytes | None:
        if relative in self.contents:
            return self.contents[relative]
        if relative in self.failed_reads:
            return None
        path = self._tree_path(relative)
        if path is None:
            self.failed_reads.add(relative)
            return None
        if not path.is_file() or path.is_symlink():
            self.fail(
                missing_message
                or f"cataloged artifact is missing from tagged tree: {relative}"
            )
            self.failed_reads.add(relative)
            return None
        try:
            content = path.read_bytes()
        except OSError as exc:
            self.fail(f"cannot read tagged-tree file {relative}: {exc}")
            self.failed_reads.add(relative)
            return None
        self.contents[relative] = content
        return content

    def validate_required_release_files(self) -> None:
        for relative in self.release_artifacts:
            self.read_tree_file(
                relative,
                missing_message=(
                    "required release artifact is missing from tagged tree: "
                    f"{relative}"
                ),
            )

    def validate_sha256sums(self, catalog: dict[str, Any] | None = None) -> None:
        if CHECKSUM_MANIFEST_PATH not in self.release_artifacts:
            return
        content = self.read_tree_file(CHECKSUM_MANIFEST_PATH)
        if content is None:
            return
        try:
            source = content.decode("utf-8")
        except UnicodeDecodeError as exc:
            self.fail(f"SHA256SUMS is not valid UTF-8: {exc}")
            return

        entries: dict[str, str] = {}
        for line_number, line in enumerate(source.splitlines(), start=1):
            match = re.fullmatch(r"([0-9A-Fa-f]{64})[ \t]+\*?(\S+)", line)
            if match is None:
                self.fail(
                    f"SHA256SUMS line {line_number} is malformed; expected "
                    "a SHA-256 digest and top-level artifact name"
                )
                continue
            digest, relative = match.groups()
            if relative in entries:
                self.fail(f"SHA256SUMS contains duplicate entry: {relative}")
                continue
            entries[relative] = digest.lower()

        if self.version == "0.1.0":
            expected_payloads = CURRENT_PAYLOAD_ARTIFACTS
        else:
            if catalog is None:
                self.fail(
                    "cannot validate SHA256SUMS payload set: catalog.json "
                    "could not be loaded"
                )
                return
            checks = catalog.get("checks")
            if not isinstance(checks, list):
                self.fail("catalog.json checks must be a list")
                return
            check_artifacts: list[str] = []
            for index, entry in enumerate(checks):
                if not isinstance(entry, dict):
                    self.fail(f"catalog checks[{index}] must be an object")
                    continue
                artifact_path = entry.get("artifact")
                if not isinstance(artifact_path, str) or not artifact_path:
                    check_id = entry.get("id", f"index {index}")
                    self.fail(
                        f"catalog check {check_id!r} has missing or "
                        "empty artifact path"
                    )
                    continue
                check_artifacts.append(artifact_path)
            expected_payloads = CURRENT_PAYLOAD_ARTIFACTS + tuple(
                check_artifacts
            )

        expected_names = set(expected_payloads)
        actual_names = set(entries)
        missing = sorted(expected_names - actual_names)
        unexpected = sorted(actual_names - expected_names)
        if missing:
            self.fail(
                "SHA256SUMS payload set mismatch: missing " + ", ".join(missing)
            )
        if unexpected:
            self.fail(
                "SHA256SUMS payload set mismatch: unexpected "
                + ", ".join(unexpected)
            )

        for relative in expected_payloads:
            expected = entries.get(relative)
            if expected is None:
                continue
            payload = self.read_tree_file(relative)
            if payload is None:
                continue
            actual = sha256_bytes(payload)
            if actual != expected:
                self.fail(
                    f"SHA256SUMS digest mismatch for {relative}: "
                    f"manifest sha256={expected} tagged sha256={actual}"
                )

    def load_catalog(self) -> dict[str, Any] | None:
        content = self.read_tree_file(
            "catalog.json",
            missing_message="required tagged-tree file is missing: catalog.json",
        )
        if content is None:
            return None
        try:
            decoded = content.decode("utf-8")
            catalog = json.loads(decoded)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            self.fail(f"catalog.json is not valid UTF-8 JSON: {exc}")
            return None
        if not isinstance(catalog, dict):
            self.fail("catalog.json root must be a JSON object")
            return None
        return catalog

    def validate_catalog_digest(
        self,
        *,
        relative: object,
        expected: object,
        label: str | None = None,
    ) -> None:
        if not isinstance(relative, str) or not relative:
            self.fail(f"{label or 'catalog entry'} has no valid artifact path")
            return
        if not isinstance(expected, str):
            self.fail(f"catalog digest is missing for {relative}")
            return
        content = self.read_tree_file(relative)
        if content is None:
            return
        actual = sha256_bytes(content)
        if actual != expected:
            self.fail(
                f"catalog digest mismatch for {relative}: "
                f"catalog sha256={expected} tagged sha256={actual}"
            )

    def validate_catalog(self, catalog: dict[str, Any]) -> None:
        if self.version is not None and catalog.get("tool_version") != self.version:
            self.fail(
                f"catalog.json tool_version is {catalog.get('tool_version')}; "
                f"tag {self.tag} requires {self.version}"
            )

        checks = catalog.get("checks")
        if not isinstance(checks, list):
            self.fail("catalog.json checks must be a list")
        else:
            if catalog.get("check_count") != len(checks):
                self.fail(
                    "catalog.json check_count does not match checks length: "
                    f"{catalog.get('check_count')} != {len(checks)}"
                )
            for index, entry in enumerate(checks):
                if not isinstance(entry, dict):
                    self.fail(f"catalog checks[{index}] must be an object")
                    continue
                self.validate_catalog_digest(
                    relative=entry.get("artifact"),
                    expected=entry.get("sha256"),
                    label=f"catalog checks[{index}]",
                )

        assembled = catalog.get("assembled_scanner")
        if not isinstance(assembled, dict):
            self.fail("catalog.json assembled_scanner must be an object")
        else:
            if assembled.get("artifact") != SCANNER_PATH:
                self.fail(
                    "catalog assembled_scanner.artifact must be "
                    f"{SCANNER_PATH}; found {assembled.get('artifact')}"
                )
            if assembled.get("site_artifact") != SITE_SCANNER_PATH:
                self.fail(
                    "catalog assembled_scanner.site_artifact must be "
                    f"{SITE_SCANNER_PATH}; found {assembled.get('site_artifact')}"
                )
            expected = assembled.get("sha256")
            self.validate_catalog_digest(
                relative=SCANNER_PATH,
                expected=expected,
            )
            self.validate_catalog_digest(
                relative=SITE_SCANNER_PATH,
                expected=expected,
            )

        review = catalog.get("review_pack")
        if not isinstance(review, dict):
            self.fail("catalog.json review_pack must be an object")
        else:
            if review.get("artifact") != REVIEW_HELPER_PATH:
                self.fail(
                    "catalog review_pack.artifact must be "
                    f"{REVIEW_HELPER_PATH}; found {review.get('artifact')}"
                )
            self.validate_catalog_digest(
                relative=REVIEW_HELPER_PATH,
                expected=review.get("sha256"),
            )

    def validate_scanner_copies(self) -> None:
        root_scanner = self.read_tree_file(SCANNER_PATH)
        site_scanner = self.read_tree_file(SITE_SCANNER_PATH)
        if (
            root_scanner is not None
            and site_scanner is not None
            and root_scanner != site_scanner
        ):
            self.fail(
                f"scanner copies differ: {SCANNER_PATH} != {SITE_SCANNER_PATH}"
            )

    def validate_versions(self) -> None:
        if self.version is None:
            return
        for relative, variable in VERSION_VARIABLES.items():
            content = self.read_tree_file(relative)
            if content is None:
                continue
            try:
                source = content.decode("utf-8")
            except UnicodeDecodeError as exc:
                self.fail(f"{relative} is not valid UTF-8: {exc}")
                continue
            pattern = re.compile(
                rf"(?m)^{re.escape(variable)}=[\"']([^\"']+)[\"'][ \t]*$"
            )
            declarations = pattern.findall(source)
            if len(declarations) != 1:
                self.fail(
                    f"version declaration missing or ambiguous in {relative}: "
                    f'expected exactly one {variable}="{self.version}"'
                )
                continue
            declared = declarations[0]
            if declared != self.version:
                self.fail(
                    f"version mismatch in {relative}: {variable} declares "
                    f"{declared}; tag {self.tag} requires {self.version}"
                )

    def validate_assets(self) -> None:
        if self.assets_dir is None:
            return
        if not self.assets_dir.is_dir() or self.assets_dir.is_symlink():
            self.fail(
                f"release asset directory does not exist: {self.assets_dir}"
            )
            return
        try:
            entries = {entry.name: entry for entry in self.assets_dir.iterdir()}
        except OSError as exc:
            self.fail(f"cannot list release asset directory: {exc}")
            return

        # The published surface is the SHA256SUMS-listed release artifacts plus
        # the byte-copy transition aliases, which carry no manifest line.
        expected_names = set(self.release_artifacts) | set(
            self.release_asset_aliases
        )
        for missing in sorted(expected_names - entries.keys()):
            self.fail(f"required release asset is missing: {missing}")
        for unexpected in sorted(entries.keys() - expected_names):
            self.fail(f"unexpected release asset: {unexpected}")

        for relative in self.release_artifacts:
            asset = entries.get(relative)
            tagged = self.read_tree_file(relative)
            if asset is None or tagged is None:
                continue
            if not asset.is_file() or asset.is_symlink():
                self.fail(f"release asset is not a regular file: {relative}")
                continue
            try:
                published = asset.read_bytes()
            except OSError as exc:
                self.fail(f"cannot read release asset {relative}: {exc}")
                continue
            if published != tagged:
                self.fail(
                    f"release asset differs from tagged tree: {relative}: "
                    f"tagged sha256={sha256_bytes(tagged)} "
                    f"asset sha256={sha256_bytes(published)}"
                )

        # R2 same-bytes invariant: a transition alias is not on the manifest,
        # so nothing else proves its bytes. It MUST be byte-identical to the
        # payload it mirrors; a drifted alias is a release-integrity error.
        for alias_name, target in self.release_asset_aliases.items():
            asset = entries.get(alias_name)
            target_bytes = self.read_tree_file(target)
            if asset is None or target_bytes is None:
                continue
            if not asset.is_file() or asset.is_symlink():
                self.fail(f"release asset is not a regular file: {alias_name}")
                continue
            try:
                published = asset.read_bytes()
            except OSError as exc:
                self.fail(f"cannot read release asset {alias_name}: {exc}")
                continue
            if published != target_bytes:
                self.fail(
                    f"release asset alias {alias_name} is not byte-identical to "
                    f"{target}: {target} sha256={sha256_bytes(target_bytes)} "
                    f"alias sha256={sha256_bytes(published)}"
                )

    def run(self) -> bool:
        self.validate_required_release_files()
        catalog = self.load_catalog()
        self.validate_sha256sums(catalog)
        if catalog is not None:
            self.validate_catalog(catalog)
        self.validate_scanner_copies()
        self.validate_versions()
        self.validate_assets()
        return not self.errors

    def print_result(self) -> None:
        if self.errors:
            for error in self.errors:
                print(f"release-integrity: FAIL: {error}", file=sys.stderr)
            print(
                f"release-integrity: FAIL: {self.tag} has "
                f"{len(self.errors)} integrity error(s)",
                file=sys.stderr,
            )
            return

        for relative in self.release_artifacts:
            content = self.contents[relative]
            print(
                f"release-integrity: OK: {relative} "
                f"sha256={sha256_bytes(content)}"
            )
        if self.assets_dir is not None:
            for alias_name, target in self.release_asset_aliases.items():
                content = self.contents.get(target)
                if content is None:
                    continue
                print(
                    f"release-integrity: OK: {alias_name} "
                    f"(byte-alias of {target}) sha256={sha256_bytes(content)}"
                )
        scope = (
            "tagged tree and release assets"
            if self.assets_dir is not None
            else "tagged tree"
        )
        print(f"release-integrity: PASS: {self.tag} ({scope} verified)")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Verify release files, catalog digests, mirrored scanner bytes, "
            "declared versions, and optional published assets."
        )
    )
    parser.add_argument("--tag", required=True, help="release tag, such as v0.1.0")
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path("."),
        help="candidate tagged tree (default: current directory)",
    )
    parser.add_argument(
        "--assets-dir",
        type=Path,
        help="directory containing all uploaded release assets",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    validator = Validator(
        tag=args.tag,
        root=args.repo_root,
        assets_dir=args.assets_dir,
    )
    passed = validator.run()
    validator.print_result()
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
