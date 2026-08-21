#!/usr/bin/env python3
"""End-to-end profile tests for the shipped AIX review-pack helper."""
from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / "ptxray-aix.sh"
REVIEW_HELPER = ROOT / "ptxray-review-pack.sh"
REVIEW_VALIDATOR = ROOT / "ptxray-review-validate.awk"
FIXTURE_ROOT = os.environ.get("AIXRAY_FIXTURE_ROOT")
FIXTURE = Path(FIXTURE_ROOT) if FIXTURE_ROOT else None
REVIEW_FIXTURES = ROOT / "tests" / "fixtures" / "review-pack"
FROZEN = "2026-07-01"
MAP_WARNING = (
    "# DO NOT SEND THIS FILE — local decode key"
)
KEEP_FRAGMENT = (
    "oslevel=7300-04-00-2549; firmware=VL950_179; VIOS=4.1; "
    "HMC=V10R3.1060.0; CVE=CVE-2026-12345; IV=IV99876; "
    "APAR=IJ55968; ifix=IJ55968s4a; check_id=security.apar_scan; "
    "status=NOT_ASSESSED; severity=high; category_score=78%; "
    "counts=57/21/9; paging=4%; dump=1241MB; "
    "tunable=maxperm%=90; device=devices.pciex.1410c183.rte; "
    "model=IBM,9009-22A; FLRTVC finding=CVE-2026-12345/IJ55968; "
    "date=2026-07-20"
)


def profile_report() -> str:
    return f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="aixray-report-version" content="1">
<meta name="aixray-privacy-schema" content="1">
<meta name="aixray-report-date" content="2026-07-20">
<meta name="aixray-report-host" content="prod-aix01">
<title>PTxray — prod-aix01</title>
<style>@page{{@top-left{{content:"PTxray · prod-aix01"}}@top-right{{content:"2026-07-20"}}}}</style>
</head><body>
<div class="meta" data-aixray-field="observed" data-aixray-location="report:host"><b>Host:</b> prod-aix01; hostname=prod-aix01; Node name: node-west-02; LPAR name: finance-lpar-7</div>
<table><tbody>
<tr><td class="ctl" data-aixray-field="observed" data-aixray-location="finding:network_exposure:label">Network identity</td><td class="obs" data-aixray-field="observed" data-aixray-location="finding:network_exposure:observed">address=10.42.8.17; netmask=255.255.255.0; IPv6=2001:db8:12::7; gateway=10.42.8.1; MAC=aa:bb:cc:dd:ee:ff; alternate MAC=12-34-56-78-9a-bc; ODM MAC=1234.5678.9abc; DNS=db01.corp.example; address/netmask=172.16.4.7/255.255.254.0</td></tr>
<tr><td class="ctl" data-aixray-field="observed" data-aixray-location="finding:tunables:label">Kernel tunables</td><td class="obs" data-aixray-field="observed" data-aixray-location="finding:tunables:observed">tunable=maxperm%=90; management address=172.16.5.1</td></tr>
<tr><td class="ctl" data-aixray-field="observed" data-aixray-location="finding:hw_gen:label">Hardware identity</td><td class="obs" data-aixray-field="observed" data-aixray-location="finding:hw_gen:observed">Machine Serial Number: 78AB12C; Frame ID=02AF91B; WWPN=0xC050760CBDBB884A; backup WWPN=10:00:00:90:fa:53:76:ec; LPAR UUID=3f2504e0-4f89-41d3-9a0c-0305e82c3301</td></tr>
<tr><td class="ctl" data-aixray-field="observed" data-aixray-location="finding:account_hygiene:label">People</td><td class="obs" data-aixray-field="observed" data-aixray-location="finding:account_hygiene:observed">username=alice; home=/home/alice; email=ops.user@example.internal; GECOS=Alice Operator, Database Team</td></tr>
<tr><td class="ctl" data-aixray-field="observed" data-aixray-location="finding:snmp_community:label">Secrets</td><td class="obs" data-aixray-field="observed" data-aixray-location="finding:snmp_community:observed">password=CorrectHorseBatteryStaple!; api_key=sk_live_51M3LongOpaqueValue; Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature; token='QuotedSecretValue9'; credential=&quot;EscapedS3cret&amp;Tail&quot;</td></tr>
<tr><td class="ctl" data-aixray-field="observed" data-aixray-location="finding:vios_level:label">Version and diagnostic syntax</td><td class="obs" data-aixray-field="observed" data-aixray-location="finding:vios_level:observed">{KEEP_FRAGMENT}</td></tr>
<tr><td class="ctl" data-aixray-field="observed" data-aixray-location="finding:fileset_state:label">Product syntax</td><td class="obs" data-aixray-field="observed" data-aixray-location="finding:fileset_state:observed">rootvg :root chacha20-poly1305@openssh.com review@powertruesystems.com bos.rte.install flrtvc.ksh apar.csv</td></tr>
<tr><td class="ctl" data-aixray-field="observed" data-aixray-location="finding:errpt_recent:label">Error-log evidence</td><td class="evidence" data-aixray-field="evidence" data-aixray-location="finding:errpt_recent:evidence">errpt node=node-west-02 ip=10.42.8.17 opaque=abcdefghijklmnop12345678</td></tr>
</tbody></table>
<footer>review@powertruesystems.com</footer>
</body></html>
"""


class ReviewPackTests(unittest.TestCase):
    def setUp(self) -> None:
        if not REVIEW_HELPER.is_file():
            self.fail(f"missing shipped review helper: {REVIEW_HELPER}")

    def run_review(
        self,
        report: Path,
    ) -> tuple[subprocess.CompletedProcess[str], Path | None, Path | None]:
        directory = report.parent
        helper = directory / REVIEW_HELPER.name
        shutil.copy2(REVIEW_HELPER, helper)
        staged = [helper]
        if REVIEW_VALIDATOR.is_file():
            validator = directory / REVIEW_VALIDATOR.name
            shutil.copy2(REVIEW_VALIDATOR, validator)
            staged.append(validator)
        before = set(directory.iterdir())
        try:
            result = subprocess.run(
                ["ksh", str(helper), str(report)],
                cwd=directory,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
        finally:
            for path in staged:
                path.unlink(missing_ok=True)
        created = set(directory.iterdir()) - before
        html = sorted(
            path
            for path in created
            if re.fullmatch(
                r"aixray-review-[0-9a-f]{8}-\d{4}-\d{2}-\d{2}\.html",
                path.name,
            )
        )
        maps = sorted(
            path
            for path in created
            if re.fullmatch(r"aixray-local-key-[0-9a-f]{8}\.map", path.name)
        )
        return (
            result,
            html[0] if len(html) == 1 else None,
            maps[0] if len(maps) == 1 else None,
        )

    def write_profile(self, directory: Path) -> Path:
        report = directory / "aixray-prod-aix01-2026-07-20.html"
        report.write_text(profile_report(), encoding="utf-8")
        return report

    def copy_review_fixture(self, directory: Path, name: str) -> Path:
        source = REVIEW_FIXTURES / name
        report = directory / name
        report.write_bytes(source.read_bytes())
        return report

    def read_failure_manifest(self, directory: Path) -> str:
        """Return the local manifest written when validation refuses to publish.

        stderr carries only the NOT READY TO SHARE banner and a pointer. The
        specific reason a field failed validation is deliberately NOT on stderr
        -- it quotes the offending value, which is the very thing that must not
        leave the machine through a terminal transcript or a CI log. Assertions
        about the reason therefore read the manifest.
        """
        manifests = sorted(
            directory.glob("aixray-local-pseudonymize-failed-*.txt")
        )
        self.assertEqual(1, len(manifests), sorted(directory.iterdir()))
        text = manifests[0].read_text(encoding="utf-8")
        self.assertNotEqual("", text.strip(), "failure manifest is empty")
        return text

    def parse_map(self, map_path: Path) -> dict[str, str]:
        lines = map_path.read_text(encoding="utf-8").splitlines()
        self.assertGreaterEqual(len(lines), 2)
        self.assertEqual(MAP_WARNING, lines[0])
        mappings: dict[str, str] = {}
        for line in lines[1:]:
            if not line or line.startswith("#"):
                continue
            token, separator, value = line.partition("\t")
            self.assertEqual("\t", separator, line)
            self.assertNotIn(token, mappings)
            mappings[token] = value
        return mappings

    def test_full_profile_redacts_identifiers_and_untyped_diagnostics(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="aixray-review-profile-") as temp:
            directory = Path(temp)
            report = self.write_profile(directory)

            result, review_path, map_path = self.run_review(report)

            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual("", result.stdout)
            self.assertIsNotNone(review_path, sorted(directory.iterdir()))
            self.assertIsNotNone(map_path, sorted(directory.iterdir()))
            if review_path is None or map_path is None:
                return
            review = review_path.read_text(encoding="utf-8")
            mappings = self.parse_map(map_path)

            self.assertNotIn("prod-aix01", review)
            self.assertNotIn("node-west-02", review)
            self.assertNotIn("finance-lpar-7", review)
            self.assertEqual("prod-aix01", mappings["host-A"])
            self.assertEqual("node-west-02", mappings["host-B"])
            self.assertEqual("finance-lpar-7", mappings["lpar-1"])

            raw_network = (
                "10.42.8.17",
                "255.255.255.0",
                "2001:db8:12::7",
                "10.42.8.1",
                "aa:bb:cc:dd:ee:ff",
                "12-34-56-78-9a-bc",
                "1234.5678.9abc",
                "db01.corp.example",
                "172.16.4.7",
                "255.255.254.0",
                "172.16.5.1",
            )
            raw_hardware = (
                "78AB12C",
                "02AF91B",
                "0xC050760CBDBB884A",
                "10:00:00:90:fa:53:76:ec",
                "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
            )
            raw_people = ("alice", "ops.user@example.internal")
            mapped_values = set(mappings.values())
            self.assertNotIn("Number:", mapped_values)
            self.assertEqual(
                {
                    "prod-aix01",
                    "node-west-02",
                    "finance-lpar-7",
                    *raw_network,
                    *raw_hardware,
                    *raw_people,
                },
                mapped_values,
            )
            for value in raw_network + raw_hardware + raw_people:
                with self.subTest(redacted=value):
                    self.assertNotIn(value, review)
                    self.assertIn(value, mapped_values)

            self.assertTrue(any(key.startswith("ip-") for key in mappings))
            self.assertTrue(any(key.startswith("mac-") for key in mappings))
            self.assertTrue(any(key.startswith("fqdn-") for key in mappings))
            self.assertTrue(any(key.startswith("serial-") for key in mappings))
            self.assertTrue(any(key.startswith("wwpn-") for key in mappings))
            self.assertTrue(any(key.startswith("user-") for key in mappings))

            reverse_mappings = {value: token for token, value in mappings.items()}
            self.assertNotIn("orphanpeer", reverse_mappings)
            for value in (
                "aa:bb:cc:dd:ee:ff",
                "12-34-56-78-9a-bc",
                "1234.5678.9abc",
            ):
                with self.subTest(mac_token=value):
                    self.assertRegex(reverse_mappings[value], r"^mac-[0-9]+$")
            for value in (
                "0xC050760CBDBB884A",
                "10:00:00:90:fa:53:76:ec",
            ):
                with self.subTest(wwpn_token=value):
                    self.assertRegex(reverse_mappings[value], r"^wwpn-[0-9]+$")

            for removed in (
                "Alice Operator, Database Team",
                "CorrectHorseBatteryStaple!",
                "sk_live_51M3LongOpaqueValue",
                "eyJhbGciOiJIUzI1NiJ9.payload.signature",
                "QuotedSecretValue9",
                "EscapedS3cret&amp;Tail",
                "abcdefghijklmnop12345678",
            ):
                with self.subTest(removed=removed):
                    self.assertNotIn(removed, review)
                    self.assertNotIn(removed, map_path.read_text(encoding="utf-8"))
            manifest = next(
                directory.glob("aixray-local-removals-*.txt")
            ).read_text(encoding="utf-8")
            self.assertIn("kind=secret-in-removed-field", manifest)
            self.assertIn("kind=GECOS-in-removed-field", manifest)
            self.assertIn("[redacted-evidence-line]</td>", review)

            self.assertNotIn(KEEP_FRAGMENT, review)
            self.assertNotIn("VIOS=4.1", review)
            self.assertNotIn("chacha20-poly1305@openssh.com", review)
            self.assertIn("review@powertruesystems.com", review)
            self.assertNotIn("bos.rte.install", review)
            self.assertNotIn("flrtvc.ksh", review)
            self.assertNotIn("apar.csv", review)
            self.assertNotIn("flrtvc.ksh", mapped_values)
            self.assertNotIn("apar.csv", mapped_values)
            self.assertIn("PSEUDONYMIZED REVIEW COPY", review)
            self.assertIn("Automated independent validation passed", review)
            self.assertIn("redacted", review)
            self.assertIn("NOT ANONYMIZED", review)
            self.assertIn("REVIEW REQUIRED", review)
            self.assertIsNone(re.search(r"https?://", review.lower()))

            self.assertEqual(
                0o600,
                stat.S_IMODE(map_path.stat().st_mode),
            )
            self.assertNotIn("prod-aix01", review_path.name)
            self.assertNotIn("prod-aix01", map_path.name)
            review_name = re.fullmatch(
                r"aixray-review-([0-9a-f]{8})-2026-07-20\.html",
                review_path.name,
            )
            map_name = re.fullmatch(
                r"aixray-local-key-([0-9a-f]{8})\.map",
                map_path.name,
            )
            self.assertIsNotNone(review_name, review_path.name)
            self.assertIsNotNone(map_name, map_path.name)
            if review_name is not None and map_name is not None:
                self.assertEqual(review_name.group(1), map_name.group(1))
            self.assertEqual([], list(directory.glob("aixray-review-*.map")))

            summary = result.stderr.splitlines()
            self.assertEqual(5, len(summary), result.stderr)
            self.assertIn("Local removals manifest (DO NOT SEND):", summary[0])
            self.assertIn("Review candidate:", summary[1])
            self.assertIn(review_path.name, summary[1])
            self.assertIn("Local decode key (DO NOT SEND):", summary[2])
            self.assertEqual(
                "REVIEW REQUIRED — inspect the review candidate and local removals manifest.",
                summary[3],
            )
            self.assertEqual(
                "Send only the review candidate after your inspection.",
                summary[4],
            )

    def test_repeated_runs_have_random_names_and_stable_bytes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aixray-review-stable-") as temp:
            directory = Path(temp)
            report = self.write_profile(directory)

            first, first_html, first_map = self.run_review(report)
            second, second_html, second_map = self.run_review(report)

            self.assertEqual(0, first.returncode, first.stderr)
            self.assertEqual(0, second.returncode, second.stderr)
            self.assertIsNotNone(first_html)
            self.assertIsNotNone(first_map)
            self.assertIsNotNone(second_html)
            self.assertIsNotNone(second_map)
            if None in (first_html, first_map, second_html, second_map):
                return
            assert first_html is not None and first_map is not None
            assert second_html is not None and second_map is not None
            self.assertNotEqual(first_html.name, second_html.name)
            self.assertNotEqual(first_map.name, second_map.name)
            self.assertEqual(first_html.read_bytes(), second_html.read_bytes())
            self.assertEqual(first_map.read_bytes(), second_map.read_bytes())

    def test_rich_fixture_has_zero_planted_identifiers_and_real_ids_only(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="aixray-review-rich-") as temp:
            directory = Path(temp)
            report = self.copy_review_fixture(directory, "rich-report.html")

            result, review_path, map_path = self.run_review(report)

            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIsNotNone(review_path, sorted(directory.iterdir()))
            self.assertIsNotNone(map_path, sorted(directory.iterdir()))
            if review_path is None or map_path is None:
                return
            source = report.read_text(encoding="utf-8")
            review = review_path.read_text(encoding="utf-8")
            mappings = self.parse_map(map_path)

            planted = REVIEW_FIXTURES / "planted-identifiers.txt"
            for planted_value in planted.read_text(
                encoding="utf-8",
            ).splitlines():
                with self.subTest(planted_in_source=planted_value):
                    self.assertGreater(source.count(planted_value), 0)
            grep_result = subprocess.run(
                ["grep", "-F", "-f", str(planted), str(review_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(
                1,
                grep_result.returncode,
                f"planted identifier grep was not zero-hit:\n{grep_result.stdout}",
            )
            self.assertEqual("", grep_result.stdout)

            keep_values = (
                REVIEW_FIXTURES / "keep-values.txt"
            ).read_text(encoding="utf-8").splitlines()
            for value in keep_values:
                with self.subTest(keep=value):
                    self.assertGreater(source.count(value), 0)
                    if value == "4.5.6 PASS":
                        self.assertEqual(
                            source.count(value),
                            review.count(value),
                        )
                    else:
                        self.assertEqual(0, review.count(value))

            reverse_mappings = {value: token for token, value in mappings.items()}
            for value in (
                "admin01",
                "nimmaster01",
                "db2node02",
                "webapp03",
                "db-ha-04",
            ):
                with self.subTest(host_list_token=value):
                    self.assertRegex(reverse_mappings[value], r"^host-[A-Z0-9]+$")
            self.assertRegex(reverse_mappings["/oracle/PRODCU"], r"^path-[0-9]+$")
            self.assertRegex(
                reverse_mappings["/nfs/appdata"],
                r"^path-[0-9]+$",
            )
            self.assertRegex(
                reverse_mappings["U9009.22A.78AB12C-P1-C4-T1"],
                r"^serial-[0-9]+$",
            )
            self.assertIn("path-1", review)
            self.assertIn("[redacted-evidence-line]", review)

    def test_independent_validation_rejects_unresolved_bareword(self) -> None:
        for fixture in (
            "unresolved-bareword.html",
            "unresolved-hyphenated.html",
            "unresolved-host-list.html",
            "unresolved-colon-list.html",
        ):
            with self.subTest(fixture=fixture), tempfile.TemporaryDirectory(
                prefix="aixray-review-validate-",
            ) as temp:
                directory = Path(temp)
                report = self.copy_review_fixture(directory, fixture)

                result, review_path, map_path = self.run_review(report)

                self.assertNotEqual(0, result.returncode)
                self.assertEqual("", result.stdout)
                self.assertIsNone(review_path, sorted(directory.iterdir()))
                self.assertIsNone(map_path, sorted(directory.iterdir()))
                self.assertIn("NOT READY TO SHARE", result.stderr)
                self.assertIn(
                    "identity field is not an issued pseudotoken",
                    self.read_failure_manifest(directory),
                )

    def test_independent_validation_rejects_unissued_pseudotoken_shape(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="aixray-review-token-shape-") as temp:
            directory = Path(temp)
            report = self.copy_review_fixture(
                directory,
                "unissued-pseudotoken.html",
            )

            result, review_path, map_path = self.run_review(report)

            self.assertNotEqual(0, result.returncode)
            self.assertEqual("", result.stdout)
            self.assertIsNone(review_path, sorted(directory.iterdir()))
            self.assertIsNone(map_path, sorted(directory.iterdir()))
            self.assertIn("NOT READY TO SHARE", result.stderr)
            self.assertIn(
                "unissued pseudotoken",
                self.read_failure_manifest(directory),
            )

    def test_independent_validation_rejects_identifiers_in_markup(self) -> None:
        for fixture in (
            "unresolved-attribute-ip.html",
            "unresolved-comment-ip.html",
        ):
            with self.subTest(fixture=fixture), tempfile.TemporaryDirectory(
                prefix="aixray-review-markup-",
            ) as temp:
                directory = Path(temp)
                report = self.copy_review_fixture(directory, fixture)

                result, review_path, map_path = self.run_review(report)

                self.assertNotEqual(0, result.returncode)
                self.assertEqual("", result.stdout)
                self.assertIsNone(review_path, sorted(directory.iterdir()))
                self.assertIsNone(map_path, sorted(directory.iterdir()))
                self.assertIn("NOT READY TO SHARE", result.stderr)
                failure = self.read_failure_manifest(directory)
                self.assertTrue(
                    "IPv4-shaped identifier remains" in failure
                    or "remote-resource attribute is not canonical" in failure,
                    failure,
                )

    def test_independent_validation_rejects_fqdn_with_suffix(self) -> None:
        for fixture in (
            "unresolved-attribute-fqdn-path.html",
            "unresolved-visible-fqdn-path.html",
            "unresolved-visible-fqdn-colon-path.html",
        ):
            with self.subTest(fixture=fixture), tempfile.TemporaryDirectory(
                prefix="aixray-review-fqdn-suffix-",
            ) as temp:
                directory = Path(temp)
                report = self.copy_review_fixture(directory, fixture)

                result, review_path, map_path = self.run_review(report)

                self.assertNotEqual(0, result.returncode)
                self.assertEqual("", result.stdout)
                self.assertIsNone(review_path, sorted(directory.iterdir()))
                self.assertIsNone(map_path, sorted(directory.iterdir()))
                self.assertIn("NOT READY TO SHARE", result.stderr)
                # An FQDN in an href is caught as a non-canonical remote
                # resource; one in a visible assessment cell is caught as an
                # unresolved identity. Both are the refusal this test is for --
                # which one fires depends on where the fixture plants it.
                failure = self.read_failure_manifest(directory)
                self.assertTrue(
                    "identity field is not an issued pseudotoken" in failure
                    or "remote-resource attribute is not canonical" in failure,
                    failure,
                )

    def test_independent_validation_rejects_issued_pseudotoken_collision(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="aixray-review-token-collision-") as temp:
            directory = Path(temp)
            report = self.copy_review_fixture(
                directory,
                "issued-pseudotoken.html",
            )

            result, review_path, map_path = self.run_review(report)

            self.assertNotEqual(0, result.returncode)
            self.assertEqual("", result.stdout)
            self.assertIsNone(review_path, sorted(directory.iterdir()))
            self.assertIsNone(map_path, sorted(directory.iterdir()))
            self.assertIn("NOT READY TO SHARE", result.stderr)
            self.assertIn(
                "unissued pseudotoken",
                self.read_failure_manifest(directory),
            )

    def test_unmarked_or_duplicate_marker_input_fails_without_artifacts(self) -> None:
        cases = {
            "unmarked": "<!doctype html><html><body>not a report</body></html>\n",
            "duplicate": profile_report().replace(
                '<meta name="aixray-report-version" content="1">',
                '<meta name="aixray-report-version" content="1">\n'
                '<meta name="aixray-report-version" content="1">',
            ),
        }
        for name, content in cases.items():
            with self.subTest(case=name), tempfile.TemporaryDirectory(
                prefix=f"aixray-review-{name}-"
            ) as temp:
                directory = Path(temp)
                report = directory / f"{name}.html"
                report.write_text(content, encoding="utf-8")

                result, review_path, map_path = self.run_review(report)

                self.assertNotEqual(0, result.returncode)
                self.assertEqual("", result.stdout)
                self.assertIsNone(review_path)
                self.assertIsNone(map_path)
                # The helper now names the count it requires rather than just
                # the marker, because zero and two are different operator
                # mistakes with the same fix. Repointed at the current wording;
                # both cases below (absent marker, duplicated marker) must still
                # be rejected before any artifact is written.
                self.assertIn(
                    "expected PTxray report version 1 exactly once",
                    result.stderr,
                )
                self.assertEqual([report], sorted(directory.iterdir()))

    @unittest.skipUnless(
        os.environ.get("AIXRAY_FIXTURE_ROOT"),
        "set AIXRAY_FIXTURE_ROOT to run scanner fixture test",
    )
    def test_current_scanner_fixture_is_redacted_under_real_ksh(self) -> None:
        assert FIXTURE is not None
        self.assertTrue(FIXTURE.is_dir(), f"fixture is missing: {FIXTURE}")
        with tempfile.TemporaryDirectory(prefix="aixray-review-rendered-") as temp:
            directory = Path(temp)
            env = os.environ.copy()
            env["AIXRAY_FIXTURES"] = f"{FIXTURE}/"
            env["AIXRAY_TODAY"] = FROZEN
            rendered = subprocess.run(
                ["ksh", str(SCANNER), "--html"],
                cwd=directory,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(0, rendered.returncode, rendered.stderr)
            report = directory / "aixray-lab-host-01-2026-07-01.html"
            report.write_text(rendered.stdout, encoding="utf-8")

            result, review_path, map_path = self.run_review(report)

            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIsNotNone(review_path)
            self.assertIsNotNone(map_path)
            if review_path is None or map_path is None:
                return
            source = report.read_text(encoding="utf-8")
            review = review_path.read_text(encoding="utf-8")
            self.assertIn("lab-host-01", source)
            self.assertNotIn("lab-host-01", review)
            self.assertIn("host-A", review)
            for keep in (
                "7300-04-00-2546",
                FROZEN,
                "VL950_168",
                "NOT_ASSESSED",
                "mksysb_age",
                "FAIL",
                "WARN",
                "PASS",
                "65%",
                "57",
            ):
                with self.subTest(keep=keep):
                    self.assertIn(keep, source)
                    self.assertEqual(source.count(keep), review.count(keep))
            # Strict top-risk evidence removal can remove incidental copies of
            # these short digit substrings. Exact diagnostic KEEP preservation
            # is covered by KEEP_FRAGMENT and the rich fixture above.
            for short_keep in ("21", "9"):
                with self.subTest(short_keep=short_keep):
                    self.assertIn(short_keep, source)
                    self.assertIn(short_keep, review)
            self.assertIn(":root", review)
            self.assertIn("rootvg", review)
            self.assertIn("review@powertruesystems.com", review)


if __name__ == "__main__":
    unittest.main(verbosity=2)
