#!/usr/bin/env python3
"""Offline contract tests for the public AIXray customer funnel."""

from __future__ import annotations

import hashlib
from html.parser import HTMLParser
import http.server
import json
import os
from pathlib import Path
import re
import socketserver
import stat
import subprocess
import tempfile
import threading
import unittest
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "site"
SCANNER = ROOT / "aixray-aix.sh"
FIXTURE_ROOT = os.environ.get("AIXRAY_FIXTURE_ROOT")
FIXTURE = Path(FIXTURE_ROOT) if FIXTURE_ROOT else None
EGRESS_LINTER = ROOT / "tools" / "ci" / "egress-lint.sh"
DOWNLOAD_PAGE_URL = "https://powertruesystems.com/aixray/"
DIRECT_ASSET_URL = "https://powertruesystems.com/aixray/aixray-aix.sh"
READY_PAGE_URL = "https://powertruesystems.com/aixray/ready/"
ROLE_VALUES = ("sysadmin", "it_manager", "director_plus", "other")
REVIEW_CTA = (
    "Free engineer review: email your report to "
    "review@powertruesystems.com — a principal engineer replies within "
    "2 business days."
)
PROGRESS = (
    "[1/9] lifecycle and support…",
    "[2/9] patch and vulnerability currency…",
    "[3/9] storage and capacity…",
    "[4/9] performance and sizing…",
    "[5/9] errors and diagnostics…",
    "[6/9] availability and recovery…",
    "[7/9] security and hardening…",
    "[8/9] configuration hygiene…",
    "[9/9] monitoring and operations…",
)
CUSTOMER_FILES = (
    ROOT / "README.md",
    SITE / "index.html",
    ROOT / "aixray.jsonld",
    ROOT / "llms.txt",
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_scanner(*args: str, cwd: Path = ROOT) -> subprocess.CompletedProcess[str]:
    if FIXTURE is None:
        raise RuntimeError("set AIXRAY_FIXTURE_ROOT to run fixture tests")
    env = os.environ.copy()
    env["AIXRAY_FIXTURES"] = f"{FIXTURE}/"
    env["AIXRAY_TODAY"] = "2026-07-01"
    return subprocess.run(
        ["ksh", str(SCANNER), *args],
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )


def inline_jsonld(site_html: str) -> dict[str, object]:
    match = re.search(
        r'<script\s+type="application/ld\+json">(.*?)</script>',
        site_html,
        flags=re.DOTALL,
    )
    if match is None:
        raise AssertionError("site has no inline JSON-LD block")
    return json.loads(match.group(1))


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        pass


class ReportParser(HTMLParser):
    """Collect the post-gate link, top-risk fields, and footer links."""

    def __init__(self) -> None:
        super().__init__()
        self.download_links: list[dict[str, object]] = []
        self.footer_links: list[dict[str, str]] = []
        self.top_risks: list[dict[str, object]] = []
        self.section_text: list[str] = []
        self._ready_depth = 0
        self._footer_depth = 0
        self._footer_link: dict[str, str] | None = None
        self._section_depth = 0
        self._risk: dict[str, object] | None = None
        self._field: str | None = None
        self._field_depth = 0

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        attributes = dict(attrs)
        classes = tuple((attributes.get("class") or "").split())
        if self._ready_depth:
            self._ready_depth += 1
            if tag == "a":
                self.download_links.append(
                    {
                        "href": attributes.get("href"),
                        "download": any(name == "download" for name, _ in attrs),
                    }
                )
        elif attributes.get("id") == "download-ready":
            self._ready_depth = 1

        if self._footer_depth:
            self._footer_depth += 1
            if tag == "a" and attributes.get("href") is not None:
                self._footer_link = {
                    "href": attributes["href"] or "",
                    "text": "",
                }
                self.footer_links.append(self._footer_link)
        elif tag == "footer":
            self._footer_depth = 1

        if self._section_depth:
            self._section_depth += 1
        elif tag == "section" and attributes.get("id") == "start-here":
            self._section_depth = 1

        if not self._section_depth:
            return
        if self._field is not None:
            self._field_depth += 1
            return
        if tag == "li" and "top-risk" in classes:
            statuses = tuple(item for item in classes if item in ("FAIL", "WARN"))
            self._risk = {
                "statuses": statuses,
                "severity": attributes.get("data-severity"),
                "label": "",
                "rank": "",
                "observed": "",
                "fix": "",
            }
            return
        if self._risk is None:
            return
        for field, class_name in (
            ("label", "top-risk-label"),
            ("rank", "top-risk-rank"),
            ("observed", "top-risk-observed"),
            ("fix", "top-risk-fix"),
        ):
            if class_name in classes:
                self._field = field
                self._field_depth = 1
                break

    def handle_endtag(self, tag: str) -> None:
        if self._field is not None:
            self._field_depth -= 1
            if self._field_depth == 0:
                self._field = None
        elif tag == "li" and self._risk is not None:
            self.top_risks.append(self._risk)
            self._risk = None
        if tag == "a" and self._footer_link is not None:
            self._footer_link = None
        if self._ready_depth:
            self._ready_depth -= 1
        if self._footer_depth:
            self._footer_depth -= 1
        if self._section_depth:
            self._section_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._section_depth:
            self.section_text.append(data)
        if self._risk is not None and self._field is not None:
            self._risk[self._field] = str(self._risk[self._field]) + data
        if self._footer_link is not None:
            self._footer_link["text"] += data


class PublicFunnelTests(unittest.TestCase):
    def test_download_gate_is_native_first_and_ajax_enhanced(self) -> None:
        site_html = (SITE / "index.html").read_text(encoding="utf-8")
        form_match = re.search(
            r'<form\b(?=[^>]*\bid="download-form")([^>]*)>(.*?)</form>',
            site_html,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(form_match, "download form is missing")
        if form_match is None:
            return
        form_open, form_body = form_match.groups()
        self.assertRegex(
            form_open,
            r'\baction="https://formsubmit\.co/hello@powertruesystems\.com"',
        )
        self.assertRegex(form_open, r'\bmethod="POST"')
        self.assertRegex(
            form_body,
            rf'<input\b(?=[^>]*\bname="_next")(?=[^>]*\bvalue="{re.escape(READY_PAGE_URL)}")[^>]*>',
        )

        def named_tag(tag: str, name: str) -> str:
            match = re.search(
                rf'<{tag}\b(?=[^>]*\bname="{re.escape(name)}")[^>]*>',
                form_body,
            )
            self.assertIsNotNone(match, f"missing {name} field")
            return match.group(0) if match else ""

        self.assertRegex(named_tag("input", "name"), r"\brequired\b")
        self.assertRegex(named_tag("input", "email"), r"\brequired\b")
        self.assertNotRegex(named_tag("select", "role"), r"\brequired\b")
        for value in ROLE_VALUES:
            self.assertRegex(form_body, rf'<option\s+value="{value}"')
        self.assertNotIn("this page reveals", site_html)

        self.assertRegex(
            site_html,
            r'<script\s+src="download-form\.js"\s+defer></script>',
        )
        enhancement = (SITE / "download-form.js").read_text(encoding="utf-8")
        self.assertIn("fetch(ajaxAction", enhancement)
        self.assertIn("form.submit();", enhancement)
        self.assertIn("AbortController", enhancement)
        self.assertIn("Promise.race", enhancement)
        self.assertIn("window.setTimeout", enhancement)
        self.assertIn("window.clearTimeout", enhancement)
        external_urls = re.findall(r'https://[^"\']+', enhancement)
        self.assertEqual(
            ["https://formsubmit.co/", "https://formsubmit.co/ajax/"],
            external_urls,
        )

        ready_html = (SITE / "ready" / "index.html").read_text(encoding="utf-8")
        self.assertIn('href="../aixray-aix.sh"', ready_html)
        self.assertRegex(ready_html, r'<a\b[^>]*\bdownload(?:\s|>|=)')

    def test_advertised_download_references_use_the_gated_page(self) -> None:
        for path in CUSTOMER_FILES:
            text = path.read_text(encoding="utf-8")
            with self.subTest(path=path.name, contract="no dead release URL"):
                self.assertNotIn("releases/latest/download", text)
            with self.subTest(path=path.name, contract="no undeployed direct asset URL"):
                self.assertNotIn(DIRECT_ASSET_URL, text)

        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        llms = (ROOT / "llms.txt").read_text(encoding="utf-8")
        site_html = (SITE / "index.html").read_text(encoding="utf-8")
        root_jsonld = json.loads((ROOT / "aixray.jsonld").read_text())
        site_jsonld = inline_jsonld(site_html)

        self.assertIn(DOWNLOAD_PAGE_URL, readme)
        self.assertIn(DOWNLOAD_PAGE_URL, llms)
        self.assertEqual(DOWNLOAD_PAGE_URL, root_jsonld.get("downloadUrl"))
        self.assertEqual(DOWNLOAD_PAGE_URL, site_jsonld.get("downloadUrl"))
        parser = ReportParser()
        parser.feed(site_html)
        download_actions = [link for link in parser.download_links if link["download"]]
        self.assertEqual(
            [{"href": "aixray-aix.sh", "download": True}],
            download_actions,
        )

    def test_site_serves_the_scanner_directly_over_local_http(self) -> None:
        site_scanner = SITE / "aixray-aix.sh"
        self.assertTrue(site_scanner.is_file(), "site scanner payload is missing")
        if not site_scanner.is_file():
            return
        self.assertEqual(SCANNER.read_bytes(), site_scanner.read_bytes())

        handler = lambda *args, **kwargs: QuietHandler(  # noqa: E731
            *args, directory=str(SITE), **kwargs
        )
        with socketserver.TCPServer(("127.0.0.1", 0), handler) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                port = server.server_address[1]
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/aixray-aix.sh", timeout=5
                ) as response:
                    self.assertEqual(200, response.status)
                    self.assertEqual(site_scanner.read_bytes(), response.read())
            finally:
                server.shutdown()
                thread.join(timeout=5)

    def test_catalog_covers_every_public_artifact_and_scanner(self) -> None:
        catalog = json.loads((ROOT / "catalog.json").read_text())
        checks = catalog.get("checks", [])
        check_dirs = sorted((ROOT / "checks").glob("ck-*"))
        manifests = sorted((ROOT / "checks").glob("ck-*/manifest.json"))
        with self.subTest(contract="current check count"):
            self.assertEqual(35, catalog.get("check_count"))
        with self.subTest(contract="catalog list count"):
            self.assertEqual(35, len(checks))
        with self.subTest(contract="public directory count"):
            self.assertEqual(35, len(check_dirs))
        with self.subTest(contract="manifest count"):
            self.assertEqual(35, len(manifests))

        for entry in checks:
            check_id = entry["id"]
            artifact = ROOT / entry["artifact"]
            manifest = ROOT / "checks" / check_id / "manifest.json"
            with self.subTest(check=check_id, file="artifact"):
                self.assertTrue(artifact.is_file())
                if artifact.is_file():
                    self.assertEqual(entry["sha256"], sha256(artifact))
            with self.subTest(check=check_id, file="manifest"):
                self.assertTrue(manifest.is_file())

        catalog_ids = [entry.get("id") for entry in checks]
        directory_ids = [path.name for path in check_dirs]
        artifact_paths = [entry.get("artifact") for entry in checks]
        self.assertEqual(len(catalog_ids), len(set(catalog_ids)))
        self.assertEqual(len(artifact_paths), len(set(artifact_paths)))
        self.assertEqual(set(directory_ids), set(catalog_ids))
        self.assertEqual(
            {f"checks/{check_id}/{check_id}.ksh" for check_id in directory_ids},
            set(artifact_paths),
        )
        for manifest in manifests:
            manifest_data = json.loads(manifest.read_text())
            self.assertEqual(manifest.parent.name, manifest_data.get("id"))
            entry = next(
                (item for item in checks if item.get("id") == manifest.parent.name),
                None,
            )
            self.assertIsNotNone(entry)
            if entry is not None:
                for key, value in manifest_data.items():
                    with self.subTest(check=manifest.parent.name, metadata=key):
                        self.assertEqual(value, entry.get(key))

        assembled = catalog.get("assembled_scanner")
        self.assertIsInstance(assembled, dict)
        if not isinstance(assembled, dict):
            return
        self.assertEqual("aixray-aix.sh", assembled.get("artifact"))
        self.assertEqual("site/aixray-aix.sh", assembled.get("site_artifact"))
        expected = sha256(SCANNER)
        self.assertEqual(expected, assembled.get("sha256"))
        self.assertEqual(expected, sha256(SITE / "aixray-aix.sh"))

    def test_customer_copy_describes_the_current_35_checks(self) -> None:
        for path in (ROOT / "README.md", SITE / "index.html", ROOT / "llms.txt"):
            text = path.read_text(encoding="utf-8")
            with self.subTest(path=path.name, contract="no stale count"):
                self.assertNotRegex(text, r"\b31 standalone\b")
            with self.subTest(path=path.name, contract="current count"):
                self.assertRegex(text, r"\b35\b")

    def test_readme_leads_a_new_customer_through_the_easy_run(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        lower = readme.lower()
        self.assertRegex(readme, r"(?m)^## Prerequisites[ \t]*$")
        prerequisites_match = re.search(
            r"(?ms)^## Prerequisites[ \t]*$\n(.*?)(?=^## )", readme
        )
        self.assertIsNotNone(prerequisites_match)
        prerequisites = prerequisites_match.group(1) if prerequisites_match else ""
        prerequisites_lower = prerequisites.lower()
        self.assertRegex(
            prerequisites, r"AIX\s+7\.2\s*/\s*7\.3|AIX\s+7\.2.*7\.3"
        )
        self.assertIn("VIOS", prerequisites)
        self.assertIn("/bin/sh", prerequisites)
        self.assertRegex(prerequisites_lower, r"standard aix userland")
        self.assertRegex(prerequisites_lower, r"root (is )?recommended")
        self.assertRegex(prerequisites_lower, r"unprivileged|without root|non-root")
        self.assertRegex(prerequisites, r"NOT_ASSESSED|unavailable")
        self.assertRegex(prerequisites_lower, r"several minutes")
        self.assertRegex(prerequisites_lower, r"runtime varies|varies by")
        self.assertRegex(prerequisites_lower, r"system size")
        self.assertRegex(prerequisites_lower, r"flrtvc")
        self.assertRegex(prerequisites_lower, r"nothing (is )?installed|installs nothing")
        self.assertRegex(readme, r"(?m)^## Verify what you run\s*$")

        bare = re.search(r"(?m)^\./aixray-aix\.sh\s*$", readme)
        html_mode = re.search(r"(?m)^\./aixray-aix\.sh --html\b", readme)
        json_mode = re.search(r"(?m)^\./aixray-aix\.sh --json\b", readme)
        self.assertIsNotNone(bare, "quickstart has no bare easy run")
        self.assertIsNotNone(html_mode, "advanced HTML stdout mode is missing")
        self.assertIsNotNone(json_mode, "advanced JSON stdout mode is missing")
        if bare is not None and html_mode is not None:
            self.assertLess(bare.start(), html_mode.start())
        self.assertIn("Report ready:", readme)
        self.assertRegex(readme, r"aixray-<hostname>-<date>\.html")

        scanner_hash = sha256(SCANNER)
        self.assertIn(scanner_hash, readme)

    def test_scanner_audit_map_names_only_public_paths(self) -> None:
        header = "\n".join(SCANNER.read_text(encoding="utf-8").splitlines()[:30])
        audit = re.search(
            r"# Audit map \(repository paths\):\n((?:#   .*\n){3})",
            header + "\n",
        )
        self.assertIsNotNone(audit, "three-line audit map is missing")
        if audit is None:
            return
        paths = tuple(
            line.removeprefix("#   ").split(" — ", 1)[0]
            for line in audit.group(1).splitlines()
        )
        self.assertEqual(
            ("checks/", "catalog.json", "README.md#verify-what-you-run"),
            paths,
        )
        self.assertTrue((ROOT / "checks").is_dir())
        self.assertTrue((ROOT / "catalog.json").is_file())
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertRegex(readme, r"(?m)^## Verify what you run\s*$")
        for dev_only in (
            "docs/HOW-TO-AUDIT.md",
            "docs/ASSEMBLE.md",
            "tools.d/checks",
        ):
            self.assertNotIn(dev_only, header)

    @unittest.skipUnless(
        os.environ.get("AIXRAY_FIXTURE_ROOT"),
        "set AIXRAY_FIXTURE_ROOT to run fixture tests",
    )
    def test_bare_run_completes_the_newcomer_drill(self) -> None:
        assert FIXTURE is not None
        self.assertTrue(FIXTURE.is_dir(), f"fixture is missing: {FIXTURE}")
        with tempfile.TemporaryDirectory(prefix="aixray-public-newcomer-") as temp:
            cwd = Path(temp)
            result = run_scanner(cwd=cwd)
            reports = sorted(cwd.glob("aixray-*-2026-07-01.html"))
            self.assertEqual(0, result.returncode, result.stderr)
            with self.subTest(contract="quiet stdout"):
                self.assertEqual("", result.stdout)
            with self.subTest(contract="one report"):
                self.assertEqual(1, len(reports))
            lines = result.stderr.splitlines()
            progress = tuple(line for line in lines if re.match(r"^\[[^]]+\]", line))
            with self.subTest(contract="ordered progress"):
                self.assertEqual(PROGRESS, progress)
            with self.subTest(contract="completion"):
                completions = [line for line in lines if line.startswith("Report ready:")]
                self.assertEqual(1, len(completions))
            with self.subTest(contract="review CTA"):
                self.assertEqual(1, lines.count(REVIEW_CTA))
            if len(reports) != 1:
                return
            report = reports[0]
            self.assertRegex(
                report.name, r"^aixray-[A-Za-z0-9._-]+-2026-07-01\.html$"
            )
            self.assertEqual(0o600, stat.S_IMODE(report.stat().st_mode))
            expected_completion = (
                f"Report ready: ./{report.name} — open it in your browser. "
                "To save a PDF: Print -> Save as PDF."
            )
            self.assertIn(expected_completion, lines)
            document = report.read_text(encoding="utf-8")
            self.assertTrue(document.rstrip().endswith("</html>"))
            self.assertIn('id="start-here"', document)
            score_at = document.find('class="score"')
            start_at = document.find('id="start-here"')
            self.assertGreaterEqual(score_at, 0)
            self.assertGreater(start_at, score_at)
            category_at = document.find('class="cathead"')
            self.assertGreater(category_at, start_at)
            footer = re.search(r"<footer>.*?</footer>", document, flags=re.DOTALL)
            self.assertIsNotNone(footer)
            if footer is not None:
                self.assertIn(REVIEW_CTA, footer.group(0))
            parser = ReportParser()
            parser.feed(document)
            linked_ctas = [
                {
                    "href": link["href"],
                    "text": " ".join(link["text"].split()),
                }
                for link in parser.footer_links
            ]
            self.assertIn(
                {
                    "href": "mailto:review@powertruesystems.com",
                    "text": REVIEW_CTA,
                },
                linked_ctas,
            )

            structured = run_scanner("--json")
            self.assertEqual(0, structured.returncode, structured.stderr)
            findings = json.loads(structured.stdout)["findings"]
            expected = [
                finding
                for status in ("FAIL", "WARN")
                for severity in ("high", "med", "low")
                for finding in findings
                if finding["status"] == status and finding["severity"] == severity
            ][:5]
            self.assertGreaterEqual(len(parser.top_risks), 1)
            self.assertLessEqual(len(parser.top_risks), 5)
            self.assertEqual(len(expected), len(parser.top_risks))
            for rendered, source in zip(parser.top_risks, expected):
                self.assertEqual((source["status"],), rendered["statuses"])
                self.assertEqual(source["severity"], rendered["severity"])
                self.assertEqual(source["label"], str(rendered["label"]).strip())
                self.assertEqual(
                    f"{source['status']} · {source['severity']}",
                    str(rendered["rank"]).strip(),
                )
                self.assertEqual(
                    f"Observed: {source['observed']}",
                    " ".join(str(rendered["observed"]).split()),
                )
                self.assertEqual(
                    f"Fix: {source['fix']}",
                    " ".join(str(rendered["fix"]).split()),
                )

    @unittest.skipUnless(
        os.environ.get("AIXRAY_FIXTURE_ROOT"),
        "set AIXRAY_FIXTURE_ROOT to run fixture tests",
    )
    def test_start_here_renders_honest_zero_actionable_guidance(self) -> None:
        assert FIXTURE is not None
        source = SCANNER.read_text(encoding="utf-8")
        needle = '\nSTART_HERE_ITEMS=""\n'
        self.assertEqual(1, source.count(needle))
        if source.count(needle) != 1:
            return
        force_no_actionable = """
i=0
while [ "$i" -lt "$NFIND" ]; do
  F_ST[$i]=NOT_ASSESSED
  i=$((i+1))
done
START_HERE_ITEMS=""
"""
        instrumented = source.replace(needle, f"\n{force_no_actionable}", 1)
        with tempfile.TemporaryDirectory(prefix="aixray-public-no-action-") as temp:
            temp_root = Path(temp)
            scanner = temp_root / "aixray-aix.sh"
            scanner.write_text(instrumented, encoding="utf-8")
            env = os.environ.copy()
            env["AIXRAY_FIXTURES"] = f"{FIXTURE}/"
            env["AIXRAY_TODAY"] = "2026-07-01"
            result = subprocess.run(
                ["ksh", str(scanner), "--html"],
                cwd=temp_root,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
        self.assertEqual(0, result.returncode, result.stderr)
        parser = ReportParser()
        parser.feed(result.stdout)
        self.assertEqual([], parser.top_risks)
        guidance = " ".join("".join(parser.section_text).split())
        self.assertIn("No actionable FAIL or WARN finding", guidance)
        self.assertIn("NOT_ASSESSED", guidance)

    @unittest.skipUnless(
        os.environ.get("AIXRAY_FIXTURE_ROOT"),
        "set AIXRAY_FIXTURE_ROOT to run fixture tests",
    )
    def test_explicit_html_remains_a_stdout_mode(self) -> None:
        result = run_scanner("--html")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertTrue(result.stdout.startswith("<!doctype html>"))
        self.assertTrue(result.stdout.rstrip().endswith("</html>"))

    def test_public_shell_and_metadata_syntax(self) -> None:
        for shell in ("sh", "ksh"):
            result = subprocess.run(
                [shell, "-n", str(SCANNER)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            with self.subTest(shell=shell):
                self.assertEqual(0, result.returncode, result.stderr)
        json.loads((ROOT / "catalog.json").read_text())
        json.loads((ROOT / "aixray.jsonld").read_text())
        inline_jsonld((SITE / "index.html").read_text(encoding="utf-8"))

    def test_scanner_has_no_egress_command_primitive(self) -> None:
        self.assertTrue(EGRESS_LINTER.is_file(), f"missing linter: {EGRESS_LINTER}")

        def lint(path: Path) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                ["sh", str(EGRESS_LINTER), str(path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )

        clean = lint(SCANNER)
        self.assertEqual(0, clean.returncode, clean.stdout + clean.stderr)
        probes = (
            'x="$(curl https://example.invalid)"',
            "command curl https://example.invalid",
            "env curl https://example.invalid",
            "/usr/bin/curl https://example.invalid",
            "host example.invalid",
            "command nslookup example.invalid",
            "tftp example.invalid",
            "sftp example.invalid",
            "rcp local-file example.invalid:/tmp/remote-file",
            "rsh example.invalid true",
            "rexec example.invalid true",
            "socat TCP:example.invalid:443 -",
            "ping example.invalid",
            "traceroute example.invalid",
            "sendmail recipient@example.invalid",
            "exec 3<>/dev/tcp/example.invalid/443",
            "exec 4<>/dev/udp/example.invalid/53",
        )
        source = SCANNER.read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory(prefix="aixray-public-egress-") as temp:
            temp_root = Path(temp)
            for index, probe in enumerate(probes):
                candidate = temp_root / f"probe-{index}.sh"
                candidate.write_text(f"{source}\n{probe}\n", encoding="utf-8")
                result = lint(candidate)
                with self.subTest(probe=probe):
                    self.assertEqual(1, result.returncode, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
