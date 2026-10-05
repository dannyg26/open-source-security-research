from __future__ import annotations

import unittest
from datetime import datetime, timezone
from pathlib import Path

import target_shortlist
import triage


class ShortlistTests(unittest.TestCase):
    def test_score_is_bounded_and_sorted(self) -> None:
        candidates = [
            {
                "repository": "example/one", "stars": 1000, "forks": 20,
                "pushed_at": "2026-08-01T00:00:00Z", "has_security_policy": False,
                "osv": {"status": "unknown", "advisories": None}, "open_issues": 2,
                "license": None, "description": "one",
            },
            {
                "repository": "example/two", "stars": 5000, "forks": 500,
                "pushed_at": "2026-09-01T00:00:00Z", "has_security_policy": True,
                "osv": {"status": "known", "advisories": 1}, "open_issues": 20,
                "license": "MIT", "description": "two",
            },
        ]
        target_shortlist.score_candidates(
            candidates, datetime(2026, 9, 3, tzinfo=timezone.utc)
        )
        self.assertEqual(candidates[0]["repository"], "example/two")
        self.assertTrue(all(0 <= candidate["score"] <= 100 for candidate in candidates))

    def test_unknown_osv_is_not_zero(self) -> None:
        result = target_shortlist.osv_history(None, None)
        self.assertEqual(result["status"], "unknown")
        self.assertIsNone(result["cves"])

    def test_osv_cves_are_deduplicated_across_pages(self) -> None:
        class FakeClient:
            calls = 0

            def request(self, _url, *, payload=None):
                self.calls += 1
                if self.calls == 1:
                    return {
                        "vulns": [{"id": "GHSA-one", "aliases": ["CVE-2026-0001"]}],
                        "next_page_token": "next",
                    }
                self.assert_page_token(payload)
                return {
                    "vulns": [{"id": "CVE-2026-0001", "aliases": ["GHSA-one"]}]
                }

            @staticmethod
            def assert_page_token(payload):
                if payload.get("page_token") != "next":
                    raise AssertionError("pagination token was not forwarded")

        package = target_shortlist.PackageIdentity("PyPI", "demo", "pyproject.toml")
        result = target_shortlist.osv_history(FakeClient(), package)
        self.assertEqual(result["advisories"], 2)
        self.assertEqual(result["cves"], 1)

    def test_package_and_repository_history_are_combined(self) -> None:
        osv = {
            "status": "known", "advisories": 1, "cves": 1,
            "ids": ["GHSA-one"], "cve_ids": ["CVE-2026-0001"],
        }
        github = {
            "status": "known", "advisories": 2, "cves": 2,
            "ids": ["GHSA-one", "GHSA-two"],
            "cve_ids": ["CVE-2026-0001", "CVE-2026-0002"],
        }
        combined = target_shortlist.combine_history(osv, github)
        self.assertEqual(combined["advisories"], 2)
        self.assertEqual(combined["cves"], 2)


class TriageTests(unittest.TestCase):
    def test_tool_lookup_checks_virtualenv_scripts_directory(self) -> None:
        self.assertTrue(triage.find_tool("python"))

    def test_categories(self) -> None:
        self.assertEqual(triage.classify("possible SQL injection", "semgrep"), "injection")
        self.assertEqual(triage.classify("server-side request forgery", "semgrep"), "SSRF")
        self.assertEqual(triage.classify("anything", "gitleaks"), "secrets")

    def test_secret_material_is_redacted(self) -> None:
        data = {"Raw": "live-value", "nested": {"token": "abc", "safe": "ok"}}
        clean = triage.sanitize(data)
        self.assertEqual(clean["Raw"], "[REDACTED]")
        self.assertEqual(clean["nested"]["token"], "[REDACTED]")
        self.assertEqual(clean["nested"]["safe"], "ok")

    def test_osv_is_labeled_dependency(self) -> None:
        data = {
            "results": [{
                "source": {"path": "package-lock.json"},
                "packages": [{
                    "package": {"name": "demo", "version": "1.0"},
                    "vulnerabilities": [{"id": "GHSA-test"}],
                }],
            }]
        }
        finding = triage.osv_findings(data, Path.cwd())[0]
        self.assertEqual(finding.tool, "OSV-Scanner (dependency)")
        self.assertIn("separately", finding.summary)


from verify.safety import assert_local_url


class HarnessSafetyTests(unittest.TestCase):
    def test_loopback_is_allowed(self) -> None:
        assert_local_url("http://127.0.0.1:8080")
        assert_local_url("http://[::1]:8080")
        assert_local_url("http://localhost:8080")

    def test_remote_and_lookalike_hosts_are_rejected(self) -> None:
        for url in ("https://example.com", "http://localhost.example.com", "file:///tmp/app"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                assert_local_url(url)


if __name__ == "__main__":
    unittest.main()
