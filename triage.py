#!/usr/bin/env python3
"""Run local-only first-pass scanners and create a manual triage worksheet."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


CATEGORIES = (
    "secrets",
    "injection",
    "auth",
    "deserialization",
    "path traversal",
    "SSRF",
    "other",
)
LANGUAGE_CONFIGS = {
    "python": "p/python",
    "javascript": "p/nodejsscan",
    "typescript": "p/nodejsscan",
    "node": "p/nodejsscan",
    "php": "p/php",
}
SENSITIVE_KEYS = {
    "raw",
    "rawv2",
    "redacted",
    "secret",
    "plaintext",
    "password",
    "token",
}


@dataclass
class Finding:
    category: str
    tool: str
    file: str
    line: int | None
    rule: str
    summary: str
    confidence: str = ""


@dataclass
class ToolRun:
    name: str
    status: str
    command: list[str]
    detail: str = ""


def find_tool(name: str) -> str | None:
    """Find a command on PATH, in the venv, or in WinGet portable packages."""
    found = shutil.which(name)
    if found:
        return found
    scripts_dir = Path(sys.executable).resolve().parent
    for filename in (name, f"{name}.exe", f"{name}.cmd"):
        candidate = scripts_dir / filename
        if candidate.is_file():
            return str(candidate)
    if sys.platform == "win32":
        packages = Path.home() / "AppData" / "Local" / "Microsoft" / "WinGet" / "Packages"
        package_ids = {
            "gitleaks": "Gitleaks.Gitleaks_*",
            "osv-scanner": "Google.OSVScanner_*",
        }
        pattern = package_ids.get(name.casefold())
        if pattern and packages.is_dir():
            for package_dir in packages.glob(pattern):
                candidate = package_dir / f"{name}.exe"
                if candidate.is_file():
                    return str(candidate)
    return None


def detect_language(target: Path) -> str:
    if (target / "pyproject.toml").exists() or (target / "requirements.txt").exists():
        return "python"
    if (target / "package.json").exists():
        return "node"
    if (target / "composer.json").exists():
        return "php"
    return "unknown"


def classify(text: str, tool: str) -> str:
    value = text.casefold()
    if tool in {"trufflehog", "gitleaks"} or any(
        word in value for word in ("secret", "credential", "api key", "private key")
    ):
        return "secrets"
    if any(word in value for word in ("path traversal", "directory traversal", "zip slip")):
        return "path traversal"
    if any(word in value for word in ("ssrf", "server-side request forgery")):
        return "SSRF"
    if any(word in value for word in ("deserial", "pickle", "yaml.load", "object injection")):
        return "deserialization"
    if any(
        word in value
        for word in ("sql injection", "command injection", "code injection", "xss", "eval", "exec")
    ):
        return "injection"
    if any(
        word in value
        for word in ("auth", "permission", "access control", "idor", "jwt", "session", "csrf")
    ):
        return "auth"
    return "other"


def safe_relative(path: str, target: Path) -> str:
    candidate = Path(path)
    try:
        return str(candidate.resolve().relative_to(target)).replace("\\", "/")
    except (ValueError, OSError):
        return path.replace("\\", "/")


def sanitize(value: Any, parent_key: str = "") -> Any:
    """Remove secret material before persisting scanner JSON."""
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if key.casefold() in SENSITIVE_KEYS else sanitize(item, key)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [sanitize(item, parent_key) for item in value]
    return value


def run_json(command: list[str], allowed_codes: set[int] | None = None) -> tuple[Any, str, int]:
    result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace")
    allowed = allowed_codes or {0}
    if result.returncode not in allowed:
        raise RuntimeError(result.stderr.strip() or f"exit code {result.returncode}")
    output = result.stdout.strip()
    return (json.loads(output) if output else {}, result.stderr.strip(), result.returncode)


def semgrep_findings(data: dict[str, Any], target: Path) -> list[Finding]:
    findings = []
    for result in data.get("results", []):
        extra = result.get("extra") or {}
        rule = result.get("check_id", "unknown-rule")
        message = extra.get("message", rule)
        findings.append(
            Finding(
                classify(f"{rule} {message}", "semgrep"),
                "Semgrep",
                safe_relative(result.get("path", "unknown"), target),
                (result.get("start") or {}).get("line"),
                rule,
                message.replace("\n", " ").strip(),
                str((extra.get("metadata") or {}).get("confidence", "")),
            )
        )
    return findings


def bandit_findings(data: dict[str, Any], target: Path) -> list[Finding]:
    findings = []
    for result in data.get("results", []):
        rule = result.get("test_id", "unknown-rule")
        message = result.get("issue_text", rule)
        findings.append(
            Finding(
                classify(f"{rule} {message}", "bandit"),
                "Bandit",
                safe_relative(result.get("filename", "unknown"), target),
                result.get("line_number"),
                rule,
                message.replace("\n", " ").strip(),
                result.get("issue_confidence", ""),
            )
        )
    return findings


def trufflehog_findings(data: list[dict[str, Any]], target: Path) -> list[Finding]:
    findings = []
    for result in data:
        git = (((result.get("SourceMetadata") or {}).get("Data") or {}).get("Git") or {})
        location = git.get("file") or git.get("File") or "git history"
        line = git.get("line") or git.get("Line")
        detector = result.get("DetectorName", "secret-detector")
        verified = "verified detector match" if result.get("Verified") else "unverified detector match"
        findings.append(
            Finding("secrets", "TruffleHog", safe_relative(location, target), line, detector, verified)
        )
    return findings


def gitleaks_findings(data: list[dict[str, Any]], target: Path) -> list[Finding]:
    return [
        Finding(
            "secrets",
            "Gitleaks",
            safe_relative(item.get("File", "git history"), target),
            item.get("StartLine"),
            item.get("RuleID", "secret-detector"),
            item.get("Description", "potential secret"),
        )
        for item in data
    ]


def osv_findings(data: dict[str, Any], target: Path) -> list[Finding]:
    findings: list[Finding] = []
    for result in data.get("results", []):
        source = result.get("source") or {}
        source_path = safe_relative(source.get("path", "lockfile"), target)
        for package_entry in result.get("packages", []):
            package = package_entry.get("package") or {}
            name = package.get("name", "unknown-package")
            version = package.get("version", "unknown-version")
            for vuln in package_entry.get("vulnerabilities", []):
                vuln_id = vuln.get("id", "unknown-advisory")
                findings.append(
                    Finding(
                        "other",
                        "OSV-Scanner (dependency)",
                        source_path,
                        None,
                        vuln_id,
                        f"Known advisory for dependency {name} {version}; assess separately from first-party code.",
                    )
                )
    return findings


def parse_json_lines(text: str) -> list[dict[str, Any]]:
    records = []
    for line in text.splitlines():
        if line.strip():
            records.append(json.loads(line))
    return records


def write_raw(raw_dir: Path, name: str, data: Any) -> None:
    raw_dir.mkdir(parents=True, exist_ok=True)
    (raw_dir / f"{name}.json").write_text(
        json.dumps(sanitize(data), indent=2, sort_keys=True), encoding="utf-8"
    )


def run_scans(target: Path, raw_dir: Path, language: str, dry_run: bool) -> tuple[list[Finding], list[ToolRun]]:
    findings: list[Finding] = []
    runs: list[ToolRun] = []
    lang_config = LANGUAGE_CONFIGS.get(language.casefold())

    semgrep = find_tool("semgrep")
    configs = ["p/owasp-top-ten", "p/security-audit"] + ([lang_config] if lang_config else [])
    command = [semgrep or "semgrep", "scan"]
    for config in configs:
        command.extend(["--config", config])
    command.extend(["--json", "--quiet", str(target)])
    if dry_run:
        runs.append(ToolRun("Semgrep", "planned", command))
    elif not semgrep:
        runs.append(ToolRun("Semgrep", "missing", command, "Install Semgrep and rerun."))
    else:
        try:
            data, stderr, _ = run_json(command, {0, 1})
            write_raw(raw_dir, "semgrep", data)
            findings.extend(semgrep_findings(data, target))
            runs.append(ToolRun("Semgrep", "completed", command, stderr[-300:]))
        except (RuntimeError, json.JSONDecodeError) as exc:
            runs.append(ToolRun("Semgrep", "failed", command, str(exc)))

    trufflehog = find_tool("trufflehog")
    gitleaks = find_tool("gitleaks")
    if trufflehog:
        command = [trufflehog, "git", target.as_uri(), "--json", "--no-update"]
        secret_tool = "TruffleHog"
    elif gitleaks:
        command = [gitleaks, "git", str(target), "--report-format", "json", "--no-banner"]
        secret_tool = "Gitleaks"
    else:
        command = ["trufflehog", "git", target.as_uri(), "--json", "--no-update"]
        secret_tool = "TruffleHog/Gitleaks"
    if dry_run:
        runs.append(ToolRun(secret_tool, "planned", command))
    elif not trufflehog and not gitleaks:
        runs.append(ToolRun(secret_tool, "missing", command, "Install either TruffleHog or Gitleaks."))
    elif trufflehog:
        try:
            result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace")
            if result.returncode not in {0, 183}:
                raise RuntimeError(result.stderr.strip() or f"exit code {result.returncode}")
            data = parse_json_lines(result.stdout)
            write_raw(raw_dir, "trufflehog", data)
            findings.extend(trufflehog_findings(data, target))
            runs.append(ToolRun("TruffleHog", "completed", command, result.stderr.strip()[-300:]))
        except (RuntimeError, json.JSONDecodeError) as exc:
            runs.append(ToolRun("TruffleHog", "failed", command, str(exc)))
    else:
        with tempfile.TemporaryDirectory(prefix="triage-gitleaks-") as temp_dir:
            report = Path(temp_dir) / "gitleaks.json"
            command.extend(["--report-path", str(report)])
            result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace")
            if result.returncode in {0, 1} and report.exists():
                try:
                    data = json.loads(report.read_text(encoding="utf-8") or "[]")
                    write_raw(raw_dir, "gitleaks", data)
                    findings.extend(gitleaks_findings(data, target))
                    runs.append(ToolRun("Gitleaks", "completed", command, result.stderr.strip()[-300:]))
                except json.JSONDecodeError as exc:
                    runs.append(ToolRun("Gitleaks", "failed", command, str(exc)))
            else:
                runs.append(ToolRun("Gitleaks", "failed", command, result.stderr.strip()[-300:]))

    if language.casefold() == "python":
        bandit = find_tool("bandit")
        command = [bandit or "bandit", "-r", str(target), "-f", "json", "-q"]
        if dry_run:
            runs.append(ToolRun("Bandit", "planned", command))
        elif not bandit:
            runs.append(ToolRun("Bandit", "missing", command, "Install Bandit and rerun."))
        else:
            try:
                data, stderr, _ = run_json(command, {0, 1})
                write_raw(raw_dir, "bandit", data)
                findings.extend(bandit_findings(data, target))
                runs.append(ToolRun("Bandit", "completed", command, stderr[-300:]))
            except (RuntimeError, json.JSONDecodeError) as exc:
                runs.append(ToolRun("Bandit", "failed", command, str(exc)))

    osv = find_tool("osv-scanner")
    command = [
        osv or "osv-scanner", "scan", "source", "--format=json", "--verbosity=error",
        "--no-resolve", "--recursive", str(target),
    ]
    if dry_run:
        runs.append(ToolRun("OSV-Scanner", "planned", command))
    elif not osv:
        runs.append(ToolRun("OSV-Scanner", "missing", command, "Install OSV-Scanner v2 and rerun."))
    else:
        try:
            data, stderr, _ = run_json(command, {0, 1})
            write_raw(raw_dir, "osv-scanner", data)
            findings.extend(osv_findings(data, target))
            runs.append(ToolRun("OSV-Scanner", "completed", command, stderr[-300:]))
        except (RuntimeError, json.JSONDecodeError) as exc:
            runs.append(ToolRun("OSV-Scanner", "failed", command, str(exc)))
    return findings, runs


def escape(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ").strip()


def render_report(target: Path, language: str, findings: list[Finding], runs: list[ToolRun]) -> str:
    now = datetime.now(timezone.utc).isoformat()
    lines = [
        f"# Triage: {target.name}", "", f"Generated: {now}", f"Target: `{target}`",
        f"Detected/selected language: `{language}`", "",
        "> Every entry is an unverified scanner lead, not a vulnerability finding.",
        "> Test only this local clone/instance and follow the project's published security policy.",
        "", "## Tool status", "", "| Tool | Status | Detail |", "|---|---|---|",
    ]
    for run in runs:
        lines.append(f"| {run.name} | {run.status} | {escape(run.detail)} |")
    for category in CATEGORIES:
        lines.extend(["", f"## {category.title() if category != 'SSRF' else 'SSRF'}", ""])
        matches = [finding for finding in findings if finding.category == category]
        if not matches:
            lines.append("No leads emitted by the completed tools.")
            continue
        for index, finding in enumerate(matches, 1):
            location = f"{finding.file}:{finding.line}" if finding.line else finding.file
            lines.extend(
                [
                    f"### {index}. {escape(finding.rule)}", "",
                    f"- Location: `{location}`", f"- Tool: {finding.tool}",
                    f"- Candidate: {escape(finding.summary)}",
                    f"- Confidence: {finding.confidence or 'not supplied'}",
                    "- Verified? [ ] Yes [ ] No [ ] Needs investigation", "- Notes:", "",
                ]
            )
    lines.extend(
        ["", "## Manual review reminders", "", "- Confirm reachability and attacker control before treating a lead as real.",
         "- Separate dependency advisories from flaws in the target's own code.",
         "- Do not place live credentials or an unpatched working exploit in this report.", ""]
    )
    return "\n".join(lines)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", type=Path, help="Path to a local git clone")
    parser.add_argument("--language", choices=sorted(LANGUAGE_CONFIGS), help="Override language detection")
    parser.add_argument("--output-dir", type=Path, default=Path("reports"))
    parser.add_argument("--dry-run", action="store_true", help="Print planned tools without executing them")
    parser.add_argument("--strict-tools", action="store_true", help="Fail if a scanner is missing or fails")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    target = args.target.resolve()
    if not target.is_dir() or not (target / ".git").exists():
        print("error: target must be the root of a local git clone", file=sys.stderr)
        return 2
    language = args.language or detect_language(target)
    report_root = args.output_dir.resolve() / target.name
    raw_dir = report_root / "raw"
    findings, runs = run_scans(target, raw_dir, language, args.dry_run)
    report_root.mkdir(parents=True, exist_ok=True)
    report_path = report_root / "triage.md"
    report_path.write_text(render_report(target, language, findings, runs), encoding="utf-8")
    (report_root / "tool-runs.json").write_text(
        json.dumps([asdict(run) for run in runs], indent=2), encoding="utf-8"
    )
    print(f"Wrote {len(findings)} unverified leads to {report_path}")
    failed = any(run.status in {"missing", "failed"} for run in runs)
    return 3 if args.strict_tools and failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
