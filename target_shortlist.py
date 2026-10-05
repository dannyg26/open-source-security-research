#!/usr/bin/env python3
"""Build an auditable shortlist of open-source vulnerability-research targets.

This script discovers projects. It does not select, clone, scan, or test them.
"""

from __future__ import annotations

import argparse
import base64
import json
import math
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


GITHUB_API = "https://api.github.com"
OSV_API = "https://api.osv.dev/v1"
SECURITY_PATHS = ("SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md")
MANIFEST_PATHS = ("pyproject.toml", "package.json", "composer.json")
LANGUAGE_ALIASES = {
    "node": "JavaScript",
    "nodejs": "JavaScript",
    "js": "JavaScript",
    "javascript": "JavaScript",
    "ts": "TypeScript",
    "typescript": "TypeScript",
    "python": "Python",
    "php": "PHP",
}


class ApiError(RuntimeError):
    pass


class JsonClient:
    def __init__(self, github_token: str | None = None, timeout: int = 20) -> None:
        self.github_token = github_token
        self.timeout = timeout

    def request(self, url: str, *, payload: dict[str, Any] | None = None) -> Any:
        headers = {"User-Agent": "local-vulnerability-research-toolkit/1.0"}
        if url.startswith(GITHUB_API):
            headers.update(
                {
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                }
            )
            if self.github_token:
                headers["Authorization"] = f"Bearer {self.github_token}"
        data = None
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=data, headers=headers)
        for attempt in range(3):
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    return json.load(response)
            except urllib.error.HTTPError as exc:
                detail = exc.read().decode("utf-8", errors="replace")[:500]
                if exc.code in (403, 429) and attempt < 2:
                    time.sleep(2**attempt)
                    continue
                raise ApiError(f"HTTP {exc.code} from {url}: {detail}") from exc
            except urllib.error.URLError as exc:
                if attempt < 2:
                    time.sleep(2**attempt)
                    continue
                raise ApiError(f"Unable to reach {url}: {exc.reason}") from exc
        raise ApiError(f"Unable to reach {url}")


@dataclass(frozen=True)
class PackageIdentity:
    ecosystem: str
    name: str
    source: str


def github_url(path: str, **params: Any) -> str:
    url = f"{GITHUB_API}{path}"
    if params:
        url += "?" + urllib.parse.urlencode(params)
    return url


def normalize_language(value: str) -> str:
    return LANGUAGE_ALIASES.get(value.casefold(), value)


def months_ago(now: datetime, months: int = 6) -> datetime:
    # GitHub accepts a date qualifier; 183 days is a transparent six-month proxy.
    return now - timedelta(days=183 if months == 6 else 30.5 * months)


def fetch_content(client: JsonClient, full_name: str, path: str) -> str | None:
    quoted = "/".join(urllib.parse.quote(part, safe="") for part in path.split("/"))
    try:
        result = client.request(github_url(f"/repos/{full_name}/contents/{quoted}"))
    except ApiError as exc:
        if "HTTP 404" in str(exc):
            return None
        raise
    if not isinstance(result, dict) or result.get("type") != "file":
        return None
    content = result.get("content")
    if not isinstance(content, str):
        return None
    try:
        return base64.b64decode(content).decode("utf-8", errors="replace")
    except (ValueError, TypeError):
        return None


def repository_paths(
    client: JsonClient, full_name: str, default_branch: str
) -> set[str]:
    branch = urllib.parse.quote(default_branch, safe="")
    result = client.request(
        github_url(f"/repos/{full_name}/git/trees/{branch}", recursive="1")
    )
    return {
        str(item["path"])
        for item in result.get("tree", [])
        if item.get("type") == "blob" and item.get("path")
    }


def security_policy(
    client: JsonClient, full_name: str, paths: set[str]
) -> tuple[bool, str | None]:
    path_lookup = {path.casefold(): path for path in paths}
    for expected in SECURITY_PATHS:
        actual = path_lookup.get(expected.casefold())
        if actual:
            return True, f"https://github.com/{full_name}/blob/HEAD/{actual}"
    try:
        profile = client.request(github_url(f"/repos/{full_name}/community/profile"))
        security = (profile.get("files") or {}).get("security")
        if security:
            return True, security.get("html_url") or security.get("url")
    except ApiError:
        pass
    return False, None


def package_identity(
    client: JsonClient, full_name: str, paths: set[str]
) -> PackageIdentity | None:
    path_lookup = {path.casefold(): path for path in paths}
    for expected in MANIFEST_PATHS:
        path = path_lookup.get(expected.casefold())
        if not path:
            continue
        text = fetch_content(client, full_name, path)
        if text is None:
            continue
        try:
            if path == "package.json":
                name = json.loads(text).get("name")
                if name:
                    return PackageIdentity("npm", str(name), path)
            elif path == "composer.json":
                name = json.loads(text).get("name")
                if name:
                    return PackageIdentity("Packagist", str(name), path)
            else:
                import tomllib

                document = tomllib.loads(text)
                name = (document.get("project") or {}).get("name")
                if not name:
                    name = ((document.get("tool") or {}).get("poetry") or {}).get("name")
                if name:
                    return PackageIdentity("PyPI", str(name), path)
        except (json.JSONDecodeError, ValueError, TypeError):
            continue
    return None


def osv_history(client: JsonClient, package: PackageIdentity | None) -> dict[str, Any]:
    if package is None:
        return {
            "status": "unknown", "advisories": None, "cves": None,
            "ids": [], "cve_ids": [],
        }
    payload: dict[str, Any] = {
        "package": {"ecosystem": package.ecosystem, "name": package.name}
    }
    records: dict[str, dict[str, Any]] = {}
    while True:
        response = client.request(f"{OSV_API}/query", payload=payload)
        for vuln in response.get("vulns", []):
            records[vuln["id"]] = vuln
        token = response.get("next_page_token")
        if not token:
            break
        payload["page_token"] = token
    cves = {
        identifier
        for record in records.values()
        for identifier in [record.get("id", ""), *(record.get("aliases") or [])]
        if identifier.startswith("CVE-")
    }
    return {
        "status": "known",
        "advisories": len(records),
        "cves": len(cves),
        "ids": sorted(records),
        "cve_ids": sorted(cves),
    }


def github_advisory_history(client: JsonClient, full_name: str) -> dict[str, Any]:
    """Return published advisories attached directly to a GitHub repository."""
    try:
        records = client.request(
            github_url(
                f"/repos/{full_name}/security-advisories",
                state="published",
                per_page=100,
            )
        )
    except ApiError as exc:
        return {
            "status": "unknown", "advisories": None, "cves": None,
            "ids": [], "cve_ids": [], "error": str(exc),
        }
    ids = {record.get("ghsa_id") for record in records if record.get("ghsa_id")}
    cves = {record.get("cve_id") for record in records if record.get("cve_id")}
    return {
        "status": "known", "advisories": len(ids), "cves": len(cves),
        "ids": sorted(ids), "cve_ids": sorted(cves), "error": None,
    }


def combine_history(osv: dict[str, Any], github: dict[str, Any]) -> dict[str, Any]:
    known = osv["status"] == "known" or github["status"] == "known"
    ids = set(osv.get("ids") or []) | set(github.get("ids") or [])
    cve_ids = set(osv.get("cve_ids") or []) | set(github.get("cve_ids") or [])
    return {
        "status": "known" if known else "unknown",
        "advisories": len(ids) if known else None,
        "cves": len(cve_ids) if known else None,
        "ids": sorted(ids),
        "cve_ids": sorted(cve_ids),
    }


def scale_log(value: int, values: list[int]) -> float:
    ceiling = max(values, default=0)
    if ceiling <= 0:
        return 0.0
    return math.log1p(max(0, value)) / math.log1p(ceiling)


def score_candidates(candidates: list[dict[str, Any]], now: datetime) -> None:
    forks = [item["forks"] for item in candidates]
    stars = [item["stars"] for item in candidates]
    ratios: list[float] = []
    for item in candidates:
        history = item.get("security_history", item["osv"])
        if history["status"] == "known":
            ratios.append(
                (item["forks"] + item["stars"] / 20) / (1 + history["advisories"])
            )
    max_ratio = max(ratios, default=0.0)

    for item in candidates:
        adoption = 0.7 * scale_log(item["forks"], forks) + 0.3 * scale_log(
            item["stars"], stars
        )
        age_days = max(0.0, (now - parse_datetime(item["pushed_at"])).total_seconds() / 86400)
        maintenance = max(0.0, 1.0 - age_days / 183.0)
        readiness = 1.0 if item["has_security_policy"] else 0.0
        history = item.get("security_history", item["osv"])
        if history["status"] == "known" and max_ratio:
            ratio = (item["forks"] + item["stars"] / 20) / (
                1 + history["advisories"]
            )
            under_review = ratio / max_ratio
        else:
            # Unknown is neutral, not equivalent to a clean history.
            under_review = 0.5
        issue_signal = min(item["open_issues"], 50) / 50
        health = (
            0.5 * bool(item["license"])
            + 0.25 * bool(item["description"])
            + 0.25 * issue_signal
        )
        components = {
            "adoption_35": round(35 * adoption, 2),
            "maintenance_25": round(25 * maintenance, 2),
            "disclosure_15": round(15 * readiness, 2),
            "under_review_15": round(15 * under_review, 2),
            "health_10": round(10 * health, 2),
        }
        item["score_components"] = components
        item["score"] = round(sum(components.values()), 2)
    candidates.sort(key=lambda item: (item["score"], item["forks"]), reverse=True)


def parse_datetime(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def discover(
    client: JsonClient,
    language: str,
    category: str,
    limit: int,
    now: datetime,
) -> tuple[list[dict[str, Any]], str]:
    cutoff = months_ago(now).date().isoformat()
    clean_category = " ".join(category.replace("-", " ").split())
    query = (
        f"{clean_category} in:name,description,topics "
        f"language:{normalize_language(language)} stars:1000..20000 "
        f"pushed:>={cutoff} archived:false fork:false is:public"
    )
    response = client.request(
        github_url("/search/repositories", q=query, sort="stars", order="desc", per_page=limit)
    )
    candidates: list[dict[str, Any]] = []
    for repo in response.get("items", [])[:limit]:
        full_name = repo["full_name"]
        try:
            paths = repository_paths(client, full_name, repo["default_branch"])
            has_security, security_url = security_policy(client, full_name, paths)
            identity = package_identity(client, full_name, paths)
            history = osv_history(client, identity)
            repository_history = github_advisory_history(client, full_name)
            security_history = combine_history(history, repository_history)
            enrichment_error = None
        except ApiError as exc:
            has_security, security_url, identity = False, None, None
            history = {
                "status": "unknown", "advisories": None, "cves": None,
                "ids": [], "cve_ids": [],
            }
            repository_history = {
                "status": "unknown", "advisories": None, "cves": None,
                "ids": [], "cve_ids": [], "error": str(exc),
            }
            security_history = combine_history(history, repository_history)
            enrichment_error = str(exc)
        candidates.append(
            {
                "repository": full_name,
                "url": repo["html_url"],
                "stars": repo.get("stargazers_count", 0),
                "forks": repo.get("forks_count", 0),
                "dependents": None,
                "dependents_status": "not available from GitHub public REST API",
                "open_issues": repo.get("open_issues_count", 0),
                "pushed_at": repo["pushed_at"],
                "language": repo.get("language"),
                "description": repo.get("description") or "",
                "license": (repo.get("license") or {}).get("spdx_id"),
                "has_security_policy": has_security,
                "security_policy_url": security_url,
                "package": identity.__dict__ if identity else None,
                "osv": history,
                "github_repository_advisories": repository_history,
                "security_history": security_history,
                "enrichment_error": enrichment_error,
            }
        )
    score_candidates(candidates, now)
    return candidates, query


def markdown(candidates: list[dict[str, Any]], query: str, generated: datetime) -> str:
    lines = [
        "# Target shortlist",
        "",
        f"Generated: {generated.isoformat()}",
        "",
        f"GitHub query: `{query}`",
        "",
        "> Research aid only. A high score is not permission to test and is not evidence of a vulnerability.",
        "> Review each project's security policy and bug-bounty scope before cloning or testing locally.",
        "",
        "## Ranking",
        "",
        "| Rank | Repository | Score | Stars | Forks | Dependents | Last push | Security policy | Prior CVEs | Package | Language | Description |",
        "|---:|---|---:|---:|---:|---:|---|---|---:|---|---|---|",
    ]
    for rank, item in enumerate(candidates, 1):
        package = item["package"]
        package_text = (
            f"{package['ecosystem']}:{package['name']}" if package else "unknown"
        )
        cves = item.get("security_history", item["osv"])["cves"]
        security = "[yes](%s)" % item["security_policy_url"] if item["security_policy_url"] else "no"
        description = item["description"].replace("|", "\\|").replace("\n", " ")
        lines.append(
            f"| {rank} | [{item['repository']}]({item['url']}) | {item['score']:.2f} | "
            f"{item['stars']} | {item['forks']} | unknown | {item['pushed_at'][:10]} | "
            f"{security} | {cves if cves is not None else 'unknown'} | {package_text} | "
            f"{item['language'] or 'unknown'} | {description} |"
        )
    lines.extend(
        [
            "",
            "## Score details",
            "",
            "Score = adoption 35 + maintenance 25 + disclosure readiness 15 + under-review signal 15 + health 10. Adoption uses log-scaled forks (70%) and stars (30%). Unknown OSV mapping receives a neutral under-review value, not a zero-advisory bonus.",
            "",
        ]
    )
    for rank, item in enumerate(candidates, 1):
        components = ", ".join(f"{key}={value}" for key, value in item["score_components"].items())
        warning = f"; enrichment error: {item['enrichment_error']}" if item["enrichment_error"] else ""
        lines.append(f"{rank}. **{item['repository']}** — {components}{warning}")
    lines.extend(
        [
            "",
            "## Data limitations",
            "",
            "- GitHub's public REST API does not expose the repository UI's reverse-dependent count; `dependents` is therefore reported as unknown. Forks are the consistent adoption proxy.",
            "- OSV history is queried only after deriving an ecosystem package name from a root manifest. Published GitHub repository advisories are also checked because some advisories have no package identifier. `unknown` means lookup failed; it does not mean zero advisories.",
            "- Counts describe known public advisories and can contain multiple records representing related advisories. The CVE count is deduplicated from CVE aliases.",
            "",
        ]
    )
    return "\n".join(lines)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("language", help="GitHub language/ecosystem, e.g. python, node, php")
    parser.add_argument("category", help="Rough category, e.g. cms, auth, admin-panel")
    parser.add_argument("--limit", type=int, default=10, choices=range(1, 31), metavar="1..30")
    parser.add_argument("--output", type=Path, default=Path("shortlist.md"))
    parser.add_argument("--json-output", type=Path, help="Optional raw JSON output")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    now = datetime.now(timezone.utc)
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token:
        print("Warning: no GITHUB_TOKEN/GH_TOKEN; GitHub's low anonymous rate limit applies.", file=sys.stderr)
    try:
        candidates, query = discover(JsonClient(token), args.language, args.category, args.limit, now)
    except ApiError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(markdown(candidates, query, now), encoding="utf-8")
    if args.json_output:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(
            json.dumps({"generated_at": now.isoformat(), "query": query, "candidates": candidates}, indent=2),
            encoding="utf-8",
        )
    print(f"Wrote {len(candidates)} candidates to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
