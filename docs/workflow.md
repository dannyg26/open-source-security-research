# Supporting scripts: setup and workflow

Run commands in this guide from the repository root. The scripts collect
information and observations for manual review. Choosing a project, establishing
a security flaw, writing a report, and contacting maintainers are manual steps.

For the completed django CMS research outcome, read the
[case study](../case-studies/GHSA-79vf-xh44-8cpm.md). Its target-specific
reproduction tests are private and are not run by these generic helpers.

## Safety and scope

- Review the target's `SECURITY.md`, bug-bounty scope, and prohibited-testing rules before doing anything beyond reading public source.
- Clone and test only on your own machine or infrastructure you are explicitly authorized to use.
- Never scan public deployments, enumerate internet hosts, or direct this harness at someone else's service.
- Treat every scanner result as an unverified lead until source review and a minimal local reproduction establish a security-boundary failure.
- Keep working exploit material and reports private until a coordinated fix is available and the maintainer agrees on disclosure.
- A project's policy overrides this workflow, including any shorter or longer disclosure timeline.

## Requirements

- Python 3.11+
- An optional `GITHUB_TOKEN` or `GH_TOKEN` for practical GitHub API rate limits
- Part 2 tools on `PATH`: Semgrep, TruffleHog (or Gitleaks), Bandit for Python projects, and OSV-Scanner v2
- Docker Compose only after selecting a target whose documented local setup supports containers

Install the Python harness dependency in a virtual environment:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Install scanners from their official documentation and verify their versions. Scanner registries and advisory databases evolve, so preserve the command/status artifacts produced with each run.

## 1. Generate a target shortlist

```powershell
$env:GITHUB_TOKEN = "YOUR_READ_ONLY_TOKEN"
python target_shortlist.py python cms --limit 10 --output shortlist.md --json-output shortlist.json
```

The script searches public, non-fork, non-archived repositories with 1,000–20,000 stars and a push in the preceding 183 days. It enriches each result with:

- stars, forks, push date, language, license, description, and issue count from GitHub;
- a community-profile or common-path `SECURITY.md` check;
- a package identity from root `pyproject.toml`, `package.json`, or `composer.json`;
- known OSV advisory and deduplicated CVE counts for that exact package identity.
- published GitHub repository advisories, including advisories without a package identifier.

The initial search returns up to `--limit` repositories sorted by stars, then
scores that subset. It does not search or rank every eligible project.
Package mapping examines root manifests only; monorepos and projects whose
published package name differs from repository metadata require manual follow-up.

The script leaves reverse-dependent counts as `unknown`. Forks and stars are
rough popularity proxies, not measurements of deployment or actual usage.
An unresolved OSV package mapping is `unknown`, not zero. Repository-level
GitHub advisories are retained separately and included in the combined history.

The 100-point score is auditable in the output:

- adoption, 35 points: 70% log-scaled forks and 30% log-scaled stars;
- maintenance, 25 points: linear recency over the six-month eligibility window;
- disclosure readiness, 15 points: detected security policy;
- advisory-history heuristic, 15 points: `(forks + stars / 20) / (1 + advisory count)`, normalized within the result set (stored as `under_review_15`);
- project health, 10 points: license, description, and bounded issue activity.

If both advisory sources are unknown, the history component receives a neutral
value. If either source succeeds, the combined count is used even when the other
source is unavailable. GitHub repository history currently fetches only the
first 100 published advisories. Advisory IDs are combined by exact identifier;
different identifiers for the same issue can inflate the advisory count. CVE IDs
are deduplicated separately.

This score has not been validated as a predictor of undiscovered flaws or review
coverage. Few advisories can reflect limited disclosure, incomplete mapping, or
other factors. The issue-count component is a capped count, not a measure of
response quality. Review the raw data and project policy before choosing a target.

## 2. Run a local static-analysis pass

Record planned scanner commands without executing scanners:

```powershell
python triage.py C:\path\to\local-clone --dry-run
```

Dry runs still write the worksheet and command/status files under `reports/`.

Run the tools and generate `reports/<target>/triage.md`:

```powershell
python triage.py C:\path\to\local-clone
```

Use `--language python|node|javascript|typescript|php` if detection is wrong, and `--strict-tools` in automation when a missing/failed scanner should make the command fail.

The wrapper invokes Semgrep with OWASP, security-audit, and language-specific
community configurations; TruffleHog's Git source mode (or Gitleaks) against Git
history; Bandit for Python; and OSV-Scanner v2 recursively with dependency
resolution disabled. It does not install dependencies or start the target.
Scanners may contact rule registries, advisory services, or secret-verification
services; a local source path does not make the scan offline.

Scanner JSON is retained under the ignored `reports/` directory, with selected
secret-value fields redacted before writing. This is partial redaction, not a
guarantee that outputs contain no sensitive data. Keep all artifacts private.
Inspect tool statuses: zero leads with missing or failed tools is not evidence
of a clean scan. Without `--strict-tools`, those statuses do not make the command
exit unsuccessfully.

The worksheet groups leads into secrets, injection, auth, deserialization, path traversal, SSRF, and other. OSV results are explicitly labeled as dependency advisories. Empty verification and notes fields are for manual source review.

## 3. Verify a selected lead locally

Read [verify/README.md](../verify/README.md). Copy and adapt `verify/compose.local.yaml` according to the target's own documentation. Its sample port is published only on `127.0.0.1`, and its network is internal. Review any security relaxation required by the application.

The `httpx` helper provides:

- request pairs with and without caller-supplied authentication headers;
- caller-bounded ID comparisons;
- explicitly supplied header/parameter variants;
- compact observation export for private notes.

It accepts only `localhost` or loopback IP literals and never follows redirects.
Requests share a cookie jar, so changing headers alone does not guarantee an
unauthenticated session; see the [HTTP-helper notes](../verify/README.md).
These comparisons collect observations for manual interpretation. Start the
private report from `verify/report-template.md` only after manual verification.

## 4. Coordinate disclosure

Copy the entry template in `disclosure_tracker.md` into `private-results/` for
each locally confirmed candidate. Record the tested commit, contact channel,
response and patch dates, advisory identifier, any CVE assignment if applicable,
follow-ups, and the disclosure date agreed with the maintainer. The placeholder
90-day date is a planning default, not a deadline that overrides project policy
or an agreement. The templates do not send messages or request identifiers.

Keep reports factual: state preconditions, confirmed affected versions, the smallest reproducible steps, concrete impact and limits, and a suggested fix. Do not send maintainers an unreviewed scanner dump.

## Suggested end-to-end workflow

1. Generate several shortlists with focused language/category pairs.
2. Manually review adoption, governance, disclosure policy, bounty scope, architecture, and setup cost.
3. Choose one target yourself, clone it locally, and record the commit.
4. Run triage, then prioritize leads by attacker control, reachability, and security boundary—not tool severity alone.
5. Read the relevant code and tests before starting the local application.
6. Reproduce the suspected behavior minimally on loopback and compare it with intended behavior.
7. Rule out false positives, configuration mistakes, duplicate advisories, and already-fixed versions.
8. Privately report through the project's preferred channel and maintain the tracker through remediation and advisory publication; record a CVE ID only if one is assigned.
9. Publish only after coordination, removing live secrets and respecting embargo terms.

## Current limitations

These helpers cover selected workflow steps. They do not establish exploitability
or replace a target-specific test. The HTTP helper checks destination names/IP
literals and disables redirects; it is not a network sandbox. The generic
Compose file must be adapted to each target. The public case study omits private
correspondence and target-specific reproduction material.

## Tests

The ready-to-enable [GitHub Actions template](../.github/tests-workflow.yml) runs
the test suite and syntax checks on Linux and Windows with Python 3.11, 3.12,
and 3.13. To enable it, move the file to `.github/workflows/tests.yml` and push
with credentials authorized to write workflows, or create that file through
GitHub's web editor. CI is inactive until the template is moved.

```powershell
python -m unittest discover -s tests -v
python -m py_compile target_shortlist.py triage.py verify\harness.py
```

See the [repository overview](../README.md) for the public contents. Local target
clones, scanner reports, private evidence, virtual environments, and environment
files are excluded by `.gitignore`.

## Public files and research evidence

| File or directory | Role |
|---|---|
| `target_shortlist.py` | Project discovery, existing advisory history, and heuristic ranking |
| `triage.py` | Installed-scanner orchestration and unverified-lead worksheets |
| `verify/` | Local HTTP observation helpers, Compose example, and report template |
| `disclosure_tracker.md` | Empty template; keep populated copies in `private-results/` |
| `tests/` | 10 unit tests covering selected supporting-script behavior |
| `python-auth.*`, `node-cms.*`, `php-upload.*` | Historical shortlist snapshots from September 3, 2026 |

The shortlist snapshots are examples of discovery output, not current
recommendations or additional confirmed findings. Their CVE counts describe
other projects' existing advisory histories at collection time.

The case study reports historical target-specific observations and test results.
Private correspondence, target-specific reproduction tests, candidate patches,
and scanner reports are excluded. Running the public unit tests does not
reproduce the django CMS flaw or rerun its target-specific regression tests.

## Advisory identifiers

A vulnerability is the underlying security flaw. A GitHub Security Advisory
documents an issue under a `GHSA-...` identifier. A CVE ID is a separate
identifier that may be assigned to the same issue. Record the identifiers
actually published by the maintainer; advisory publication does not establish
that a CVE has been assigned.
