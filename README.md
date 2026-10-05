# Open-Source Vulnerability Research Toolkit

This repository documents a responsible, source-first vulnerability research
workflow. It discovers plausible projects, organizes local static-analysis
output, supports controlled manual verification against local instances, and
tracks coordinated disclosure.

The workflow produced [GHSA-79vf-xh44-8cpm](https://github.com/django-cms/django-cms/security/advisories/GHSA-79vf-xh44-8cpm), a maintainer-confirmed django CMS authorization vulnerability. The public case study explains the analysis without including a turnkey exploit. The toolkit still does **not** choose targets automatically, prove scanner output exploitable, or authorize testing against third-party systems.

## Published research outcome

[Read the django CMS case study](case-studies/GHSA-79vf-xh44-8cpm.md).

- **Finding:** a client-controlled plugin parent was not consistently scoped to
  the authorized destination placeholder and language.
- **Impact:** restricted rendered-plugin disclosure and a corrupt
  cross-placeholder plugin tree.
- **Affected:** the flaw was present from django CMS 3.0 onward.
- **Resolution:** fixed in 5.0.12 and 5.1.3.
- **Recognition:** `dannyg26` is credited as Reporter in the published GitHub
  Security Advisory.
- **Classification:** Moderate, CVSS 5.5; no CVE was assigned at publication.

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

Package mapping currently examines root manifests only; monorepos and projects whose published package name differs from repository metadata require manual follow-up.

GitHub's public REST API does not provide the reverse-dependent count shown in parts of the website, so the script emits `unknown` instead of scraping HTML or inventing a value. Forks are the stable non-star adoption signal. An unresolved OSV package mapping is also `unknown`, not zero; repository-level GitHub advisories are retained separately and included in the combined history.

The 100-point score is auditable in the output:

- adoption, 35 points: 70% log-scaled forks and 30% log-scaled stars;
- maintenance, 25 points: linear recency over the six-month eligibility window;
- disclosure readiness, 15 points: detected security policy;
- under-review signal, 15 points: adoption divided by one plus known advisory count, normalized within the result set;
- project health, 10 points: license, description, and bounded issue activity.

Unknown OSV history receives a neutral value for the under-review component. Read the raw components, project governance, dependents shown by the relevant package registry, and security policy before choosing anything manually.

## 2. Run a local static-analysis pass

Preview exactly what would run:

```powershell
python triage.py C:\path\to\local-clone --dry-run
```

Run the tools and generate `reports/<target>/triage.md`:

```powershell
python triage.py C:\path\to\local-clone
```

Use `--language python|node|javascript|typescript|php` if detection is wrong, and `--strict-tools` in automation when a missing/failed scanner should make the command fail.

The wrapper runs Semgrep with OWASP, security-audit, and language-specific community configurations; TruffleHog's Git source mode (or Gitleaks) across Git history; Bandit for Python; and OSV-Scanner v2 recursively with dependency resolution disabled. It does not install dependencies or execute the target. Raw JSON is retained under the ignored `reports/` directory, with common secret-value fields redacted before writing.

The worksheet groups leads into secrets, injection, auth, deserialization, path traversal, SSRF, and other. OSV results are explicitly labeled as dependency advisories. Empty verification and notes fields are for manual source review.

## 3. Verify a selected lead locally

Read [verify/README.md](verify/README.md). Copy and adapt `verify/compose.local.yaml` according to the target's own documentation. Its sample port is published only on `127.0.0.1`, and its network is internal. Review any security relaxation required by the application.

The `httpx` helper provides:

- authenticated/unauthenticated request pairs;
- caller-bounded ID comparisons;
- explicitly supplied header/parameter variants;
- compact observation export for private notes.

It accepts only `localhost` or loopback IP literals and never follows redirects. These comparisons are evidence-gathering helpers, not exploit generators or vulnerability classifiers. Start the private report from `verify/report-template.md` only after manual verification.

## 4. Coordinate disclosure

Copy the entry template in `disclosure_tracker.md` for each locally confirmed candidate. Record the exact tested commit, contact channel, response and patch dates, CVE path, follow-ups, and the disclosure date agreed with the maintainer. The placeholder 90-day date is a planning default, not a deadline that overrides project policy or an agreement.

Keep reports factual: state preconditions, confirmed affected versions, the smallest reproducible steps, concrete impact and limits, and a suggested fix. Do not send maintainers an unreviewed scanner dump.

## Suggested end-to-end workflow

1. Generate several shortlists with focused language/category pairs.
2. Manually review adoption, governance, disclosure policy, bounty scope, architecture, and setup cost.
3. Choose one target yourself, clone it locally, and record the commit.
4. Run triage, then prioritize leads by attacker control, reachability, and security boundary—not tool severity alone.
5. Read the relevant code and tests before starting the local application.
6. Reproduce the suspected behavior minimally on loopback and compare it with intended behavior.
7. Rule out false positives, configuration mistakes, duplicate advisories, and already-fixed versions.
8. Privately report through the project's preferred channel and maintain the tracker through remediation and CVE coordination.
9. Publish only after coordination, removing live secrets and respecting embargo terms.

## Current limitations

The public case study intentionally omits a turnkey exploit and private
maintainer correspondence. The generic Compose file must still be adapted to
each target, and per-target verification tests must be written from the actual
code path and intended authorization model. GHSA-79vf-xh44-8cpm did not have a
CVE ID at publication, so this repository does not claim one.

## Tests

The ready-to-enable [GitHub Actions template](.github/tests-workflow.yml) runs
the test suite and syntax checks on Linux and Windows with Python 3.11, 3.12,
and 3.13. To enable it, move the file to `.github/workflows/tests.yml` and push
with credentials authorized to write workflows, or create that file through
GitHub's web editor. CI is inactive until the template is moved.

```powershell
python -m unittest discover -s tests -v
python -m py_compile target_shortlist.py triage.py verify\harness.py
```

## Repository contents

- `target_shortlist.py`: GitHub discovery and auditable shortlist scoring.
- `triage.py`: local scanner orchestration and review worksheets.
- `verify/`: loopback-only observation helpers and a local Compose template.
- `tests/`: offline unit tests.
- `case-studies/`: published research and coordinated-disclosure outcomes.
- `target-selection.md`: the completed django CMS selection rationale.
- `python-auth.*`, `node-cms.*`, and `php-upload.*`: dated example shortlist snapshots.
- `disclosure_tracker.md`: an empty template; keep populated trackers in `private-results/`.

Local target clones, scanner reports, private evidence, virtual environments,
and environment files are excluded by `.gitignore`.
