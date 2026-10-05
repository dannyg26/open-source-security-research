# Open-Source Security Research

A record of a manual security review of **django CMS**, the resulting
coordinated disclosure, and the Python scripts used to support the research.

The main outcome is [GHSA-79vf-xh44-8cpm](https://github.com/django-cms/django-cms/security/advisories/GHSA-79vf-xh44-8cpm):
a maintainer-confirmed authorization flaw, fixed in django CMS 5.0.12 and 5.1.3.
The advisory credits [`dannyg26`](https://github.com/dannyg26) as Reporter.
**The advisory lists no CVE ID as of October 5, 2026.** The outcome is a
published security advisory and fix; this project does not claim a CVE assignment.

## Start here

- **Understand the finding:** [django CMS case study](case-studies/GHSA-79vf-xh44-8cpm.md).
- **Understand the research process:** [why django CMS was selected](target-selection.md).
- **Use the supporting scripts:** [setup and workflow guide](docs/workflow.md).

## What was found?

django CMS lets editors arrange content blocks called *plugins* inside content
areas called *placeholders*. A *parent plugin* is a block containing other blocks.

In part of the plugin move/copy handling, the server accepted a parent ID
without checking that it belonged to the destination content area. A staff
editor could reference a parent in a restricted area and receive its rendered
content. The operation also created an inconsistent parent-child relationship.
The fix constrained the parent lookup to the destination placeholder and language.

The flaw required authenticated staff/plugin permissions. It did not provide
anonymous access or place content onto the restricted page. The maintainers
rated it Moderate, with a CVSS 3.1 score of 5.5. See the
[upstream advisory](https://github.com/django-cms/django-cms/security/advisories/GHSA-79vf-xh44-8cpm)
for the authoritative affected ranges, impact, and remediation.

## What the scripts do

These are research helpers. The finding was established through manual source
review and local testing; a scanner result alone was not confirmation.

| Component | Purpose | Output |
|---|---|---|
| [`target_shortlist.py`](target_shortlist.py) | Search GitHub and collect project metadata and existing advisory history | Ranked Markdown/JSON shortlist for manual review |
| [`triage.py`](triage.py) | Run installed scanners against a local source checkout | Tool statuses, sanitized scanner JSON, and an unverified-lead worksheet |
| [`verify/`](verify/README.md) | Compare caller-supplied HTTP requests against a local application | Response observations for manual interpretation |
| [`disclosure_tracker.md`](disclosure_tracker.md) | Provide an empty disclosure-tracking template | A private record filled in by the researcher |

The shortlist score is a heuristic for organizing review, not a measurement of
security or the likelihood of finding a flaw. Existing CVE counts in shortlists
describe other projects' public advisory histories, not discoveries by this project.

## What is included?

The public case study describes the reasoning, local observations, impact limits,
and disclosure timeline. It also reports historical target-specific test results.
Private correspondence, target-specific reproduction tests, candidate patches,
and scanner reports are excluded from this repository.

The 10 tests in [`tests/`](tests/test_toolkit.py) check selected behavior of the
supporting scripts. They do not reproduce the django CMS finding. The generic
Compose template needs to be adapted to a target's own setup instructions.

[`python-auth.md`](python-auth.md), [`node-cms.md`](node-cms.md), and
[`php-upload.md`](php-upload.md), with their JSON counterparts, are historical
shortlist snapshots from September 3, 2026. They are examples of discovery
output, not additional confirmed findings or current recommendations.

## Advisory and CVE terminology

A security vulnerability is the underlying flaw. A GitHub Security Advisory
documents a reported issue and has a `GHSA-...` identifier. A CVE ID is a
separate identifier that may be assigned to that issue. Here, the documented
result is **GHSA-79vf-xh44-8cpm, with no CVE ID listed**. A missing CVE ID does
not negate the maintainer-confirmed vulnerability.

## Run the supporting tests

Requires Python 3.11+. From the repository root:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
```

Scanner installation and HTTP-helper usage are covered in the
[workflow guide](docs/workflow.md). The [CI template](.github/tests-workflow.yml)
is included but inactive; the guide explains how to enable it.

## Research scope

The django CMS reproduction used local test databases. No public deployment was
tested. Use the helpers only with local instances or source checkouts you are
authorized to review, and follow the target's security and disclosure policy.
Keep working reports and evidence in the ignored `private-results/` directory.
