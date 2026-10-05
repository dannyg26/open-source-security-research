# django CMS Security Research & Disclosure

I found a permissions flaw in **django CMS** that allowed a staff editor to read
content they were not allowed to access. I reproduced it locally, reported it
privately, and worked with the maintainers through confirmation and a fix.

This repository contains the **write-up of that research** and the Python
scripts used to support the review.

**[Read the case study ?](case-studies/GHSA-79vf-xh44-8cpm.md)**

## The finding, in plain language

django CMS is a system for managing website content. Editors work with content
blocks called *plugins*.

During some plugin move/copy operations, the server checked the editor's access
to the destination content area but did not properly check the selected parent
block. By selecting a block from a restricted area, the editor could receive
that block's rendered content in the response. The operation also created an
invalid relationship between blocks in different content areas.

This required an authenticated staff editor with plugin permissions. The
confirmed impact was restricted-content disclosure and an inconsistent plugin
tree; the operation did not insert content into the restricted page.

## The result

The django CMS maintainers confirmed the issue and published
[GHSA-79vf-xh44-8cpm](https://github.com/django-cms/django-cms/security/advisories/GHSA-79vf-xh44-8cpm)
on September 24, 2026, crediting **dannyg26** as Reporter. The fix was released
in **5.0.12 and 5.1.3**. The advisory rates the issue **Moderate (CVSS 5.5)**
and lists **no CVE ID as of October 5, 2026**.

## What I did

1. Selected django CMS and reviewed its plugin permission checks.
2. Followed a user-supplied parent ID through the server's checks and response.
3. Reproduced the permission failure using local test data.
4. Privately reported the issue with a regression test and proposed fix.
5. Coordinated with the security team through remediation and disclosure.

## Where to look

| If you want to? | Read? |
|---|---|
| Understand the bug, local evidence, and disclosure timeline | [Case study](case-studies/GHSA-79vf-xh44-8cpm.md) |
| See why I chose django CMS | [Research selection notes](target-selection.md) |
| Run the supporting scripts or tests | [Setup and workflow guide](docs/workflow.md) |

The scripts help shortlist projects, organize scanner output, and compare
responses from local applications. The finding came from manual review and
local verification. Historical shortlist files are discovery examples, not
additional confirmed findings.

Private correspondence, reproduction tests, and candidate patches are excluded.
The public tests check the supporting scripts. All reproduction work used local
test databases; no public django CMS deployment was tested.
