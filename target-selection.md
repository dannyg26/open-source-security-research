# Research selection notes: django CMS

Selected repository: [django-cms/django-cms](https://github.com/django-cms/django-cms)

Selection date: 2026-09-03

Status: research completed; maintainer-confirmed vulnerability published as
[GHSA-79vf-xh44-8cpm](https://github.com/django-cms/django-cms/security/advisories/GHSA-79vf-xh44-8cpm).
The advisory lists no CVE ID as of October 5, 2026.

Baseline commit: `4c823f233aaa0d1f6d63f13b413003b8f09b4214`

Baseline description: `5.1.0-53-g4c823f233`

## Why I selected it

I selected django CMS for a focused review of editor permissions and plugin
operations. Its source made it possible to trace how client-supplied object IDs
were checked, stored, and used to render responses. It also had a documented
private security-reporting channel.

Strapi and Wagtail were considered during discovery, but django CMS was the
project chosen for this review. This was a practical scope decision, not a
conclusion that it was less secure, easier to exploit, or less thoroughly reviewed.

## Review focus

- How plugin operations enforce permissions on referenced objects.
- Whether sibling branches constrain the same object identifiers consistently.
- How plugin parent relationships affect persistence and response rendering.
- Whether a locally reproduced behavior violates the intended authorization model.

The shortlist scripts supplied discovery metadata. They did not identify the
authorization flaw or establish that a project would contain a reportable issue.

## Scope constraints

- Test only a local clone and locally created accounts, pages, plugins, and files.
- Bind the development application only to a loopback address.
- Do not interact with or enumerate public django CMS installations.
- Test a supported release/current branch and record the exact commit.
- Review the current security policy before reporting.
- Keep reproduction material private until disclosure is coordinated.
- Scanner output is an unverified lead, not a finding.
- Selection does not guarantee a vulnerability or CVE assignment.

## References

- [Repository](https://github.com/django-cms/django-cms)
- [Security policy](https://github.com/django-cms/django-cms/security)
- [Published advisory GHSA-79vf-xh44-8cpm](https://github.com/django-cms/django-cms/security/advisories/GHSA-79vf-xh44-8cpm)

## Outcome

Manual review of the plugin move/copy authorization path identified an unscoped
client-controlled parent lookup. The issue was reproduced only in local test
databases, reported privately on 2026-09-03, confirmed by the django CMS
security team, fixed in releases 5.0.12 and 5.1.3, and disclosed on 2026-09-24.
The advisory credits `dannyg26` as Reporter and lists no CVE ID. See the
[public case study](case-studies/GHSA-79vf-xh44-8cpm.md) for the technical and
disclosure timeline.
