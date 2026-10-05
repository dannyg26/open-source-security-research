# Target selection: django CMS

Selected repository: [django-cms/django-cms](https://github.com/django-cms/django-cms)

Selection date: 2026-09-03

Status: research completed; maintainer-confirmed vulnerability published as
[GHSA-79vf-xh44-8cpm](https://github.com/django-cms/django-cms/security/advisories/GHSA-79vf-xh44-8cpm).

Baseline commit: `4c823f233aaa0d1f6d63f13b413003b8f09b4214`

Baseline description: `5.1.0-53-g4c823f233`

## Decision

django CMS is the best balance between reputation and realistic first-finding difficulty. At selection time it has approximately 10,700 stars and 3,200 forks, is governed by the nonprofit django CMS Association, directly publishes the `django-cms` PyPI package, and has an established private security contact and CVE history.

Strapi was considered for maximum recognition but rejected as too ambitious for this first third-party research project. Its large JavaScript/TypeScript monorepo, professional security process, strict production-mode reproduction rules, and frequent recent advisories create substantial setup, duplicate, and review-coverage risk. Wagtail was also rejected because it recently received an independent security audit covering the exact high-value areas this project would initially examine.

## Why django CMS remains a strong portfolio target

- Recognizable, mature Django CMS used in professional environments.
- Maintained through the django CMS Association, with active 2026 releases.
- Relevant first-party surface: page/plugin permissions, object-level authorization, frontend editing, rendering, caching, admin workflows, and extension boundaries.
- Private reports go to `security@django-cms.org`.
- CVE-2024-11319 demonstrates that the project can coordinate a public CVE and security fix.
- Recent security releases credit independent researchers for authorization findings.
- Large enough that a valid finding matters, but small enough to build a useful mental model of selected subsystems.

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
- [django CMS Association](https://www.django-cms.org/)
- [CVE-2024-11319](https://nvd.nist.gov/vuln/detail/CVE-2024-11319)
- [June 2026 security release](https://www.django-cms.org/en/blog/2026/06/10/django-cms-5-0-8-released-a-security-update-everyone-should-install/)
- [August 2026 security release](https://www.django-cms.org/resources/blog/2026/08/27/django-cms-5011-and-512-released/)

## Outcome

Manual review of the plugin move/copy authorization path identified an unscoped
client-controlled parent lookup. The issue was reproduced only in local test
databases, reported privately on 2026-09-03, confirmed by the django CMS
security team, fixed in releases 5.0.12 and 5.1.3, and disclosed on 2026-09-24.
The project credits `dannyg26` as Reporter. See the
[public case study](case-studies/GHSA-79vf-xh44-8cpm.md) for the technical and
disclosure timeline.
