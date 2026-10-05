# django CMS authorization flaw: a coordinated-disclosure case study

- **Advisory:** [GHSA-79vf-xh44-8cpm](https://github.com/django-cms/django-cms/security/advisories/GHSA-79vf-xh44-8cpm)
- **Reporter:** [Danny Galvis (`dannyg26`)](https://github.com/dannyg26)
- **Published:** September 24, 2026
- **Severity:** Moderate, CVSS 3.1 score 5.5
- **Affected supported ranges:** `>= 5.0.0, < 5.0.12` and `>= 5.1.0, < 5.1.3`; the maintainer also reports the flaw existed from 3.0
- **Fixed:** 5.0.12 and 5.1.3
- **CVE:** No CVE ID listed in the advisory as of October 5, 2026

This case study records a confirmed vulnerability published under a GitHub
Security Advisory identifier. It does not claim a CVE assignment. The
[upstream advisory](https://github.com/django-cms/django-cms/security/advisories/GHSA-79vf-xh44-8cpm)
is the public source for affected versions, severity, impact, and reporter credit.

## Terms used below

- **Plugin:** a django CMS content block, which may contain other blocks.
- **Placeholder:** a content area holding a plugin tree.
- **Parent:** the containing plugin referenced by a child plugin.
- **Authorization:** checking that the editor is allowed to access or change each referenced object.

## Executive summary

During a source-first review of django CMS, I found that the `move-plugin`
administrative endpoint accepted a client-controlled `plugin_parent` identifier
without consistently constraining the referenced plugin to the authorized
destination placeholder and language.

A staff editor with legitimate control over one placeholder could reference a
plugin in a placeholder they were not allowed to access. The server returned
the restricted parent's rendered subtree and created an invalid plugin whose
parent belonged to another placeholder.

I reproduced the issue only in local test databases, reported it privately,
and coordinated with the django CMS security team. The maintainers independently
confirmed the authorization failure, expanded the affected-version analysis,
fixed the vulnerable and neighboring code paths, released patched versions, and
published the advisory with reporter credit.

## Why the code looked suspicious

The endpoint had two different trust models for the same client-supplied
identifier. One branch resolved the parent using its ID, target language, and
target placeholder. Other branches resolved it using only the primary key.

That inconsistency mattered because later checks covered the source plugin and
destination placeholder, but not the independently selected parent's
placeholder. Downstream code then used that parent both when copying the plugin
and when choosing the subtree rendered into the response.

This was not established by treating scanner output as a vulnerability. Static
analysis organized the initial review, but the finding came from manually
following attacker-controlled data through authorization checks, persistence,
and response rendering.

## Local verification

I wrote a regression-style test using only synthetic objects in an in-memory
database. The test created:

1. a limited staff editor with ordinary plugin permissions;
2. a source plugin and destination placeholder the editor controlled;
3. a separate restricted page containing a marked nested plugin subtree; and
4. a request naming the restricted plugin as `plugin_parent`.

The secure expectation was rejection, no new plugin, and no restricted marker
in the response. Instead, the request returned HTTP 200, created a plugin whose
placeholder and parent belonged to different trees, and returned the restricted
marker.

I reproduced this behavior on django CMS 5.0.11, 5.1.2, and the then-current
development revision. I also tested the minimal repair: resolving every supplied
parent inside the target placeholder and language blocked the reproduction, and
the 31 neighboring placeholder-admin tests passed.

No public django CMS deployment was accessed or tested.

These are historical research observations. The target-specific tests and
candidate patch remain in private research material and are not included here.
The public `tests/` suite checks the supporting scripts; it does not reproduce
this finding or run the 31 django CMS tests mentioned above.

## Impact and limits

The confirmed impact was:

- disclosure of rendered plugin content to an authenticated staff editor who
  lacked access to the referenced placeholder; and
- creation of a corrupt cross-placeholder plugin relationship.

The maintainers determined that the malformed child remains orphaned in the
attacker's placeholder because rendering groups children within one
placeholder. It therefore does not inject content into the victim page. There
is no anonymous attack path, and the attacker must already hold staff/plugin
permissions. These constraints are reflected in the advisory's Moderate rating
and CVSS vector `AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:L/A:N`.

## Coordinated remediation

I privately contacted the address in django CMS's security policy on September
3, 2026. The security team confirmed the report, reproduced it on `main`, and
classified it as a security-boundary violation.

Their history review found that the vulnerable behavior dated to 2013 and was
present from django CMS 3.0 onward. They applied the proposed parent scoping to
all relevant paths and fixed a neighboring transition that could create the
same cross-placeholder relationship without the permission bypass.

The project published django CMS 5.0.12 and 5.1.3 together with
GHSA-79vf-xh44-8cpm on September 24, 2026. Unsupported pre-5.0 lines remain
affected and should be upgraded. The advisory did not have a CVE ID at
publication, and still lists no CVE ID as of October 5, 2026.

## Lessons

- Compare sibling branches that resolve the same client-controlled object. A
  stricter query in one branch is often evidence of a missing invariant in
  another.
- Authorization must cover every referenced object, not only the primary source
  and destination objects.
- Trace a suspected authorization bypass through both the write and response
  paths. Here, the strongest impact was produced by response rendering, while
  the write impact was more limited than it initially appeared.
- State limitations explicitly. Ruling out anonymous access and victim-page
  injection made the report more accurate and easier to remediate.
- A minimal regression test and proposed invariant are more useful to
  maintainers than raw scanner output.

## Disclosure timeline

| Date | Event |
|---|---|
| 2026-09-03 | Selected django CMS, completed initial triage, and reproduced the issue locally. |
| 2026-09-03 | Sent the private report, regression test, and candidate fix. |
| 2026-09-08 | Security team confirmed the authorization violation and broader affected history. |
| 2026-09-24 | Fixed releases and GHSA-79vf-xh44-8cpm were published with reporter credit. |

## References

- [GitHub Security Advisory GHSA-79vf-xh44-8cpm](https://github.com/django-cms/django-cms/security/advisories/GHSA-79vf-xh44-8cpm)
- [django CMS repository](https://github.com/django-cms/django-cms)
- [django CMS security policy](https://github.com/django-cms/django-cms/security/policy)
