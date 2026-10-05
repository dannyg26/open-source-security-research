# Target shortlist

Historical discovery output from September 3, 2026. These entries are projects
considered for review, not confirmed findings. Prior CVEs describe their public
advisory histories at collection time, not CVEs discovered by this project.

Generated: 2026-09-03T18:41:02.398169+00:00

GitHub query: `cms in:name,description,topics language:JavaScript stars:1000..20000 pushed:>=2026-03-04 archived:false fork:false is:public`

> Research aid only. A high score is not permission to test and is not evidence of a vulnerability.
> Review each project's security policy and bug-bounty scope before cloning or testing locally.

## Ranking

| Rank | Repository | Score | Stars | Forks | Dependents | Last push | Security policy | Prior CVEs | Package | Language | Description |
|---:|---|---:|---:|---:|---:|---|---|---:|---|---|---|
| 1 | [mediacms-io/mediacms](https://github.com/mediacms-io/mediacms) | 93.68 | 5093 | 953 | unknown | 2026-08-25 | [yes](https://github.com/mediacms-io/mediacms/blob/HEAD/SECURITY.md) | 0 | npm:mediacms | JavaScript | MediaCMS is a modern, fully featured open source video and media CMS, written in Python/Django and React, featuring a REST API. |
| 2 | [decaporg/decap-cms](https://github.com/decaporg/decap-cms) | 92.47 | 19340 | 3125 | unknown | 2026-09-03 | [yes](https://github.com/decaporg/decap-cms/blob/HEAD/SECURITY.md) | unknown | unknown | JavaScript | A Git-based CMS for Static Site Generators |
| 3 | [doramart/DoraCMS](https://github.com/doramart/DoraCMS) | 86.31 | 3542 | 1033 | unknown | 2026-07-12 | [yes](https://github.com/doramart/DoraCMS/blob/HEAD/SECURITY.md) | 0 | npm:egg-cms | JavaScript | DoraCMS 是一个基于 EggJS 3.x + Vue 3 + TypeScript 的现代化内容管理系统，采用 pnpm monorepo 架构管理。它不仅仅是一个 CMS 系统，更是一个优秀的企业级应用架构实践。 |
| 4 | [apostrophecms/apostrophe](https://github.com/apostrophecms/apostrophe) | 69.59 | 4613 | 649 | unknown | 2026-09-03 | no | 0 | npm:@apostrophecms | JavaScript | A full-featured, open-source content management framework built with Node.js that empowers organizations by combining in-context editing and headless architecture in a full-stack JS environment. |
| 5 | [logamee/lin-cms-vue](https://github.com/logamee/lin-cms-vue) | 56.34 | 2839 | 652 | unknown | 2026-05-04 | no | 0 | npm:lin-cms-vue | JavaScript |  🔆 Vue+ElementPlus构建的CMS开发框架 |

## Score details

Score = adoption 35 + maintenance 25 + disclosure readiness 15 + under-review signal 15 + health 10. Adoption uses log-scaled forks (70%) and stars (30%). Unknown OSV mapping receives a neutral under-review value, not a zero-advisory bonus.

1. **mediacms-io/mediacms** — adoption_35=29.97, maintenance_25=23.74, disclosure_15=15.0, under_review_15=14.97, health_10=10.0
2. **decaporg/decap-cms** — adoption_35=35.0, maintenance_25=24.97, disclosure_15=15.0, under_review_15=7.5, health_10=10.0
3. **doramart/DoraCMS** — adoption_35=29.83, maintenance_25=17.68, disclosure_15=15.0, under_review_15=15.0, health_10=8.8
4. **apostrophecms/apostrophe** — adoption_35=28.69, maintenance_25=25.0, disclosure_15=0.0, under_review_15=10.9, health_10=5.0
5. **logamee/lin-cms-vue** — adoption_35=28.19, maintenance_25=8.31, disclosure_15=0.0, under_review_15=9.84, health_10=10.0

## Data limitations

- GitHub's public REST API does not expose the repository UI's reverse-dependent count; `dependents` is therefore reported as unknown. Forks are the consistent adoption proxy.
- OSV history is queried only after deriving an ecosystem package name from a root manifest. `unknown` means mapping failed; it does not mean zero advisories.
- Counts describe known public advisories and can contain multiple records representing related advisories. The CVE count is deduplicated from CVE aliases.
