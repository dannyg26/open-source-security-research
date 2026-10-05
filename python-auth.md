# Target shortlist

Historical discovery output from September 3, 2026. These entries are projects
considered for review, not confirmed findings. Prior CVEs describe their public
advisory histories at collection time, not CVEs discovered by this project.

Generated: 2026-09-03T18:41:40.512033+00:00

GitHub query: `auth in:name,description,topics language:Python stars:1000..20000 pushed:>=2026-03-04 archived:false fork:false is:public`

> Research aid only. A high score is not permission to test and is not evidence of a vulnerability.
> Review each project's security policy and bug-bounty scope before cloning or testing locally.

## Ranking

| Rank | Repository | Score | Stars | Forks | Dependents | Last push | Security policy | Prior CVEs | Package | Language | Description |
|---:|---|---:|---:|---:|---:|---|---|---:|---|---|---|
| 1 | [authlib/authlib](https://github.com/authlib/authlib) | 84.43 | 5410 | 561 | unknown | 2026-08-31 | [yes](https://github.com/authlib/authlib/blob/HEAD/.github/SECURITY.md) | 12 | PyPI:Authlib | Python | The ultimate Python library in building OAuth, OpenID Connect clients and servers. JWS, JWE, JWK, JWA, JWT included. |
| 2 | [Sophomoresty/gemini-web2api](https://github.com/Sophomoresty/gemini-web2api) | 79.58 | 3083 | 676 | unknown | 2026-08-14 | no | 0 | PyPI:gemini-web2api | Python | Convert Google Gemini web into OpenAI-compatible API. Zero auth, cross-platform, single file. |
| 3 | [supabase/supabase-py](https://github.com/supabase/supabase-py) | 75.71 | 2575 | 542 | unknown | 2026-09-03 | no | unknown | unknown | Python | Python Client for Supabase. Query Postgres from Flask, Django, FastAPI. Python user authentication, security policies, edge functions, file storage, and realtime data streaming. Good first issue. |
| 4 | [python-social-auth/social-app-django](https://github.com/python-social-auth/social-app-django) | 67.68 | 2143 | 392 | unknown | 2026-09-03 | no | 2 | PyPI:social-auth-app-django | Python | Python Social Auth - Application - Django |
| 5 | [mkhorasani/Streamlit-Authenticator](https://github.com/mkhorasani/Streamlit-Authenticator) | 64.42 | 2082 | 289 | unknown | 2026-07-01 | no | unknown | unknown | Python | A secure authentication module to manage user access in a Streamlit application. |

## Score details

Score = adoption 35 + maintenance 25 + disclosure readiness 15 + under-review signal 15 + health 10. Adoption uses log-scaled forks (70%) and stars (30%). Unknown OSV mapping receives a neutral under-review value, not a zero-advisory bonus.

1. **authlib/authlib** — adoption_35=34.3, maintenance_25=24.53, disclosure_15=15.0, under_review_15=0.6, health_10=10.0
2. **Sophomoresty/gemini-web2api** — adoption_35=34.31, maintenance_25=22.27, disclosure_15=0.0, under_review_15=15.0, health_10=8.0
3. **supabase/supabase-py** — adoption_35=33.26, maintenance_25=24.95, disclosure_15=0.0, under_review_15=7.5, health_10=10.0
4. **python-social-auth/social-app-django** — adoption_35=31.82, maintenance_25=24.96, disclosure_15=0.0, under_review_15=1.8, health_10=9.1
5. **mkhorasani/Streamlit-Authenticator** — adoption_35=30.65, maintenance_25=16.27, disclosure_15=0.0, under_review_15=7.5, health_10=10.0

## Data limitations

- GitHub's public REST API does not expose the repository UI's reverse-dependent count; `dependents` is therefore reported as unknown. Forks are the consistent adoption proxy.
- OSV history is queried only after deriving an ecosystem package name from a root manifest. `unknown` means mapping failed; it does not mean zero advisories.
- Counts describe known public advisories and can contain multiple records representing related advisories. The CVE count is deduplicated from CVE aliases.
