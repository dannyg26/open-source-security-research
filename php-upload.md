# Target shortlist

Generated: 2026-09-03T18:41:15.660663+00:00

GitHub query: `file upload in:name,description,topics language:PHP stars:1000..20000 pushed:>=2026-03-04 archived:false fork:false is:public`

> Research aid only. A high score is not permission to test and is not evidence of a vulnerability.
> Review each project's security policy and bug-bounty scope before cloning or testing locally.

## Ranking

| Rank | Repository | Score | Stars | Forks | Dependents | Last push | Security policy | Prior CVEs | Package | Language | Description |
|---:|---|---:|---:|---:|---:|---|---|---:|---|---|---|
| 1 | [UniSharp/laravel-filemanager](https://github.com/UniSharp/laravel-filemanager) | 83.97 | 2148 | 732 | unknown | 2026-08-09 | [yes](https://github.com/UniSharp/laravel-filemanager/blob/HEAD/docs/security.md) | 3 | Packagist:unisharp/laravel-filemanager | PHP | Media gallery with CKEditor, TinyMCE and Summernote support. Built on Laravel file system. |
| 2 | [dustin10/VichUploaderBundle](https://github.com/dustin10/VichUploaderBundle) | 79.00 | 1908 | 521 | unknown | 2026-08-20 | no | 0 | Packagist:vich/uploader-bundle | PHP | A simple Symfony bundle to ease file uploads with ORM entities and ODM documents. |
| 3 | [spatie/laravel-medialibrary](https://github.com/spatie/laravel-medialibrary) | 78.94 | 6163 | 1100 | unknown | 2026-09-03 | no | 2 | Packagist:spatie/laravel-medialibrary | PHP | Associate files with Eloquent models |

## Score details

Score = adoption 35 + maintenance 25 + disclosure readiness 15 + under-review signal 15 + health 10. Adoption uses log-scaled forks (70%) and stars (30%). Unknown OSV mapping receives a neutral under-review value, not a zero-advisory bonus.

1. **UniSharp/laravel-filemanager** — adoption_35=32.31, maintenance_25=21.55, disclosure_15=15.0, under_review_15=5.11, health_10=10.0
2. **dustin10/VichUploaderBundle** — adoption_35=30.98, maintenance_25=23.02, disclosure_15=0.0, under_review_15=15.0, health_10=10.0
3. **spatie/laravel-medialibrary** — adoption_35=35.0, maintenance_25=24.97, disclosure_15=0.0, under_review_15=11.42, health_10=7.55

## Data limitations

- GitHub's public REST API does not expose the repository UI's reverse-dependent count; `dependents` is therefore reported as unknown. Forks are the consistent adoption proxy.
- OSV history is queried only after deriving an ecosystem package name from a root manifest. `unknown` means mapping failed; it does not mean zero advisories.
- Counts describe known public advisories and can contain multiple records representing related advisories. The CVE count is deduplicated from CVE aliases.
