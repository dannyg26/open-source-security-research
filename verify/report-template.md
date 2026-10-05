# Private vulnerability report: [concise title]

> Keep this report private until the maintainer agrees it can be disclosed or a coordinated fix is public.

## Summary

[What security boundary fails, without overstating impact.]

## Target and affected versions

- Project/repository:
- Tested commit:
- Tested release:
- Confirmed affected versions:
- Confirmed unaffected/fixed versions:

## Preconditions and threat model

- Required attacker access or role:
- Required victim action:
- Required configuration:
- Local test environment:

## Reproduction

1. [Build/start the maintainer's project locally.]
2. [Create only the accounts/data needed for the test.]
3. [Make the baseline request.]
4. [Make the changed request.]
5. [Record the observed security-boundary failure.]

Expected result:

[Expected secure behavior.]

Actual result:

[Observed behavior, with secrets and personal data removed.]

## Impact

[Concrete confidentiality, integrity, or availability impact and its limits.]

## Evidence / minimal PoC

```python
# Smallest local-only reproducer. Do not publish before a coordinated fix.
```

## Root cause

- File/function:
- Relevant control flow:
- Why the existing check is insufficient:

## Suggested fix

[A narrow remediation idea; let maintainers choose the final design.]

## Disclosure timeline

- YYYY-MM-DD: Found in local testing.
- YYYY-MM-DD: Privately reported via [channel].
- YYYY-MM-DD: [Response/update].

## Researcher contact and credit preference

- Contact:
- Preferred credit:
- Advisory credit preference:
- CVE attribution preference (if a CVE is assigned):
