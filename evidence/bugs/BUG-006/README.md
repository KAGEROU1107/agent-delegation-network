# BUG-006 Evidence — GitHub Actions CI red X from Post commit status step

## Affected GitHub Actions runs

| Run ID | Conclusion | Commit | Note |
|---|---|---|---|
| 27357391040 | FAILURE | 8f3831c | Tests passed; status step failed the job |
| 27356667500 | FAILURE | 1ced77d | Tests passed; status step failed the job |
| 27354842340 | SUCCESS | 9c9349f | Before status step was added |
| 27351120825 | SUCCESS | eaaaa60 | Before status step was added |

## Root cause

The `Post commit status` step used `if: always()` without `continue-on-error: true`.
When `gh api .../statuses/$GITHUB_SHA` failed (likely a permissions/endpoint issue),
the step set the job's exit code to failure, overriding the passing test result.

## Fix

Commit `0c7b10b` added `continue-on-error: true` to the step.

```yaml
- name: Post commit status
  if: always()
  continue-on-error: true   # prevents step failure from failing the job
```

## Related

- `docs/bugs/BUG-006-ci-post-commit-status-red-x.md`
- `.github/workflows/ci.yml`
