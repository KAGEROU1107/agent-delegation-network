# BUG-006 — GitHub Actions CI red X: `Post commit status` step fails the job

## Summary

Adding `gh api repos/.../statuses/$GITHUB_SHA` as a CI step (for badge visibility)
without `continue-on-error: true` caused the entire CI job to fail when the step failed.
The test suite was passing 33/33, but the badge showed a red X because the status-posting
step was the last step and it ran as part of the job's exit code chain.

## Date / Time

2026-06-11 (commits 1ced77d and 8f3831c)

## Environment

| Field | Value |
|---|---|
| OS | GitHub Actions ubuntu-latest |
| CI platform | GitHub Actions |
| Branch | main |
| Commits with red X | `1ced77d`, `8f3831c` |
| Fix commit | `0c7b10b` |

## Command Run

```yaml
# From .github/workflows/ci.yml (BEFORE fix)
- name: Post commit status
  if: always()
  run: |
    STATE=$([ "${{ job.status }}" = "success" ] && echo "success" || echo "failure")
    gh api repos/${{ github.repository }}/statuses/${{ github.sha }} \
      -f state="$STATE" \
      -f context="Tests" \
      -f description="pytest 33 negative security tests"
  env:
    GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

## Expected Result

Tests pass (33/33), CI job shows green. The `Post commit status` step is cosmetic
and should not affect the job result.

## Actual Result

GitHub Mobile showed a red X on the `main` branch. GitHub Actions run marked as
FAILURE despite all 33 tests passing. The `Post commit status` step failed (likely
due to `gh api` permissions or the statuses API endpoint behavior when the repo
was briefly private) and since it runs `if: always()` without `continue-on-error`,
it set the job's final exit code to failure.

## Error Summary

`Post commit status` step failed during CI run for commits `1ced77d` and `8f3831c`.
The step `if: always()` condition meant it ran even on success paths, but a failure
here overwrote the job result.

## Evidence

`evidence/bugs/BUG-006/`

GitHub Actions runs:
- Run 27357391040: `completed failure` — "Session 6 final proof" push
- Run 27356667500: `completed failure` — "CI: post commit status" push
- Run 27354842340: `completed success` — prior clean run (before status step added)

## Reproduction Steps

1. Add a `gh api .../statuses/...` step with `if: always()` but no `continue-on-error`
2. Push to main
3. Observe: tests pass but CI job shows failure if the status step fails

## Impact

Repository showed a red X in GitHub, misleading bounty judges that tests were failing.
Track 1 judging depends on visible CI health. A false red X undermines submission quality.

## Severity

**MEDIUM** — False negative: tests were passing but CI showed failure. Reputation impact
on bounty submission.

## Workaround / Fix

Add `continue-on-error: true` to the `Post commit status` step:

```yaml
- name: Post commit status
  if: always()
  continue-on-error: true   # ← this line
  run: |
    ...
```

The step still runs and attempts to post the status badge, but failure no longer
fails the overall job.

## Status

**FIXED** (commit `0c7b10b`)

## Notes for Terminal 3

N/A — this is a GitHub Actions configuration issue, not a T3N SDK issue.
