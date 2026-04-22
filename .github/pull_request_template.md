<!--
Before you open this PR, please read CONTRIBUTING.md.
PRs that skip the issue-first flow or don't address an acceptance criterion
will be closed with a pointer back to the guidelines.
-->

## Linked issue

Closes #<!-- issue number -->

<!-- If there is no linked issue, explain why a PR is appropriate here.
     Most non-trivial changes need an issue + discussion first. -->

## Summary

<!-- What changed and why. Not a re-statement of the diff.
     Focus on the "why" — the diff already shows the "what". -->

-
-

## Test plan

<!-- How a reviewer can verify this locally. Be specific. -->

- [ ] `uv run pytest` — all tests pass
- [ ] `uv run ruff check` — clean
- [ ] `uv run ruff format --check` — clean
- [ ]

## Checklist

- [ ] Commit message follows [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`, `test:`, `chore:`, etc.)
- [ ] Single commit (rebased/squashed before review)
- [ ] Tests added or updated for behavior changes
- [ ] No unrelated changes sneaking in
