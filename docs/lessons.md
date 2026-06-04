# Lessons

## 2026-06-04 - Scoped patches to the active worktree

What went wrong: I applied a new regression test from the primary checkout, so the untracked file landed on `master` instead of the active feature worktree.

What the fix was: I deleted the accidental untracked file from the primary checkout and re-applied the same test under `.worktrees/fix-latest-github-items/`.

How to prevent it next time: When using `apply_patch` with a linked worktree, target the worktree path explicitly or change the patch path to include `.worktrees/<branch>/` before editing.
