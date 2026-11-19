# `tdx.persistence.git_hook_change`

This candidate detects an agent setting `core.hooksPath`, a narrow co-occurrence pattern where searchable tool arguments contain both a `.git/hooks/<name>` path and a shebang marker within 400 characters, and a file write whose target is a hook under `.git/hooks/` other than a `.sample` file. The first two branches read `tool.command` and `tool.arguments`; the write branch reads `tool.written_path`, which Telltale sets only for a write, patch or edit request. The co-occurrence branch does not require a write operation. A match proves only that the recorded tool request contained the configuration pattern, nearby hook-path and shebang text, or a hook write target, not that a hook was written or later executed.

The bundled regex pack has no Git-hook or `core.hooksPath` rule. Its nearest persistence rule, `persistence.shell_profile`, covers shell profiles, cron, services, and launch agents rather than repository-triggered execution. The process-chain pack also does not add agent-command coverage for Git hook configuration.

Expected false positives include explicitly requested repository bootstrap, team-managed hooks, and hook-framework installation. Read-only `git config --get core.hooksPath` is a benign confounder and is outside the pattern. The configuration branch also covers `--add` and `--replace-all` with local, global, or system scope. It requires horizontal whitespace and a value token that does not begin with a shell operator, redirection, or comment: `git config core.hooksPath || printf ...` is a query, not a write with `||` as its value. A following line is not treated as a value either. User intent and later hook execution require analyst context.

Read-only shebang inspection such as `grep '#!' .git/hooks/pre-commit` also matches the co-occurrence branch. The independently benign `detection.git_hook_shebang_query` scenario reports `false_positive` in both formats at the pinned assessment and the supplemental current-source assessment. The co-occurrence branch, severity high, score 50, and test maturity are unchanged; this finding does not justify broadening the rule to match a hook path that is only read or mentioned.

Telltale no longer reads text that a patch, write or edit only authors as command or argument text, so the co-occurrence branch does not see a hook file's content when the agent writes it. The write branch covers that case through the write target instead, and does not depend on the content. At the pinned assessment, the direct hook-file write in `detection.git_hook_program_write` is detected from both Codex `compatible` and OpenCode `upstream`, and the benign Git hook scenarios stay as they were. Hook reads and text that only mentions a hook path have no write target and do not match the write branch.

## Coverage limits

Coverage is limited to the configuration and co-occurrence forms above as they appear in `tool.command` and `tool.arguments`, and to hook writes whose target Telltale records as `tool.written_path`. Hook writes made through commands or scripts rather than a write tool, other ways of configuring or installing hooks, and indirect script or command construction are out of scope for this rule.

## Changes

- 2026-10-13: Added as an experimental rule.
- 2026-10-20: Promoted to `test` and shipped in the community package.
- 2026-10-23: Matched configuration writes more precisely and stopped alerting on read-only queries with shell fallbacks.
- 2026-11-18: Converted to Rule v2, Telltale's Sigma profile, with no change in behaviour.
- 2026-11-18: Added the write branch on `tool.written_path`, so a hook file written through a write, patch or edit tool matches again after Telltale stopped reading authored content as argument text; the explanation now names hook writes.
