# `tdx.persistence.git_hook_change`

This candidate detects an agent setting `core.hooksPath` and a narrow direct-write form where searchable tool arguments contain both a `.git/hooks/<name>` path and shebang-bearing hook content. It evaluates Rule v1 `command` and `arguments`. A match proves that the recorded tool request contained a hook configuration or hook-program write pattern; it does not prove that a later Git operation executed the hook.

The bundled regex pack has no Git-hook or `core.hooksPath` rule. Its nearest persistence rule, `persistence.shell_profile`, covers shell profiles, cron, services, and launch agents rather than repository-triggered execution. The process-chain pack also does not add agent-command coverage for Git hook configuration.

Expected false positives include explicitly requested repository bootstrap, team-managed hooks, and hook-framework installation. Read-only `git config --get core.hooksPath` is a benign confounder and is outside the pattern. Capability limits include hook writes whose tool arguments omit content, hook programs without a shebang, writes through an unparsed script, and global configuration changes expressed through unsupported command forms. User intent and later hook execution require analyst context.
