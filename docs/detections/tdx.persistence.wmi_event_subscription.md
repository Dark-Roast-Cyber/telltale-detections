# `tdx.persistence.wmi_event_subscription`

This candidate detects creation of a WMI permanent event subscription requested through an agent tool call: `Set-WmiInstance` or `New-CimInstance` whose class (the `-Class` / `-ClassName` value or the first positional argument) is `__EventFilter`, `CommandLineEventConsumer`, `ActiveScriptEventConsumer`, or `__FilterToConsumerBinding`; a `[wmiclass]` cast to one of those classes followed by `.CreateInstance`; and `wmic ... <class> create`, with the class quoted or not. The class parameter may follow one `@{...}` hashtable argument. It reads the `tool.command` and `tool.arguments` fields, which prove the request, not that WMI stored the instance.

Telltale core rules have no WMI subscription rule. A complete subscription needs a filter, a consumer, and a binding; the rule matches any one of them, so a partial or failed attempt still matches.

Queries and removal do not match: `Get-WmiObject` and `Get-CimInstance` on the subscription classes, `Remove-CimInstance` in a pipeline, `wmic ... get`, and a documentation search that names the classes. A subscription class named only as a property value of another class does not match. The bounded windows stop at a pipe, `;` outside the one hashtable, `&`, or line break, so `Get-Help Set-WmiInstance -Full; Get-CimInstance ... -ClassName __EventFilter` does not match; in the serialized `arguments` field an escaped `\n` does not end a window.

At the pinned revisions, both Codex `compatible` and OpenCode `upstream` record `detected` for `detection.windows_wmi_event_subscription` (`Set-WmiInstance` for a filter, a command-line consumer, and a binding) and `clean` for `detection.windows_persistence_read_only_audit` and `detection.windows_persistence_docs_search`. The `New-CimInstance`, `[wmiclass]`, and `wmic` forms are covered by pattern tests only.

Expected false positives are approved endpoint-management or monitoring software that registers subscriptions, quoted command examples, and `-WhatIf` previews, which the rule's pattern cannot exclude.

## Coverage limits

Coverage is limited to the creation forms above as they appear in `tool.command` and `tool.arguments`. Other parameter-passing styles, other ways of registering a subscription, such as compiled definitions or programmatic interfaces, other consumer classes, and indirect command construction are out of scope for this rule.

## Changes

- 2026-10-28: Added at `test` maturity; argument windows and ends tightened after review.
- 2026-11-18: Converted to Rule v2, Telltale's Sigma profile, with no change in behaviour.
