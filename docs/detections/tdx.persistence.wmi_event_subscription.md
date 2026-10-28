# `tdx.persistence.wmi_event_subscription`

This candidate detects creation of a WMI permanent event subscription requested through an agent tool call: `Set-WmiInstance` or `New-CimInstance` naming `__EventFilter`, `CommandLineEventConsumer`, `ActiveScriptEventConsumer`, or `__FilterToConsumerBinding`; a `[wmiclass]` cast to one of those classes followed by `.CreateInstance`; and `wmic ... <class> create`. It evaluates the Rule v1 `command` and `arguments` fields, which prove the request, not that WMI stored the instance.

Telltale core rules have no WMI subscription rule. A complete subscription needs a filter, a consumer, and a binding; the rule matches any one of them, so a partial or failed attempt still matches.

Queries and removal do not match: `Get-WmiObject` and `Get-CimInstance` on the subscription classes, `Remove-CimInstance` in a pipeline, `wmic ... get`, and a documentation search that names the classes.

At the pinned revisions, both Codex `compatible` and OpenCode `upstream` record `detected` for `detection.windows_wmi_event_subscription` (`Set-WmiInstance` for a filter, a command-line consumer, and a binding) and `clean` for `detection.windows_persistence_read_only_audit` and `detection.windows_persistence_docs_search`. The `New-CimInstance`, `[wmiclass]`, and `wmic` forms are covered by pattern tests only.

Expected false positives are approved endpoint-management or monitoring software that registers subscriptions, and quoted command examples. Not covered: `mofcomp` with a MOF file, subscriptions created through the WMI COM API from a compiled program or a script whose contents are not in the searchable arguments, and consumer classes other than the command-line and script consumers.
