# `tdx.privilege_escalation.container_host_escape`

This **experimental alert** identifies an agent tool request for container-mediated host access, not a confirmed sandbox escape. It matches a Docker Desktop-style `mount -t virtiofs <tag> <target>`, a `docker`/`podman`/`nerdctl run|create` with the host root (`/`) bind-mounted, `nsenter` targeting PID 1, or a curl Docker Unix-socket request with privileged or host-root creation fields. It evaluates Rule v1 `command` and `arguments`, severity high, score 50.

## Evidence and rationale

- [Docker bind mounts](https://docs.docker.com/engine/storage/bind-mounts/) describes host files and directories exposed through a bind mount. Host root mounted read-only still exposes files; it is not evidence of modification.
- [Docker daemon attack surface](https://docs.docker.com/engine/security/protect-access/) explains why access to a Docker daemon is sensitive.
- [Docker run reference](https://docs.docker.com/reference/cli/docker/container/run/) documents privileged mode and host namespace options.
- [Pillar Security's multi-agent research](https://www.pillar.security/blog/one-docker-socket-to-rule-them-all-escaping-codex-cursor-and-gemini-clis-sandboxes) documents a Docker Desktop socket and virtiofs chain across coding agents; [Cursor advisory GHSA-v4xv-rqh3-w9mc](https://github.com/cursor/cursor/security/advisories/GHSA-v4xv-rqh3-w9mc) addresses one affected configuration. The report is threat motivation, not a claim that an arbitrary rule match exploited the sandbox.

## Interpretation and false positives

Each rule match proves **only that the command or tool arguments contained a candidate host-access request**. Actual execution, daemon reachability, security boundaries, whether the host is a VM, and user authorization require analyst review. The same string is legitimate for incident response, a containerized host monitoring agent (including a read-only `-v /:/rootfs:ro`), or a deliberately configured VM's virtiofs share. Synthetic scores do not establish a production false-positive rate. The official [Prometheus node_exporter Docker deployment](https://github.com/prometheus/node_exporter#docker) uses `--pid="host"` and `-v "/:/host:ro,rslave"`. It **does match this high-severity rule** in normal authorized operation. `scenarios/benign/node_exporter_host_monitoring.json` deliberately preserves the independently benign `no_alert` expectation and is a known false-positive gate finding, not an argument to relabel the command as malicious. Review precision before any maturity promotion.

The companion hunt rule identifies preconditions such as `--privileged` or a socket mount at low severity. In one session, both rules may add risk along with a core shell rule. Do not interpret the combined score as proof of a second independent intrusion. For triage, check the original user request, the exact mount path, runtime context, and subsequent file operations.

## Validation and visibility

The independent scenarios include a published Docker Desktop virtiofs request, Linux host-root bind mount, a correctly shaped Docker API create request, the documented Testcontainers Ryuk daemon socket launch, a Prometheus host-monitoring false-positive case, and read-only documentation search. A native Compose file write is intentionally `not_evaluable` because `command` and `arguments` do not guarantee native write-content visibility.

Known gaps: non-root host mounts (e.g. `/etc`), `docker compose` and Kubernetes manifest changes, Docker TCP endpoints or non-curl API clients, aliases/variables/heredocs, Windows Docker named pipes, and alternate `mount` operand ordering. No live escape or host filesystem operation is executed by the scenarios.

See [fixture provenance](container-fixture-provenance.md) for source-to-command mapping and platform assumptions. See [issue #7](https://github.com/Dark-Roast-Cyber/telltale-detections/issues/7) for research, synthetic engine replay, and pinned-gate history.
