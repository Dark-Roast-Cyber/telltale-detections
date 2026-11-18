# `tdx.privilege_escalation.container_host_escape`

This **experimental alert** identifies an agent tool request for container-mediated host access, not a confirmed sandbox escape. It matches any of these:

- A Docker Desktop-style `mount -t virtiofs <tag> <target>`.
- A `docker`/`podman`/`nerdctl run|create` with the host root (`/`) bind-mounted, including on a remote daemon selected with global options such as `-H`, `--context`, `--tlsverify` or `podman --remote`.
- `nsenter` targeting PID 1.
- A Docker Engine API `containers/create` request whose body sets `Privileged` to true or binds the host root through `Binds` or `Mounts`. The request can go over the Unix socket or an `http(s)` endpoint, from curl, wget, a Python one-liner or PowerShell.

It evaluates Rule v1 `command` and `arguments`, severity high, score 50.

## Evidence and rationale

- [Docker bind mounts](https://docs.docker.com/engine/storage/bind-mounts/) describes host files and directories exposed through a bind mount. Host root mounted read-only still exposes files; it is not evidence of modification.
- [Docker daemon attack surface](https://docs.docker.com/engine/security/protect-access/) explains why access to a Docker daemon is sensitive.
- [Docker run reference](https://docs.docker.com/reference/cli/docker/container/run/) documents privileged mode and host namespace options.
- [Pillar Security's multi-agent research](https://www.pillar.security/blog/one-docker-socket-to-rule-them-all-escaping-codex-cursor-and-gemini-clis-sandboxes) documents a Docker Desktop socket and virtiofs chain across coding agents; [Cursor advisory GHSA-v4xv-rqh3-w9mc](https://github.com/cursor/cursor/security/advisories/GHSA-v4xv-rqh3-w9mc) addresses one affected configuration. The report is threat motivation, not a claim that an arbitrary rule match exploited the sandbox.
- [Profero's Grok sandbox write-up](https://profero.io/blog/the-rootkit-built-into-grok-bot/) describes a probe of an unauthenticated Docker Engine API on TCP port 2375. The probe ran from a sandbox shell and was followed by a privileged container create. The write-up publishes the probe and the create response, but not the create body. It does not state that the requests were agent tool calls.
- [Docker remote access](https://docs.docker.com/engine/daemon/remote-access/) shows a daemon listening on `tcp://…:2375` and warns that remote access without TLS is not recommended.
- [Docker CLI global options](https://docs.docker.com/reference/cli/docker/) and [Podman global options](https://docs.podman.io/en/latest/markdown/podman.1.html) document `-H`, `-c`/`--context`, the `--tls*` options, `--remote`, `--connection` and `--url`.
- The [Engine API reference](https://docs.docker.com/reference/api/engine/version/v1.47/) defines `HostConfig.Binds`, `HostConfig.Privileged` and `HostConfig.Mounts[].{Type,Source,Target}`.

## Interpretation and false positives

Each rule match proves **only that the command or tool arguments contained a candidate host-access request**. Actual execution, daemon reachability, security boundaries, whether the host is a VM, and user authorization require analyst review. The same string is legitimate for incident response, a containerized host monitoring agent (including a read-only `-v /:/rootfs:ro`), or a deliberately configured VM's virtiofs share. Synthetic scores do not establish a production false-positive rate. The official [Prometheus node_exporter Docker deployment](https://github.com/prometheus/node_exporter#docker) uses `--pid="host"` and `-v "/:/host:ro,rslave"`. It **does match this high-severity rule** in normal authorized operation. `scenarios/benign/node_exporter_host_monitoring.json` deliberately preserves the independently benign `no_alert` expectation and is a known false-positive gate finding, not an argument to relabel the command as malicious. Review precision before any maturity promotion.

For a remote daemon, the host is the daemon's machine, which may not be the agent's. Requested CI or remote host maintenance can legitimately create privileged or host-root containers there, so compare the request with the user's ask. Read-only Engine API requests, such as `/version` or `/containers/json`, do not match this rule.

The companion hunt rule identifies preconditions such as `--privileged` or a socket mount at low severity. In one session, both rules may add risk along with a core shell rule. Do not interpret the combined score as proof of a second independent intrusion. For triage, check the original user request, the exact mount path, runtime context, and subsequent file operations.

## Validation and visibility

The independent scenarios include a published Docker Desktop virtiofs request, Linux host-root bind mount, a correctly shaped Docker API create request, the documented Testcontainers Ryuk daemon socket launch, a Prometheus host-monitoring false-positive case, and read-only documentation search. A native Compose file write is intentionally `not_evaluable` because `command` and `arguments` do not guarantee native write-content visibility.

The remote-daemon scenarios are two attacks and their benign twins:
- **Attack:** a TCP Engine API probe followed by a privileged host-root create.
- **Attack:** a host-root bind on a daemon selected with `-H` and `--tlsverify`.
- **Benign twin:** a requested read-only container listing over TCP.
- **Benign twin:** a requested remote test run that binds only the workspace.

Coverage is limited to the direct command forms listed above, as they appear in `command` and `arguments`, with the API endpoint and the create body in the same shell segment. Other container orchestration paths, other daemon transports, and indirect command or request construction are out of scope for this rule. No live escape or host filesystem operation is executed by the scenarios.

See [fixture provenance](container-fixture-provenance.md) for source-to-command mapping and platform assumptions. See [issue #7](https://github.com/Dark-Roast-Cyber/telltale-detections/issues/7) for research, synthetic engine replay, and pinned-gate history.
