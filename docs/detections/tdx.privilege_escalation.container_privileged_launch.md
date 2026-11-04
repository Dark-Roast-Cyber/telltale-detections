# `tdx.privilege_escalation.container_privileged_launch`

This **experimental hunt** rule observes agent shell tool requests that start a container with `--privileged`, host PID mode, broad capabilities, relaxed confinement, or the Docker socket mounted; it also observes `curl --unix-socket ...docker.sock`. It is low severity, score 20, and targets Rule v1 `command` and `arguments`.

## Evidence and interpretation

The [Docker run reference](https://docs.docker.com/reference/cli/docker/container/run/) documents privileged containers and namespace settings. The [Docker daemon security guidance](https://docs.docker.com/engine/security/protect-access/) documents the importance of daemon access. These options can enable host access, but the matched command **does not prove** a daemon accepted the request, that a container started, or that a sandbox boundary was crossed.

This rule intentionally does not alert by itself. Common authorized behavior includes Docker-in-Docker, KinD, Testcontainers and test helpers, eBPF tools, profiling, host monitoring, and Docker status queries. In particular, a read-only `curl --unix-socket ...docker.sock .../containers/json` is a hunt, not evidence of host compromise.

## Analyst use and limitations

Compare the user's request with the command, daemon privileges, selected capabilities, mounts and follow-on actions. When the companion host-access alert matches, investigate whether multiple rule score contributions describe the same command. The synthetic benign socket-mount scenario is intentionally `no_alert` even though this hunt rule matches.

Known gaps include non-curl Docker clients, TCP Docker API endpoints, Compose and Kubernetes manifests without a visible shell command, embedded scripts, aliases and indirect environment-variable expansion. Native file-write content is not guaranteed by Rule v1 `command`/`arguments` targets. No live Docker invocation is executed by test scenarios.

See [issue #7](https://github.com/Dark-Roast-Cyber/telltale-detections/issues/7) and the companion [host access alert](tdx.privilege_escalation.container_host_escape.md).
