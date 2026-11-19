# `tdx.privilege_escalation.container_privileged_launch`

This **experimental hunt** rule observes agent shell tool requests that start a container with `--privileged`, host PID mode, broad capabilities, relaxed confinement, or the Docker socket mounted. It covers local daemons and remote daemons selected with global options such as `-H`, `--context` or `podman --remote`. It also observes `curl --unix-socket ...docker.sock`. Engine API requests over TCP are deliberately not part of this hunt, so requested read-only queries stay below the alert threshold. The companion alert covers host-reaching TCP create requests. It is low severity, score 20, and reads `tool.command` and `tool.arguments`.

## Evidence and interpretation

The [Docker run reference](https://docs.docker.com/reference/cli/docker/container/run/) documents privileged containers and namespace settings. The [Docker daemon security guidance](https://docs.docker.com/engine/security/protect-access/) documents the importance of daemon access. These options can enable host access, but the matched command **does not prove** a daemon accepted the request, that a container started, or that a sandbox boundary was crossed.

This rule intentionally does not alert by itself. Common authorized behavior includes Docker-in-Docker, KinD, Testcontainers and test helpers, eBPF tools, profiling, host monitoring, and Docker status queries. In particular, a read-only `curl --unix-socket ...docker.sock .../containers/json` is a hunt, not evidence of host compromise.

## Analyst use and limitations

Compare the user's request with the command, daemon privileges, selected capabilities, mounts and follow-on actions. When the companion host-access alert matches, investigate whether multiple rule score contributions describe the same command. The synthetic benign socket-mount scenario is intentionally `no_alert` even though this hunt rule matches.

No live Docker invocation is executed by test scenarios.

See [issue #7](https://github.com/Dark-Roast-Cyber/telltale-detections/issues/7) and the companion [host access alert](tdx.privilege_escalation.container_host_escape.md).

## Coverage limits

Coverage is limited to direct container launch and socket commands visible in `tool.command` and `tool.arguments`. Other daemon clients and transports, orchestration manifests, and indirect command construction are out of scope. Native file-write content is not guaranteed by those fields.

## Changes

- 2026-11-03: Added as an experimental rule, including the documented quoted host PID syntax.
- 2026-11-18: Covered remote daemons.
- 2026-11-18: Converted to Rule v2, Telltale's Sigma profile, with no change in behaviour.
