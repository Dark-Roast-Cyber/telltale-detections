"""Focused pattern regression checks for container host-access community rules.

These checks do not replace pinned parser-to-event assessment.
"""
import json
import re
import shlex
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACK = ROOT / "packs/experimental/container-host-escape.yaml"
REMOTE = "docker-host.invalid"


def pattern(rule_id: str) -> re.Pattern[str]:
    lines = PACK.read_text(encoding="utf-8").splitlines()
    lines = lines[lines.index(f"  - id: {rule_id}"):]
    line = next(value for value in lines if value.startswith("    regex: "))
    assert line.startswith("    regex: '") and line.endswith("'")
    return re.compile(line[len("    regex: '"):-1].replace("''", "'"), re.IGNORECASE)


class ContainerHostAccessTests(unittest.TestCase):
    def test_host_access_requests(self) -> None:
        rule = pattern("tdx.privilege_escalation.container_host_escape")
        positive = (
            "docker exec helper sh -c 'mkdir -p /root/mac-home && mount -t virtiofs virtiofs0 /root/mac-home'",
            "docker run --rm -v /:/host:ro alpine:3.20 ls /host",
            "podman container create --mount type=bind,source=/,target=/host alpine",
            'nsenter --target 1 --mount --uts --net --pid -- sh -c "cat /etc/hostname"',
            """curl -sfS --unix-socket /var/run/docker.sock -X POST -H 'Content-Type: application/json' http://localhost/containers/create -d '{"Image":"alpine:3.20","Cmd":["ls","/host"],"HostConfig":{"Binds":["/:/host:ro"],"Privileged":true,"PidMode":"host","NetworkMode":"host","IpcMode":"host"}}'""",
        )
        negative = (
            "docker run --rm -v /workspace:/work alpine true",
            "docker run --rm --privileged -v /workspace:/work alpine true",
            "docker run -d -v /var/run/docker.sock:/var/run/docker.sock -p 127.0.0.1:8080:8080 testcontainers/ryuk:latest",
            "curl --unix-socket /var/run/docker.sock http://localhost/containers/json",
            "rg -n 'mount -t virtiofs|--privileged|-v /:/host' docs/",
        )
        self.assert_cases(rule, positive, negative)

    def test_privileged_prerequisites(self) -> None:
        rule = pattern("tdx.privilege_escalation.container_privileged_launch")
        positive = (
            "docker run --rm --privileged alpine true",
            "docker run --pid=host alpine:3.20 true",
            'docker run --pid="host" alpine:3.20 true',
            'docker run --pid=\\"host\\" alpine:3.20 true',
            "podman run --cap-add=SYS_ADMIN alpine true",
            "docker run --security-opt seccomp=unconfined alpine true",
            "docker run -d -v /var/run/docker.sock:/var/run/docker.sock -p 127.0.0.1:8080:8080 testcontainers/ryuk:latest",
            "curl --unix-socket /var/run/docker.sock http://localhost/containers/json",
        )
        negative = (
            "docker run --rm -v /workspace:/work alpine true",
            "docker run --rm -v /:/host:ro alpine ls /host",
            "rg -n 'mount -t virtiofs|--privileged|-v /:/host' docs/",
            "docker ps",
            "docker run --pid=hostname alpine:3.20 true",
        )
        self.assert_cases(rule, positive, negative)

    def test_published_scenario_primitives(self) -> None:
        """Guard against drifting back to made-up images, APIs or incomplete commands."""
        scenarios = ROOT / "scenarios"

        def fixture(relative_path: str) -> dict:
            return json.loads((scenarios / relative_path).read_text(encoding="utf-8"))

        virtiofs = fixture("adversarial/docker_desktop_virtiofs_escape.json")
        virtiofs_command = virtiofs["steps"][1]["command"]
        self.assertIn("--privileged", virtiofs_command)
        self.assertIn('source="$(pwd)",target=/host-tmp', virtiofs_command)
        self.assertLess(virtiofs_command.index("mkdir -p /root/mac-home"),
                        virtiofs_command.index("mount -t virtiofs virtiofs0 /root/mac-home"))

        api = fixture("adversarial/docker_api_privileged_create.json")
        api_args = shlex.split(api["steps"][1]["command"])
        self.assertIn("--unix-socket", api_args)
        self.assertEqual(api_args[api_args.index("--unix-socket") + 1], "/var/run/docker.sock")
        self.assertIn("http://localhost/containers/create", api_args)
        self.assertIn("-d", api_args)
        body = json.loads(api_args[api_args.index("-d") + 1])
        self.assertEqual(body["Image"], "alpine:3.20")
        self.assertEqual(body["Cmd"], ["ls", "/host"])
        self.assertTrue(body["HostConfig"]["Privileged"])
        self.assertIn("/: /host:ro".replace(" ", ""), body["HostConfig"]["Binds"])
        self.assertEqual(body["HostConfig"]["PidMode"], "host")

        root_bind = fixture("adversarial/docker_socket_host_root_mount.json")
        self.assertIn("-v /:/host:ro alpine:3.20", root_bind["steps"][1]["command"])

        ryuk = fixture("benign/testcontainers_socket_mount.json")
        ryuk_command = ryuk["steps"][1]["command"]
        self.assertIn("-v /var/run/docker.sock:/var/run/docker.sock", ryuk_command)
        self.assertIn("testcontainers/ryuk:latest", ryuk_command)
        self.assertIn("-p 127.0.0.1:8080:8080", ryuk_command)

        compose = fixture("visibility-limited/compose_privileged_file_write.json")
        compose_text = compose["steps"][1]["content"]
        self.assertIn("privileged: true", compose_text)
        self.assertIn("- /:/host", compose_text)

    def test_official_host_monitoring_is_known_alert_false_positive(self) -> None:
        """Prometheus's documented, authorized node_exporter launch also matches the alert."""
        fixture = json.loads(
            (ROOT / "scenarios/benign/node_exporter_host_monitoring.json").read_text(encoding="utf-8")
        )
        self.assertEqual(fixture["disposition"], "benign")
        self.assertEqual(fixture["review"]["expectation"], "no_alert")
        command = fixture["steps"][1]["command"]
        self.assertIn("quay.io/prometheus/node-exporter:latest", command)
        self.assertIn('-v "/:/host:ro,rslave"', command)
        self.assertIsNotNone(pattern("tdx.privilege_escalation.container_host_escape").search(command))
        self.assertIsNotNone(pattern("tdx.privilege_escalation.container_privileged_launch").search(command))

    def test_remote_daemon_and_engine_api_host_access(self) -> None:
        rule = pattern("tdx.privilege_escalation.container_host_escape")
        positive = (
            f"""curl -s -X POST -H 'Content-Type: application/json' http://{REMOTE}:2375/v1.45/containers/create -d '{{"Image":"alpine:3.20","Cmd":["ls","/host"],"HostConfig":{{"Binds":["/:/host:ro"],"Privileged":true}}}}'""",
            f"""curl -sS --cacert ca.pem --cert cert.pem --key key.pem -X POST https://{REMOTE}:2376/containers/create -H 'Content-Type: application/json' -d '{{"Image":"alpine:3.20","HostConfig":{{"Privileged":true}}}}'""",
            f"""curl -s -X POST 'http://{REMOTE}:8375/containers/create?name=probe' -H 'Content-Type: application/json' -d '{{"Image":"alpine:3.20","HostConfig":{{"Mounts":[{{"Type":"bind","Source":"/","Target":"/host"}}]}}}}'""",
            f"""wget -qO- --header='Content-Type: application/json' --post-data='{{"Image":"alpine:3.20","HostConfig":{{"Binds":["/:/host"]}}}}' http://{REMOTE}:2375/containers/create""",
            f"""python3 -c "import requests; print(requests.post('http://{REMOTE}:2375/containers/create', json={{'Image': 'alpine:3.20', 'HostConfig': {{'Privileged': True}}}}).status_code)\"""",
            f"""powershell -NoProfile -Command "Invoke-RestMethod -Method Post -Uri http://{REMOTE}:2375/containers/create -ContentType application/json -Body '{{\\"Image\\":\\"alpine:3.20\\",\\"HostConfig\\":{{\\"Privileged\\":true}}}}'\"""",
            """curl --unix-socket /var/run/docker.sock -X POST -H 'Content-Type: application/json' http://localhost/containers/create -d '{"Image":"alpine:3.20","HostConfig":{"Mounts":[{"Type":"bind","Source":"/","Target":"/host","ReadOnly":true}]}}'""",
            f"docker -H tcp://{REMOTE}:2375 run --rm -v /:/host alpine:3.20 ls /host",
            f"docker --tlsverify -H=tcp://{REMOTE}:2376 container create --mount type=bind,source=/,target=/host alpine:3.20",
            "docker --context remote run --rm -v /:/host alpine:3.20 true",
            "docker --log-level debug -c remote run -v /:/host alpine:3.20 true",
            "podman --remote run --rm -v /:/host alpine:3.20 true",
            "podman --connection=ci run --rm --volume=/:/host alpine:3.20 true",
            "nerdctl --namespace k8s.io run --rm -v /:/host alpine:3.20 true",
        )
        negative = (
            f"curl -s -o /dev/null -w '%{{http_code}}\\n' http://{REMOTE}:2375/version",
            f"curl -s 'http://{REMOTE}:2375/containers/json?all=1'",
            f"""curl -s -X POST -H 'Content-Type: application/json' http://{REMOTE}:2375/containers/create -d '{{"Image":"alpine:3.20","HostConfig":{{"Binds":["/workspace/demo:/work"],"Privileged":false}}}}'""",
            """rg -n '"Privileged": true' docs/api/containers/create.md""",
            "rg -n 'containers/create|Privileged|2375' docs/",
            f"docker -H tcp://{REMOTE}:2375 ps",
            f"docker -H tcp://{REMOTE}:2376 --tlsverify run --rm -v /workspace/demo:/work -w /work golang:1.23 go test ./...",
            f"DOCKER_HOST=tcp://{REMOTE}:2375 docker run --rm -v /workspace/demo:/work alpine:3.20 true",
            """kubectl run probe --image=alpine:3.20 --overrides='{"spec":{"containers":[{"name":"probe","image":"alpine:3.20","securityContext":{"privileged":true}}]}}'""",
            """curl -s -X POST https://api.example/v1/jobs -d '{"privileged":false,"source":"/"}'""",
            "docker-compose -f ci.yml run --rm tests",
            f"curl -s http://{REMOTE}:2375/containers/json; rg -n '\"Privileged\": true' docs/",
        )
        self.assert_cases(rule, positive, negative)

    def test_remote_daemon_privileged_prerequisites(self) -> None:
        rule = pattern("tdx.privilege_escalation.container_privileged_launch")
        positive = (
            f"docker -H tcp://{REMOTE}:2375 run --rm --privileged alpine:3.20 true",
            "podman --remote run --cap-add=SYS_ADMIN alpine:3.20 true",
            "docker --context remote run --pid=host alpine:3.20 true",
        )
        negative = (
            f"curl -s 'http://{REMOTE}:2375/containers/json?all=1'",
            f"curl -s -o /dev/null -w '%{{http_code}}\\n' http://{REMOTE}:2375/version",
            f"docker -H tcp://{REMOTE}:2375 run --rm -v /workspace/demo:/work alpine:3.20 true",
        )
        self.assert_cases(rule, positive, negative)

    def test_remote_daemon_fixtures(self) -> None:
        """Keep the remote-daemon fixtures on documented API fields and global options."""
        def fixture(relative_path: str) -> dict:
            return json.loads((ROOT / "scenarios" / relative_path).read_text(encoding="utf-8"))

        api = fixture("adversarial/docker_tcp_api_privileged_create.json")
        probe = shlex.split(api["steps"][1]["command"])
        self.assertEqual(probe[-1], f"http://{REMOTE}:2375/version")
        create = shlex.split(api["steps"][2]["command"])
        self.assertIn(f"http://{REMOTE}:2375/v1.45/containers/create", create)
        body = json.loads(create[create.index("-d") + 1])
        self.assertEqual(body["Image"], "alpine:3.20")
        self.assertTrue(body["HostConfig"]["Privileged"])
        self.assertIn("/:/host:ro", body["HostConfig"]["Binds"])

        remote = shlex.split(fixture("adversarial/docker_remote_daemon_host_root_run.json")["steps"][1]["command"])
        self.assertEqual(remote[:4], ["docker", "-H", f"tcp://{REMOTE}:2376", "--tlsverify"])
        self.assertEqual(remote[4], "run")
        self.assertIn("/:/host:ro", remote)

        listing = fixture("benign/docker_tcp_api_container_list.json")["steps"][1]["command"]
        self.assertIn(f"http://{REMOTE}:2375/containers/json?all=1", listing)

        workspace = shlex.split(fixture("benign/docker_remote_daemon_workspace_run.json")["steps"][1]["command"])
        self.assertEqual(workspace[:5], ["docker", "-H", f"tcp://{REMOTE}:2376", "--tlsverify", "run"])
        self.assertIn("/workspace/demo:/work", workspace)

    def assert_cases(self, rule: re.Pattern[str], positive: tuple[str, ...], negative: tuple[str, ...]) -> None:
        for command in positive:
            for value in serializations(command):
                with self.subTest(pattern=rule.pattern, command=value):
                    self.assertIsNotNone(rule.search(value))
        for command in negative:
            for value in serializations(command):
                with self.subTest(pattern=rule.pattern, command=value):
                    self.assertIsNone(rule.search(value))


def serializations(command: str) -> tuple[str, ...]:
    """Raw text, a bash -lc array, a {"cmd"} object, and a Codex {"command": [...]} object."""
    return (
        command,
        json.dumps(["bash", "-lc", command]),
        json.dumps({"cmd": command}),
        json.dumps({"command": ["bash", "-lc", command], "workdir": "/workspace/demo"}),
    )


if __name__ == "__main__":
    unittest.main()
