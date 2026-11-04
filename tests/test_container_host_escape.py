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
        self.assertIn("source=\\"$(pwd)\\",target=/host-tmp", virtiofs_command)
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
        self.assertIn("-v \\"/:/host:ro,rslave\\"", command)
        self.assertIsNotNone(pattern("tdx.privilege_escalation.container_host_escape").search(command))
        self.assertIsNotNone(pattern("tdx.privilege_escalation.container_privileged_launch").search(command))

    def assert_cases(self, rule: re.Pattern[str], positive: tuple[str, ...], negative: tuple[str, ...]) -> None:
        for command in positive:
            for value in (command, json.dumps(["bash", "-lc", command]), json.dumps({"cmd": command})):
                with self.subTest(pattern=rule.pattern, command=value):
                    self.assertIsNotNone(rule.search(value))
        for command in negative:
            for value in (command, json.dumps(["bash", "-lc", command]), json.dumps({"cmd": command})):
                with self.subTest(pattern=rule.pattern, command=value):
                    self.assertIsNone(rule.search(value))


if __name__ == "__main__":
    unittest.main()
