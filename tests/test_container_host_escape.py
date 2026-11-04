"""Focused pattern regression checks for container host-access community rules.

These checks do not replace pinned parser-to-event assessment.
"""
import json
import re
import unittest
from pathlib import Path

PACK = Path(__file__).resolve().parents[1] / "packs/experimental/container-host-escape.yaml"


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
            "docker exec helper sh -c 'mount -t virtiofs virtiofs0 /mnt/host'",
            "docker run --rm -v /:/host:ro alpine ls /host",
            "podman container create --mount type=bind,source=/,target=/host alpine",
            "nsenter --target 1 --mount --uts --net --pid -- sh",
            """curl --unix-socket /var/run/docker.sock -X POST -d '{"HostConfig":{"Binds":["/:/host"],"Privileged":true}}' http://localhost/containers/create""",
        )
        negative = (
            "docker run --rm -v /workspace:/work alpine true",
            "docker run --rm --privileged -v /workspace:/work alpine true",
            "docker run -v /var/run/docker.sock:/var/run/docker.sock synthetic-helper true",
            "curl --unix-socket /var/run/docker.sock http://localhost/containers/json",
            "rg -n 'mount -t virtiofs|--privileged|-v /:/host' docs/",
        )
        self.assert_cases(rule, positive, negative)

    def test_privileged_prerequisites(self) -> None:
        rule = pattern("tdx.privilege_escalation.container_privileged_launch")
        positive = (
            "docker run --rm --privileged alpine true",
            "docker run --pid=host alpine true",
            "podman run --cap-add=SYS_ADMIN alpine true",
            "docker run --security-opt seccomp=unconfined alpine true",
            "docker run -v /var/run/docker.sock:/var/run/docker.sock synthetic-helper true",
            "curl --unix-socket /var/run/docker.sock http://localhost/containers/json",
        )
        negative = (
            "docker run --rm -v /workspace:/work alpine true",
            "docker run --rm -v /:/host:ro alpine ls /host",
            "rg -n 'mount -t virtiofs|--privileged|-v /:/host' docs/",
            "docker ps",
        )
        self.assert_cases(rule, positive, negative)

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
