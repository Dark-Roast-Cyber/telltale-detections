"""Focused command confounders for the shipped Rule v1 regexes.

These are fast pattern checks, not a substitute for the pinned parser-to-event gate.
"""

import json
import re
import unittest
from pathlib import Path


PACKS = Path(__file__).resolve().parents[1] / "packs" / "test"


def pattern(pack: str) -> re.Pattern[str]:
    # Contribution lint requires one single-quoted regex on one line in these packs.
    line = next(
        line
        for line in (PACKS / pack).read_text(encoding="utf-8").splitlines()
        if line.startswith("    regex: ")
    )
    assert line.startswith("    regex: '") and line.endswith("'")
    return re.compile(line[len("    regex: '") : -1].replace("''", "'"), re.IGNORECASE)


class RulePatternTests(unittest.TestCase):
    def test_git_hook_change(self) -> None:
        rule = pattern("git-hook-persistence.yaml")
        positive = (
            "git config core.hooksPath .githooks",
            "git config --global core.hooksPath hooks",
            "git config --local --add core.hooksPath .githooks",
            "printf '#!/bin/sh\\necho ok' > .git/hooks/pre-commit",
        )
        negative = (
            "git config --get core.hooksPath",
            "git config --show-origin --get core.hooksPath",
            "git config --unset core.hooksPath",
            "cat .git/hooks/pre-commit",
        )
        for command in positive:
            with self.subTest(command=command):
                self.assertIsNotNone(rule.search(command))
        for command in negative:
            with self.subTest(command=command):
                self.assertIsNone(rule.search(command))

    def test_mcp_registration(self) -> None:
        rule = pattern("mcp-server-registration.yaml")
        for command in (
            "codex mcp add helper --url http://127.0.0.1:65535/mcp",
            "claude mcp add helper -- command",
            "opencode mcp add helper",
            "opencode mcp add",
        ):
            with self.subTest(command=command):
                self.assertIsNotNone(rule.search(command))
                self.assertIsNotNone(rule.search(json.dumps(["bash", "-lc", command])))
        for command in (
            "codex mcp list",
            "claude mcp get helper",
            "opencode mcp add-json helper",
            "claude mcp add-json --help",
            "codex mcp addition",
        ):
            with self.subTest(command=command):
                self.assertIsNone(rule.search(command))
                self.assertIsNone(rule.search(json.dumps(["bash", "-lc", command])))

    def test_known_read_only_false_positives_remain_visible(self) -> None:
        cases = (
            ("git-hook-persistence.yaml", "grep '#!' .git/hooks/pre-commit"),
            ("mcp-server-registration.yaml", "claude mcp add --help"),
        )
        for pack, command in cases:
            with self.subTest(pack=pack, command=command):
                # These benign commands match today; independently labeled scenarios
                # must keep reporting the resulting false positives in the full gate.
                rule = pattern(pack)
                self.assertIsNotNone(rule.search(command))
                self.assertIsNotNone(rule.search(json.dumps(["bash", "-lc", command])))

    def test_windows_persistence(self) -> None:
        rule = pattern("windows-agent-persistence.yaml")
        positive = (
            "schtasks.exe /Create /SC ONLOGON /TN SyntheticUpdater /TR example.exe",
            r"reg.exe add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Example /d example.exe",
            r"reg add HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce /v Example /d example.exe",
            r'reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell /d example.exe',
            r'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Example /d example.exe',
            r'reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v Example /d example.exe',
            'copy helper.lnk "C:\\Users\\Example\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\helper.lnk"',
            r'copy /Y "C:\Example Files\helper.lnk" "C:\Users\Example\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\helper.lnk"',
            r'copy /-Y "C:\Example Files\helper.lnk" C:\Example\Startup\helper.lnk',
            r'move "C:\Example Files\helper.lnk" "C:\Example\Startup"',
            r"xcopy /Y C:\Example\helper.lnk C:\Example\Startup",
            r'robocopy "C:\Example Files" "C:\Example\Startup" helper.lnk',
        )
        negative = (
            "schtasks.exe /Query /TN SyntheticUpdater",
            r"reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            r"reg add HKCU\Software\Example\Settings /v Hint /d C:\Example\CurrentVersion\Run",
            r"reg add HKCU\Software\Example\Settings /v Run /d example.exe",
            r"copy C:\Users\Example\Startup\helper.lnk C:\Backup\helper.lnk",
            r'copy "C:\Users\Example\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\helper.lnk" "C:\Backup\helper.lnk"',
            r'copy /Y "C:\Users\Example\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\helper.lnk" "C:\Backup\helper.lnk"',
            r'copy helper.lnk "C:\Backup\Startup-old\helper.lnk"',
            r"copy helper.lnk C:\Backup\Startup.txt",
            r"reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run-Backup /v Note /d EXAMPLE",
            r'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce-Backup" /v Note /d EXAMPLE',
            r'reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon-Backup" /v Note /d EXAMPLE',
        )
        for command in positive:
            with self.subTest(command=command):
                self.assertIsNotNone(rule.search(command))
                self.assertIsNotNone(rule.search(json.dumps(["bash", "-lc", command])))
        for command in negative:
            with self.subTest(command=command):
                self.assertIsNone(rule.search(command))
                self.assertIsNone(rule.search(json.dumps(["bash", "-lc", command])))


if __name__ == "__main__":
    unittest.main()
