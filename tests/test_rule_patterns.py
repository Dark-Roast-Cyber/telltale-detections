"""Focused command confounders for the shipped Rule v1 regexes.

These are fast pattern checks, not a substitute for the pinned parser-to-event gate.
"""

import json
import re
import unittest
from pathlib import Path


PACKS = Path(__file__).resolve().parents[1] / "packs" / "test"


def pattern(pack: str, rule_id: str | None = None) -> re.Pattern[str]:
    # Contribution lint requires one single-quoted regex on one line per rule.
    lines = (PACKS / pack).read_text(encoding="utf-8").splitlines()
    if rule_id is not None:
        lines = lines[lines.index(f"  - id: {rule_id}") :]
    line = next(line for line in lines if line.startswith("    regex: "))
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
            "git config core.hooksPath || printf 'No hook path configured\\n'",
            "git config core.hooksPath && printf 'Hook path configured\\n'",
            "git config core.hooksPath > /workspace/demo/hook-path.txt",
            "git config core.hooksPath # inspect the configured path",
            "git config core.hooksPath\nprintf 'No write requested\\n'",
            "cat .git/hooks/pre-commit",
        )
        for command in positive:
            with self.subTest(command=command):
                self.assertIsNotNone(rule.search(command))
                self.assertIsNotNone(rule.search(json.dumps(["bash", "-lc", command])))
        for command in negative:
            with self.subTest(command=command):
                self.assertIsNone(rule.search(command))
                self.assertIsNone(rule.search(json.dumps(["bash", "-lc", command])))

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
            "Register-ScheduledTask -TaskName SyntheticUpdater -Action $action -Trigger $trigger",
            "$task | Register-ScheduledTask -TaskName SyntheticUpdater",
            "Set-ScheduledTask -TaskName SyntheticUpdater -Action $action",
            r"Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name Example -Value example.exe",
            r"New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce -Name Example -Value example.exe",
            r'Set-ItemProperty -Name Shell -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Value example.exe',
            r"Set-ItemProperty Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run -Name Example -Value example.exe",
            r'Copy-Item C:\Example\helper.lnk "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\helper.lnk"',
            r"Copy-Item -Path C:\Example\helper.lnk -Destination 'C:\Users\Example\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'",
            r"(New-Object -ComObject Shell.Application).Namespace('shell:startup').CopyHere('C:\Example\helper.lnk')",
        )
        negative = (
            "schtasks.exe /Query /TN SyntheticUpdater",
            "Get-ScheduledTask -TaskName SyntheticUpdater",
            "Unregister-ScheduledTask -TaskName SyntheticUpdater -Confirm:$false",
            "Get-Help Register-ScheduledTask -Examples",
            r"Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'",
            r"Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\ProfileList\S-1-5-21-0' -Name ProfileImagePath",
            r"Remove-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Run -Name Example",
            r"Set-ItemProperty -Path HKCU:\Software\Example -Name Hint -Value 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'",
            r"Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run-Backup' -Name Note -Value EXAMPLE",
            r"Copy-Item -Path 'C:\Users\Example\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\helper.lnk' -Destination C:\Backup",
            "explorer.exe shell:startup",
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
        self.assert_windows_matches(rule, positive, negative)

    def test_windows_service_change(self) -> None:
        rule = pattern("windows-agent-persistence.yaml", "tdx.persistence.windows_service_change")
        positive = (
            r'New-Service -Name SyntheticSvc -BinaryPathName "C:\Example\svc.exe" -StartupType Automatic',
            r"New-Service -BinaryPathName C:\Example\svc.exe -Name SyntheticSvc",
            r'sc.exe create SyntheticSvc binPath= "C:\Example\svc.exe" start= auto',
            r'sc.exe config SyntheticSvc binPath= "C:\Example\other.exe"',
            "sc config SyntheticSvc start= auto",
            "Set-Service -Name SyntheticSvc -StartupType Automatic",
        )
        negative = (
            "sc query SyntheticSvc",
            "sc.exe qc SyntheticSvc",
            "sc config SyntheticSvc start= disabled",
            "Get-Service -Name SyntheticSvc",
            "Set-Service -Name SyntheticSvc -StartupType Disabled",
            "Get-Help New-Service -Examples",
            'rg -n "New-Service|sc create" docs/',
            'sc config.json "{}"',
        )
        self.assert_windows_matches(rule, positive, negative)

    def test_powershell_profile_write(self) -> None:
        rule = pattern("windows-agent-persistence.yaml", "tdx.persistence.powershell_profile_write")
        positive = (
            "Add-Content -Path $PROFILE -Value 'Import-Module SyntheticTools'",
            "'Import-Module SyntheticTools' | Out-File -FilePath $PROFILE -Append",
            "Set-Content -Path $PROFILE.CurrentUserAllHosts -Value 'Import-Module SyntheticTools'",
            "echo 'Import-Module SyntheticTools' >> $PROFILE",
            r'Add-Content "$HOME\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1" "Import-Module SyntheticTools"',
            r"Copy-Item .\profile.ps1 $PROFILE",
            "cp ./profile.ps1 ~/.config/powershell/Microsoft.PowerShell_profile.ps1",
        )
        negative = (
            "Get-Content $PROFILE",
            "Test-Path $PROFILE",
            ". $PROFILE",
            "notepad $PROFILE",
            "New-Item -Path $PROFILE -ItemType File -Force",
            r"Copy-Item $PROFILE C:\Backup\profile.ps1",
            r"Copy-Item $PROFILE -Destination C:\Backup\profile.ps1",
            r"Get-Content $PROFILE > C:\Backup\profile.txt",
            "Set-Content -Path notes.txt -Value $PROFILE",
        )
        self.assert_windows_matches(rule, positive, negative)

    def test_wmi_event_subscription(self) -> None:
        rule = pattern("windows-agent-persistence.yaml", "tdx.persistence.wmi_event_subscription")
        positive = (
            r"Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{Name='SyntheticFilter'; QueryLanguage='WQL'}",
            r"New-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -Property @{Name='SyntheticConsumer'}",
            r"Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{Filter=$filter; Consumer=$consumer}",
            r'wmic /NAMESPACE:"\\root\subscription" PATH __EventFilter CREATE Name="SyntheticFilter"',
            r'$consumer = ([wmiclass]"\\.\root\subscription:CommandLineEventConsumer").CreateInstance()',
        )
        negative = (
            r"Get-WmiObject -Namespace root\subscription -Class __EventFilter",
            "Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding",
            "Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer | Remove-CimInstance",
            r'wmic /NAMESPACE:"\\root\subscription" PATH __EventFilter GET Name',
            'rg -n "__EventFilter|CommandLineEventConsumer" docs/',
        )
        self.assert_windows_matches(rule, positive, negative)

    def assert_windows_matches(self, rule: re.Pattern[str], positive: tuple[str, ...],
                               negative: tuple[str, ...]) -> None:
        # Each form is checked raw and as serialized shell and PowerShell arguments.
        def forms(command: str) -> tuple[str, ...]:
            return (
                command,
                json.dumps(["bash", "-lc", command]),
                json.dumps(["powershell.exe", "-NoProfile", "-Command", command]),
            )

        for command in positive:
            with self.subTest(command=command):
                for form in forms(command):
                    self.assertIsNotNone(rule.search(form))
        for command in negative:
            with self.subTest(command=command):
                for form in forms(command):
                    self.assertIsNone(rule.search(form))


if __name__ == "__main__":
    unittest.main()
