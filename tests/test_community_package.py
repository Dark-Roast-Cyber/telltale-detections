"""Contribution lint and community package builds need only the standard library."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import community_package  # noqa: E402


class CommunityPackageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "content"
        for name in ("packs", "scenarios", "docs"):
            shutil.copytree(ROOT / name, self.root / name)
        shutil.copyfile(ROOT / "community-package.json", self.root / "community-package.json")
        self.pack = self.root / "packs" / "test" / "mcp-server-registration.yaml"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def assert_lint_error(self, fragment: str) -> None:
        with self.assertRaises(community_package.ContentError) as caught:
            community_package.lint(self.root)
        self.assertIn(fragment, str(caught.exception))

    def edit_pack(self, old: str, new: str) -> None:
        text = self.pack.read_text(encoding="utf-8")
        self.assertIn(old, text)
        self.pack.write_text(text.replace(old, new), encoding="utf-8")

    def test_repository_content_passes_lint(self) -> None:
        self.assertIn("tdx.persistence.mcp_server_registration", community_package.lint(ROOT))

    def test_ids_must_use_the_package_namespace(self) -> None:
        self.edit_pack("id: tdx.persistence.mcp_server_registration", "id: mcp.server_registration")
        self.assert_lint_error("must start with `tdx.`")

    def test_status_must_match_the_maturity_directory(self) -> None:
        self.edit_pack("status: test", "status: stable")
        self.assert_lint_error("needs `status: test`")

    def test_rules_need_notes_and_both_scenario_polarities(self) -> None:
        (self.root / "docs" / "detections" / "tdx.persistence.mcp_server_registration.md").unlink()
        self.assert_lint_error("needs docs/detections/")
        shutil.copyfile(ROOT / "docs" / "detections" / "tdx.persistence.mcp_server_registration.md",
                        self.root / "docs" / "detections" / "tdx.persistence.mcp_server_registration.md")
        (self.root / "scenarios" / "benign" / "mcp_server_list.json").unlink()
        self.assert_lint_error("needs a benign scenario")

    def test_hidden_characters_markup_and_extra_documents_are_rejected(self) -> None:
        cases = [
            ("registers a new MCP server", "registers a new‮MCP server", "forbidden character U+202E"),
            ("registers a new MCP server", "registers a <b>new</b> MCP server", "markup, links"),
            # YAML would decode these escapes to markup and a link.
            ("title: MCP server registered by an agent command",
             'title: "\\x3cimg\\x3e https\\x3a//evil.example"', "or escapes"),
            # str.splitlines() treats these as line breaks; the package must not.
            ("registers a new MCP server", "registers a new\x0c    author: x", "forbidden character U+000C"),
            ("registers a new MCP server", "registers a new     enabled: false",
             "forbidden character U+2028"),
            ("registers a new MCP server", "registers a new\rMCP server", "forbidden character U+000D"),
            ("modifiers: []", "modifiers: []\noverrides: []", "unsupported top-level key `overrides`"),
            ("modifiers: []", "modifiers: []\n---\nversion: 1", "document markers"),
        ]
        original = self.pack.read_text(encoding="utf-8")
        for old, new, fragment in cases:
            with self.subTest(fragment=fragment):
                self.pack.write_text(original.replace(old, new, 1), encoding="utf-8")
                self.assert_lint_error(fragment)

    def test_rules_use_the_one_layout_the_lint_reads(self) -> None:
        rule = "  - id: tdx.persistence.mcp_server_registration\n    title:"
        cases = [
            (rule, rule.replace("registration\n", "registration # note\n"), "write each rule as"),
            (rule, "  - status: test\n    id: tdx.persistence.mcp_server_registration\n    title:",
             "write each rule as"),
            ("rules:\n  - id:", "rules:\n    - id:", "write each rule as"),
            ("rules:\n", "rules: [{id: tdx.persistence.flow, status: test}]\n", "block list"),
            ("modifiers: []", "modifiers:\n  - id: tdx.persistence.boost\n    score: 100",
             "define no modifiers"),
        ]
        original = self.pack.read_text(encoding="utf-8")
        for old, new, fragment in cases:
            with self.subTest(new=new):
                self.assertIn(old, original)
                self.pack.write_text(original.replace(old, new, 1), encoding="utf-8")
                self.assert_lint_error(fragment)

    def test_values_cannot_span_into_the_lines_after_them(self) -> None:
        title = "    title: MCP server registered by an agent command"
        status = "    status: test"
        cases = [
            # Key spellings the line reader would not see as `title`.
            (title, '    "title": <b>MCP</b>', "open and close each quoted value"),
            (title, "    title : <b>MCP</b>", "rule fields are"),
            (title, "    ? title\n    : <b>MCP</b>", "complex keys"),
            # Quoted values that would absorb the next line, which looks like a key.
            (title, "    title: 'Benign\n    regex: <b>MCP</b>'", "open and close each quoted value"),
            (title, '    title: "Benign\n    regex: \\x3cb\\x3e"', "open and close each quoted value"),
            (status, '    status: "test\n      "', "open and close each quoted value"),
            (status, "    status: test\n      experimental", "`status: <maturity>` on one line"),
            (status, "    status: test # promoted", "`status: <maturity>` on one line"),
            (title, "    title: |\n      # <b>MCP</b>", "markup, links"),
            ("tags: [mcp,", 'tags: ["mcp",', "plain items only"),
            ("tags: [mcp, tool-surface, configuration, persistence]", "tags: [mcp,\n      persistence]",
             "on one line"),
            (title, "    title: &shared MCP server", "anchors, aliases"),
        ]
        original = self.pack.read_text(encoding="utf-8")
        for old, new, fragment in cases:
            with self.subTest(new=new):
                self.assertIn(old, original)
                self.pack.write_text(original.replace(old, new, 1), encoding="utf-8")
                self.assert_lint_error(fragment)

    def test_plain_display_text_may_contain_backslashes(self) -> None:
        self.edit_pack("      - Authorized developer setup may register",
                       "      - Authorized developer setup in HKCU\\Software may register")
        self.edit_pack("    explanation: An agent invokes",
                       "    explanation: |\n      An agent's 'quoted' text.\n      # A literal line.\n      An agent invokes")
        community_package.lint(self.root)

    def test_crlf_packs_compose_to_lf_package_text(self) -> None:
        self.pack.write_bytes(self.pack.read_bytes().replace(b"\n", b"\r\n"))
        community_package.lint(self.root)
        self.assertNotIn("\r", community_package.compose_package(self.root, "0.1.0", None))

    def test_scenario_polarity_comes_from_its_directory(self) -> None:
        benign = self.root / "scenarios" / "benign" / "mcp_server_list.json"
        benign.rename(self.root / "scenarios" / "visibility-limited" / "mcp_server_list.json")
        self.assert_lint_error("needs a benign scenario")

    def test_unknown_maturity_directories_are_rejected(self) -> None:
        (self.root / "packs" / "beta").mkdir()
        self.assert_lint_error("unexpected entry under packs/: beta")

    def test_released_package_is_deterministic_and_excludes_experimental_packs(self) -> None:
        experimental = self.root / "packs" / "experimental"
        experimental.mkdir(exist_ok=True)
        (experimental / "draft.yaml").write_text(
            self.pack.read_text(encoding="utf-8")
            .replace("tdx.persistence.mcp_server_registration", "tdx.persistence.draft")
            .replace("status: test", "status: experimental"),
            encoding="utf-8",
        )
        revision = "0" * 40
        first = community_package.compose_package(self.root, "0.1.0", revision)
        second = community_package.compose_package(self.root, "0.1.0", revision)
        self.assertEqual(first, second)
        self.assertIn('id: "telltale.community"', first)
        self.assertIn('version: "0.1.0"', first)
        self.assertIn(f'revision: "{revision}"', first)
        self.assertNotIn("tdx.persistence.draft", first)
        for line in self.pack.read_text(encoding="utf-8").splitlines()[1:]:
            if line.strip():
                self.assertIn(f"    {line}\n", first)
        candidate = community_package.compose_package(
            self.root, "0.0.0-candidate", None, community_package.MATURITIES)
        self.assertIn("tdx.persistence.draft", candidate)
        with self.assertRaises(community_package.ContentError):
            community_package.compose_package(self.root, "0.1.0", "not-a-sha")

    def test_validate_requires_the_pinned_telltale_revision(self) -> None:
        shutil.copyfile(ROOT / "pins.json", self.root / "pins.json")
        binary = Path(self.tmp.name) / "telltale"
        binary.write_text("#!/bin/sh\necho 'telltale 0.0.0 (0123456789ab)'\n", encoding="utf-8")
        binary.chmod(0o755)
        with self.assertRaises(community_package.ContentError) as caught:
            community_package.validate(self.root, binary)
        self.assertIn("must report revision", str(caught.exception))

    def test_validate_rejects_rules_telltale_loads_but_the_lint_did_not_see(self) -> None:
        shutil.copyfile(ROOT / "pins.json", self.root / "pins.json")
        revision = json.loads((ROOT / "pins.json").read_text(encoding="utf-8"))["telltale"]["revision"]
        ids = community_package.lint(self.root)
        binary = Path(self.tmp.name) / "telltale"
        binary.write_text(f"""#!{sys.executable}
import hashlib, json, pathlib, sys
if sys.argv[1] == "--version":
    print("telltale 0.0.0 ({revision[:12]})")
    sys.exit()
config = pathlib.Path(sys.argv[sys.argv.index("--config-dir") + 1])
package = next((config / "rule-packages.d").iterdir()).read_bytes()
print(json.dumps({{
    "packages": [{{"id": "telltale.community", "version": "0.0.0-candidate",
                  "origin": "installed", "content_sha256": hashlib.sha256(package).hexdigest()}}],
    "provenance": [{{"id": rule_id}} for rule_id in {ids!r} + ["tdx.persistence.unseen"]],
}}))
""", encoding="utf-8")
        binary.chmod(0o755)
        with self.assertRaises(community_package.ContentError) as caught:
            community_package.validate(self.root, binary)
        self.assertIn("unexpected ['tdx.persistence.unseen']", str(caught.exception))

    @unittest.skipUnless(os.environ.get("TELLTALE_BIN"), "set TELLTALE_BIN to a pinned Telltale build")
    def test_pinned_telltale_rejects_escaped_hidden_characters_the_lint_allows(self) -> None:
        shutil.copyfile(ROOT / "pins.json", self.root / "pins.json")
        binary = Path(os.environ["TELLTALE_BIN"])
        self.assertTrue(community_package.validate(self.root, binary).startswith("telltale "))
        # Disabled rules are still loaded and accounted for.
        self.edit_pack("  enabled: true", "  enabled: false")
        community_package.validate(self.root, binary)
        # The lint reads raw text and rejects escapes only in display text;
        # Telltale also checks every decoded YAML string.
        self.edit_pack("category: persistence", 'category: "persistence\\u202E"')
        community_package.lint(self.root)
        with self.assertRaises(community_package.ContentError) as caught:
            community_package.validate(self.root, binary)
        self.assertIn("candidate package validation failed", str(caught.exception))

    def test_build_writes_the_package_and_its_checksum(self) -> None:
        out = Path(self.tmp.name) / "dist"
        path = community_package.build(self.root, "0.1.0", None, out)
        self.assertEqual(path.name, "telltale.community-0.1.0.package.yaml")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        self.assertEqual((out / "SHA256SUMS").read_text(encoding="utf-8"), f"{digest}  {path.name}\n")


if __name__ == "__main__":
    unittest.main()
