#!/usr/bin/env python3
"""Lint candidate content and build the Telltale community rule package.

Content is data: this script never executes scenario commands and needs only
the Python standard library. Rules are Rule v2, Telltale's Sigma profile, one
rule per file under `rules/`. The pinned Telltale is the parser: the lint asks
it to validate each rule file and to print its rule catalog, then checks this
repository's contribution policy against what Telltale read.

    community_package.py lint --telltale /path/to/pinned/telltale
    community_package.py validate --telltale /path/to/pinned/telltale
    community_package.py build --telltale /path/to/pinned/telltale \\
        --version 0.1.0 [--revision SHA] --out dist/
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PACKAGE_FORMAT = "telltale-rule-package/v2"
CANDIDATE_VERSION = "0.0.0-candidate"
MATURITIES = ("experimental", "test", "stable")
RELEASED_MATURITIES = ("test", "stable")
SCENARIO_KINDS = ("adversarial", "benign", "visibility-limited")
MAX_FILE_BYTES = 256 * 1024
NOTE_URL = "https://github.com/Dark-Roast-Cyber/telltale-detections/blob/main/docs/detections/{}.md"
# Catalog text an analyst tool renders: no markup or links (use `references`).
DISPLAY_KEYS = ("title", "description", "author", "explanation", "falsepositives", "tags")
REQUIRED_KEYS = ("description", "references", "author", "date")
VERSION = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$")
# Core rules load too, so a disabled or deprecated rule still yields a catalog.
CORE_ONLY = ("--no-community-rules", "--no-local-config")


class ContentError(Exception):
    pass


@dataclass(frozen=True)
class Rule:
    """One rule file and the catalog entry Telltale read from it."""

    name: str
    status: str
    path: Path
    entry: dict


def is_hidden_character(character: str) -> bool:
    """Match Telltale's check: controls, invisible formatting, and the
    U+2028/U+2029 separators that YAML treats as line breaks."""
    code = ord(character)
    if character in "\t\r\n":
        return False
    return (
        code < 0x20 or 0x7F <= code <= 0x9F or code == 0x061C
        or 0x200B <= code <= 0x200F or 0x2028 <= code <= 0x202E
        or 0x2060 <= code <= 0x2069 or code == 0xFEFF
    )


def load_metadata(root: Path) -> dict[str, str]:
    metadata = json.loads((root / "community-package.json").read_text(encoding="utf-8"))
    required = {"id", "title", "publisher", "license", "rule_namespace", "source"}
    if set(metadata) != required or not all(isinstance(v, str) and v for v in metadata.values()):
        raise ContentError(f"community-package.json must contain exactly {sorted(required)}")
    return metadata


def rule_paths(root: Path) -> list[Path]:
    """Return the rule files: regular `.yml` files directly under `rules/`."""
    directory = root / "rules"
    if not directory.is_dir():
        return []
    found = []
    for path in sorted(directory.iterdir()):
        if path.name.startswith("."):
            continue
        if path.is_symlink() or not path.is_file() or path.suffix != ".yml":
            raise ContentError(f"rules/{path.name}: rules must be regular .yml files directly under rules/")
        found.append(path)
    return found


def read_text(path: Path, limit: int = MAX_FILE_BYTES) -> str:
    raw = path.read_bytes()
    if len(raw) > limit:
        raise ContentError(f"{path.name}: exceeds {limit} bytes")
    try:
        text = raw.decode("utf-8").replace("\r\n", "\n")
    except UnicodeDecodeError as exc:
        raise ContentError(f"{path.name}: not UTF-8") from exc
    # Check the whole text: str.splitlines() would consume separators such as
    # \f or U+2028 before a per-line check could see them.
    for index, character in enumerate(text):
        if is_hidden_character(character) or character == "\r":
            number = text.count("\n", 0, index) + 1
            raise ContentError(f"{path.name}:{number}: forbidden character U+{ord(character):04X}")
    return text


def telltale_env() -> dict[str, str]:
    # Inherited TELLTALE_* settings (such as a community opt-out) must not
    # change which candidate content Telltale loads.
    return {key: value for key, value in os.environ.items() if not key.startswith("TELLTALE_")}


def run_telltale(telltale: Path, *args: str) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run([str(telltale), *args], env=telltale_env(), text=True,
                              capture_output=True, timeout=300, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ContentError(f"Telltale failed to start or timed out ({type(exc).__name__})") from exc


def telltale_json(telltale: Path, label: str, *args: str) -> dict:
    result = run_telltale(telltale, *args)
    if result.returncode:
        raise ContentError(f"{label}: Telltale rejected it: {result.stderr.strip()[-2000:]}")
    try:
        report = json.loads(result.stdout)
    except ValueError as exc:
        raise ContentError(f"{label}: `telltale {' '.join(args[:2])}` printed no JSON") from exc
    if not isinstance(report, dict):
        raise ContentError(f"{label}: `telltale {' '.join(args[:2])}` printed unexpected JSON")
    return report


def require_pinned_telltale(root: Path, telltale: Path) -> str:
    """Return the binary's version line if it reports the revision in pins.json."""
    pins = json.loads((root / "pins.json").read_text(encoding="utf-8"))
    revision = pins["telltale"]["revision"][:12]
    version = run_telltale(telltale, "--version")
    if version.returncode or not re.search(rf"\({revision}[0-9a-f]*\)", version.stdout):
        raise ContentError(f"Telltale binary must report revision {revision} (pins.json)")
    return version.stdout.strip()


def check_display_text(entry: dict, label: str) -> None:
    for key in DISPLAY_KEYS:
        value = entry.get(key)
        for text in value if isinstance(value, list) else [value]:
            if isinstance(text, str) and ("<" in text or ">" in text or "://" in text):
                raise ContentError(f"{label}: `{key}` must not contain markup or links")


def read_rule(telltale: Path, path: Path, metadata: dict[str, str], core: set[str]) -> Rule:
    """Load one rule file beside the core rules in Telltale and check what the
    package needs from its catalog entry: one rule, its name, file name and status."""
    label = f"rules/{path.name}"
    read_text(path)
    args = (*CORE_ONLY, "--rules", str(path))
    report = telltale_json(telltale, label, "rules", "validate", *args)
    if report.get("notices"):
        raise ContentError(f"{label}: resolve Telltale's notices: {report['notices']}")
    entries = [entry for entry in telltale_json(telltale, label, "rules", "catalog", *args)["entries"]
               if entry["id"] not in core]
    if len(entries) != 1:
        raise ContentError(f"{label}: a rule file holds exactly one rule")
    entry = entries[0]
    name = entry["id"]
    if entry.get("kind") != "rule":
        raise ContentError(f"{label}: community content defines rules only, not chains")
    prefix = metadata["rule_namespace"] + "."
    if not name.startswith(prefix):
        raise ContentError(f"{label}: `{name}` must start with `{prefix}`")
    expected = name.replace(".", "_") + ".yml"
    if path.name != expected:
        raise ContentError(f"{label}: the file for `{name}` is rules/{expected}")
    if entry.get("status") not in MATURITIES:
        raise ContentError(f"{label}: `status` must be one of {', '.join(MATURITIES)}")
    return Rule(name, entry["status"], path, entry)


def read_rules(root: Path, telltale: Path) -> list[Rule]:
    """Return every rule file as Telltale reads it, sorted by name."""
    metadata = load_metadata(root)
    paths = rule_paths(root)
    if not paths:
        raise ContentError("no rule files under rules/")
    rules: dict[str, Rule] = {}
    uuids: dict[str, str] = {}
    core = {entry["id"] for entry in telltale_json(telltale, "core rules", "rules", "catalog", *CORE_ONLY)["entries"]}
    for path in paths:
        rule = read_rule(telltale, path, metadata, core)
        uuid = rule.entry["uuid"]
        if uuid in uuids:
            raise ContentError(f"rules/{path.name}: `id` {uuid} is also the id of `{uuids[uuid]}`")
        uuids[uuid] = rule.name
        rules[rule.name] = rule
    return [rules[name] for name in sorted(rules)]


def check_metadata(root: Path, rule: Rule) -> None:
    """Contribution policy for a rule's descriptive metadata and its note."""
    label = f"rules/{rule.path.name}"
    for key in REQUIRED_KEYS:
        if not rule.entry.get(key):
            raise ContentError(f"{label}: `{key}` is required")
    check_display_text(rule.entry, label)
    if not (root / "docs" / "detections" / f"{rule.name}.md").is_file():
        raise ContentError(f"{label}: `{rule.name}` needs docs/detections/{rule.name}.md")
    if NOTE_URL.format(rule.name) not in rule.entry["references"]:
        raise ContentError(f"{label}: `references` must include {NOTE_URL.format(rule.name)}")


def scenario_expectations(root: Path) -> tuple[dict[str, set[str]], dict[str, set[str]], set[str]]:
    """Map rule names to adversarial scenarios that must match them and to
    benign scenarios that must not; also return every referenced name."""
    must_match: dict[str, set[str]] = {}
    must_not_match: dict[str, set[str]] = {}
    referenced: set[str] = set()
    for kind in SCENARIO_KINDS:
        directory = root / "scenarios" / kind
        if not directory.exists():
            continue
        for path in sorted(directory.glob("*.json")):
            if path.is_symlink():
                raise ContentError(f"scenarios/{kind}/{path.name}: symlinks are not allowed")
            data = json.loads(read_text(path))
            expectations = data.get("rule_expectations", {})
            referenced.update(expectations.get("must_match", []), expectations.get("must_not_match", []))
            if kind == "adversarial":
                for name in expectations.get("must_match", []):
                    must_match.setdefault(name, set()).add(data["id"])
            if kind == "benign":
                for name in expectations.get("must_not_match", []):
                    must_not_match.setdefault(name, set()).add(data["id"])
    return must_match, must_not_match, referenced


def lint(root: Path, telltale: Path) -> list[Rule]:
    """Return the linted rules sorted by name, or raise ContentError."""
    require_pinned_telltale(root, telltale)
    rules = read_rules(root, telltale)
    for rule in rules:
        check_metadata(root, rule)
    names = {rule.name for rule in rules}
    must_match, must_not_match, referenced = scenario_expectations(root)
    prefix = load_metadata(root)["rule_namespace"] + "."
    for name in sorted(referenced):
        if name.startswith(prefix) and name not in names:
            raise ContentError(f"a scenario expects unknown candidate `{name}`")
    for name in sorted(names):
        if name not in must_match:
            raise ContentError(f"`{name}` needs an adversarial scenario that must match it")
        if name not in must_not_match:
            raise ContentError(f"`{name}` needs a benign scenario that must not match it")
    return rules


def package_document(text: str, label: str) -> list[str]:
    """Return one rule file's lines, unchanged, as a document of the package
    stream. The file must hold one document without markers or directives."""
    lines = text.splitlines()
    if any(line.startswith(("---", "...", "%")) for line in lines):
        raise ContentError(f"{label}: write one rule document without YAML markers or directives")
    return lines


def compose_package(root: Path, rules: list[Rule], version: str, revision: str | None,
                    maturities: tuple[str, ...] = RELEASED_MATURITIES) -> str:
    """Compose the package stream: the header document, then the files of
    the rules whose status is in `maturities`, one document each, sorted by name."""
    if not VERSION.match(version):
        raise ContentError(f"invalid package version `{version}`")
    metadata = load_metadata(root)
    lines = [
        "# Generated by telltale-detections scripts/community_package.py. Do not edit.",
        f"format: {PACKAGE_FORMAT}",
        f"id: {json.dumps(metadata['id'])}",
        f"title: {json.dumps(metadata['title'])}",
        f"version: {json.dumps(version)}",
        f"publisher: {json.dumps(metadata['publisher'])}",
        f"license: {json.dumps(metadata['license'])}",
        f"rule_namespace: {json.dumps(metadata['rule_namespace'])}",
        f"source: {json.dumps(metadata['source'])}",
    ]
    if revision:
        if not re.fullmatch(r"[0-9a-f]{40}", revision):
            raise ContentError("revision must be a full lowercase Git commit SHA")
        lines.append(f"revision: {json.dumps(revision)}")
    selected = sorted((rule for rule in rules if rule.status in maturities), key=lambda rule: rule.name)
    if not selected:
        raise ContentError(f"no rules with status {', '.join(maturities)}")
    for rule in selected:
        label = f"rules/{rule.path.name}"
        lines.extend(["---", f"# {label}"])
        lines.extend(package_document(read_text(rule.path), label))
    return "\n".join(lines) + "\n"


def install_candidate(root: Path, telltale: Path, config_dir: Path) -> tuple[Path, dict[str, str]]:
    """Return the installed candidate package and the status of each rule.

    A package with the community ID replaces the snapshot embedded in Telltale,
    so Telltale's package loader validates exactly the content under review.
    The contribution policy is `lint`'s; this needs only what Telltale reads.
    """
    metadata = load_metadata(root)
    rules = read_rules(root, telltale)
    text = compose_package(root, rules, CANDIDATE_VERSION, None, MATURITIES)
    packages = config_dir / "rule-packages.d"
    packages.mkdir(parents=True)
    path = packages / "telltale.community.candidate.yaml"
    path.write_text(text, encoding="utf-8")
    report = telltale_json(telltale, "candidate package", "rules", "validate", "--config-dir", str(config_dir))
    try:
        active = [(p["id"], p["version"], p["origin"], p["content_sha256"]) for p in report["packages"]]
    except (KeyError, TypeError) as exc:
        raise ContentError("Telltale did not report rule packages; "
                           "the pinned revision must support rule packages") from exc
    package = (metadata["id"], CANDIDATE_VERSION, "installed", sha256_bytes(text.encode("utf-8")))
    if active != [package]:
        raise ContentError(f"Telltale did not load the candidate package as the only package: {active}")
    # The package must load each rule exactly as its file loads on its own.
    catalog = telltale_json(telltale, "candidate package", "rules", "catalog", "--config-dir", str(config_dir))

    def unpackaged(entry: dict) -> dict:
        return {key: value for key, value in entry.items() if key != "package_id"}

    loaded = {entry["id"]: unpackaged(entry) for entry in catalog.get("entries", [])
              if entry.get("package_id") == metadata["id"]}
    expected = {rule.name: unpackaged(rule.entry) for rule in rules}
    if loaded.keys() != expected.keys():
        raise ContentError("Telltale loaded different candidate definitions than the lint checked: "
                           f"unexpected {sorted(loaded.keys() - expected.keys())}, "
                           f"missing {sorted(expected.keys() - loaded.keys())}")
    changed = sorted(name for name in loaded if loaded[name] != expected[name])
    if changed:
        raise ContentError(f"the package loads these rules differently from their files: {changed}")
    return path, {rule.name: rule.status for rule in rules}


def validate(root: Path, telltale: Path) -> str:
    """Lint, then confirm the pinned Telltale loads every rule from the package."""
    version = require_pinned_telltale(root, telltale)
    lint(root, telltale)
    with tempfile.TemporaryDirectory(prefix="telltale-candidate-") as tmp:
        install_candidate(root, telltale, Path(tmp))
    return version


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_package(root: Path, rules: list[Rule], version: str, revision: str | None, out: Path) -> Path:
    """Write the released package (statuses `test` and `stable`) and SHA256SUMS."""
    package = compose_package(root, rules, version, revision)
    out.mkdir(parents=True, exist_ok=True)
    metadata = load_metadata(root)
    path = out / f"{metadata['id']}-{version}.package.yaml"
    path.write_text(package, encoding="utf-8")
    (out / "SHA256SUMS").write_text(
        f"{sha256_bytes(package.encode('utf-8'))}  {path.name}\n", encoding="utf-8"
    )
    return path


def build(root: Path, telltale: Path, version: str, revision: str | None, out: Path) -> Path:
    return write_package(root, lint(root, telltale), version, revision, out)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    commands = {
        "lint": "check contribution policy for rules, scenarios, and notes",
        "validate": "lint, then load every candidate rule as the package in the pinned Telltale",
        "build": "lint, then write the released package and SHA256SUMS",
    }
    for command, text in commands.items():
        subparser = sub.add_parser(command, help=text)
        subparser.add_argument("--telltale", required=True, help="Telltale binary built at the pins.json revision")
        if command == "build":
            subparser.add_argument("--version", required=True, help="package version, such as 0.1.0")
            subparser.add_argument("--revision", help="full Git commit SHA the package is built from")
            subparser.add_argument("--out", required=True, help="output directory")
    args = parser.parse_args()
    telltale = Path(args.telltale)
    try:
        if args.command == "lint":
            rules = lint(ROOT, telltale)
            print(f"lint ok: {len(rules)} rules")
        elif args.command == "validate":
            version = validate(ROOT, telltale)
            print(f"validate ok: {version} loaded every candidate rule")
        else:
            path = build(ROOT, telltale, args.version, args.revision, Path(args.out))
            print(f"package: {path}")
    except (ContentError, OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
