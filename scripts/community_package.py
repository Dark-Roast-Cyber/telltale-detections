#!/usr/bin/env python3
"""Lint candidate content and build the Telltale community rule package.

Content is data: this script reads YAML and JSON as text, never executes
scenario commands, and needs only the Python standard library. Telltale stays
the authoritative Rule v1 and package validator; the lint enforces this
repository's contribution policy before Telltale sees the content, and
`validate` asks the pinned Telltale to load every candidate pack.

    community_package.py lint
    community_package.py validate --telltale /path/to/pinned/telltale
    community_package.py build --version 0.1.0 [--revision SHA] --out dist/
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
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PACKAGE_FORMAT = "telltale-rule-package/v1"
CANDIDATE_VERSION = "0.0.0-candidate"
MATURITIES = ("experimental", "test", "stable")
RELEASED_MATURITIES = ("test", "stable")
SCENARIO_KINDS = ("adversarial", "benign", "visibility-limited")
MAX_PACK_BYTES = 256 * 1024
MAX_LINE_CHARS = 1000
TOP_LEVEL_KEYS = ("version", "description", "defaults", "rules", "modifiers")
# Text an analyst tool renders: no markup or links (use `references` for links).
DISPLAY_KEYS = ("title", "description", "explanation", "falsepositives", "tags")
CANONICAL_ID = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+$")
VERSION = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$")
DEFINITION = re.compile(r"^  - id: ['\"]?([^'\"\s]+)['\"]?\s*$")
RULE_FIELD = re.compile(r"^    ([a-z_]+):(?:\s|$)")
NODE_KEY = re.compile(r"^[A-Za-z0-9_]+:(?=\s|$)")
STATUS_VALUES = {form.format(maturity) for maturity in MATURITIES for form in ("{}", "'{}'", '"{}"')}


class ContentError(Exception):
    pass


def is_hidden_character(character: str) -> bool:
    """Match Telltale's package check: controls, invisible formatting, and the
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
    required = {"id", "publisher", "license", "rule_namespace", "source"}
    if set(metadata) != required or not all(isinstance(v, str) and v for v in metadata.values()):
        raise ContentError(f"community-package.json must contain exactly {sorted(required)}")
    return metadata


def pack_paths(root: Path, maturities: tuple[str, ...] = MATURITIES) -> list[tuple[str, Path]]:
    packs = root / "packs"
    if packs.exists():
        for entry in packs.iterdir():
            if entry.name.startswith("."):
                continue
            if not entry.is_dir() or entry.is_symlink() or entry.name not in MATURITIES:
                raise ContentError(f"unexpected entry under packs/: {entry.name}")
    found = []
    for maturity in maturities:
        directory = packs / maturity
        if not directory.exists():
            continue
        for path in sorted(directory.iterdir()):
            if path.name.startswith("."):
                continue
            if path.is_symlink() or not path.is_file() or path.suffix != ".yaml":
                raise ContentError(f"packs/{maturity}/{path.name}: packs must be regular .yaml files")
            found.append((maturity, path))
    return found


def read_text(path: Path, limit: int) -> str:
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
    for number, line in enumerate(text.split("\n"), start=1):
        if len(line) > MAX_LINE_CHARS:
            raise ContentError(f"{path.name}:{number}: line exceeds {MAX_LINE_CHARS} characters")
    return text


def node_value(line: str) -> tuple[str, int]:
    """Return the value that starts on a line after list markers and a plain
    key, and the indentation its continuation lines must exceed."""
    column = len(line) - len(line.lstrip(" "))
    text = line.strip()
    owner = column
    while text == "-" or text.startswith("- "):
        owner = column
        rest = text[1:]
        column += 1 + len(rest) - len(rest.lstrip(" "))
        text = rest.lstrip(" ")
    key = NODE_KEY.match(text)
    if key:
        return text[key.end():].strip(), column
    return text, owner


def quoted_end(value: str) -> int | None:
    """Return the index after the quoted scalar that opens `value`, if it closes."""
    quote, index = value[0], 1
    while index < len(value):
        if quote == '"' and value[index] == "\\":
            index += 2
        elif value[index] == quote and quote == "'" and value[index + 1:index + 2] == "'":
            index += 2
        elif value[index] == quote:
            return index + 1
        else:
            index += 1
    return None


def scalar_kind(value: str, name: str, number: int) -> str:
    """Classify a value so that no value can absorb the lines after it.

    Quoted values and flow collections must close on their own line, and
    anchors, aliases, tags, and complex keys are not allowed. Returns "empty",
    "plain", "block", or "closed".
    """
    if not value or value.startswith("#"):
        return "empty"
    if value[0] in "&*!?%@`":
        raise ContentError(f"{name}:{number}: anchors, aliases, tags, and complex keys are not allowed")
    if value[0] in "|>":
        return "block"
    if value[0] in "'\"":
        end = quoted_end(value)
        if end is None or (value[end:].strip() and not re.match(r"\s+#", value[end:])):
            raise ContentError(f"{name}:{number}: open and close each quoted value on one line")
        return "closed"
    if value[0] in "[{":
        depth = 0
        for character in value:
            if character in "'\"&*!":
                raise ContentError(f"{name}:{number}: `[...]` and `{{...}}` values hold plain items only")
            depth += (character in "[{") - (character in "]}")
            if depth < 0:
                break
        if depth:
            raise ContentError(f"{name}:{number}: open and close each `[...]` or `{{...}}` on one line")
        return "closed"
    return "plain"


def pack_definitions(text: str, name: str) -> list[dict[str, object]]:
    """Return rule blocks with the fields this lint inspects.

    Packs use a YAML subset this text reader follows exactly: a block `rules:`
    list of `  - id: <id>` entries whose fields are `    key: value` lines, and
    values that cannot span into the lines after them. The pinned Telltale's
    `validate` then confirms it loads exactly these rules.
    """
    lines = text.splitlines()
    if not lines or lines[0].rstrip() != "version: 1":
        raise ContentError(f"{name}: the first line must be `version: 1`")
    definitions: list[dict[str, object]] = []
    section = None
    current: dict[str, object] | None = None
    field = None
    # Indentation that lines must exceed to continue an open plain or block value.
    continues_above: int | None = None
    for number, line in enumerate(lines, start=1):
        if line.startswith(("---", "...")):
            raise ContentError(f"{name}:{number}: YAML document markers are not allowed")
        if "\t" in line[: len(line) - len(line.lstrip())]:
            raise ContentError(f"{name}:{number}: indent with spaces")
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        if continues_above is not None and indent > continues_above:
            # Text of a plain or block value: YAML reads quotes and `#` literally here.
            if field == "status":
                raise ContentError(f"{name}:{number}: write `status: <maturity>` on one line")
            if section == "description" or field in DISPLAY_KEYS:
                check_display_text(line, name, number)
            continue
        continues_above = None
        if line.lstrip().startswith("#"):
            continue
        value, owner = node_value(line)
        if scalar_kind(value, name, number) in ("plain", "block"):
            continues_above = owner
        if indent == 0:
            key = line.partition(":")[0]
            if key not in TOP_LEVEL_KEYS:
                raise ContentError(f"{name}:{number}: unsupported top-level key `{key}`")
            section, current, field = key, None, None
            if key == "description":
                check_display_text(value, name, number)
            elif key == "rules" and value:
                raise ContentError(f"{name}:{number}: write `rules:` as a block list of `  - id: <id>` entries")
            elif key == "modifiers" and value != "[]":
                raise ContentError(f"{name}:{number}: community packs define no modifiers; use `modifiers: []`")
            continue
        if section == "description":
            check_display_text(line, name, number)
            continue
        if section != "rules":
            continue
        match = DEFINITION.match(line)
        if match:
            current = {"id": match.group(1), "line": number, "status": None}
            definitions.append(current)
            field = None
            continue
        if current is None or indent < 4:
            raise ContentError(f"{name}:{number}: write each rule as `  - id: <id>` "
                               "followed by fields indented four spaces")
        if indent == 4:
            keyed = RULE_FIELD.match(line)
            if not keyed:
                raise ContentError(f"{name}:{number}: rule fields are `    key: value` lines; "
                                   "indent nested content further")
            field = keyed.group(1)
            if field == "status":
                if value not in STATUS_VALUES:
                    raise ContentError(f"{name}:{number}: write `status: <maturity>` on one line")
                current["status"] = value.strip("'\"")
            elif field in DISPLAY_KEYS:
                check_display_text(value, name, number)
            continue
        # Nested content of the current field, such as a falsepositives item.
        if field == "status":
            raise ContentError(f"{name}:{number}: write `status: <maturity>` on one line")
        if field in DISPLAY_KEYS:
            check_display_text(line, name, number)
    return definitions


def check_display_text(value: str, name: str, number: int) -> None:
    # Quoted values close on their own line, so only a line with a double quote
    # can hold a YAML escape that decodes to markup or a link.
    if "<" in value or ">" in value or "://" in value or ("\\" in value and '"' in value):
        raise ContentError(f"{name}:{number}: display text must not contain markup, links, or escapes")


def scenario_expectations(root: Path) -> tuple[dict[str, set[str]], dict[str, set[str]], set[str]]:
    """Map rule IDs to adversarial scenarios that must match them and to
    benign scenarios that must not; also return every referenced ID."""
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
            data = json.loads(read_text(path, MAX_PACK_BYTES))
            expectations = data.get("rule_expectations", {})
            referenced.update(expectations.get("must_match", []), expectations.get("must_not_match", []))
            if kind == "adversarial":
                for rule_id in expectations.get("must_match", []):
                    must_match.setdefault(rule_id, set()).add(data["id"])
            if kind == "benign":
                for rule_id in expectations.get("must_not_match", []):
                    must_not_match.setdefault(rule_id, set()).add(data["id"])
    return must_match, must_not_match, referenced


def lint(root: Path) -> list[str]:
    """Return the linted rule IDs or raise ContentError."""
    metadata = load_metadata(root)
    prefix = metadata["rule_namespace"] + "."
    seen: dict[str, str] = {}
    for maturity, path in pack_paths(root):
        label = f"packs/{maturity}/{path.name}"
        definitions = pack_definitions(read_text(path, MAX_PACK_BYTES), label)
        if not definitions:
            raise ContentError(f"{label}: contains no rule definitions")
        for definition in definitions:
            rule_id = str(definition["id"])
            where = f"{label}:{definition['line']}"
            if not CANONICAL_ID.match(rule_id) or len(rule_id) > 96:
                raise ContentError(f"{where}: `{rule_id}` is not a canonical rule id")
            if not rule_id.startswith(prefix):
                raise ContentError(f"{where}: `{rule_id}` must start with `{prefix}`")
            if rule_id in seen:
                raise ContentError(f"{where}: `{rule_id}` is also defined in {seen[rule_id]}")
            seen[rule_id] = label
            if definition["status"] != maturity:
                raise ContentError(f"{where}: `{rule_id}` needs `status: {maturity}`")

    must_match, must_not_match, referenced = scenario_expectations(root)
    for rule_id in sorted(referenced):
        if rule_id.startswith(prefix) and rule_id not in seen:
            raise ContentError(f"a scenario expects unknown candidate `{rule_id}`")
    for rule_id in seen:
        if not (root / "docs" / "detections" / f"{rule_id}.md").is_file():
            raise ContentError(f"`{rule_id}` needs docs/detections/{rule_id}.md")
        if rule_id not in must_match:
            raise ContentError(f"`{rule_id}` needs an adversarial scenario that must match it")
        if rule_id not in must_not_match:
            raise ContentError(f"`{rule_id}` needs a benign scenario that must not match it")
    return sorted(seen)


def compose_package(root: Path, version: str, revision: str | None,
                    maturities: tuple[str, ...] = RELEASED_MATURITIES) -> str:
    """Compose one package document from pack files, preserving their text."""
    if not VERSION.match(version):
        raise ContentError(f"invalid package version `{version}`")
    metadata = load_metadata(root)
    lines = [
        "# Generated by telltale-detections scripts/community_package.py. Do not edit.",
        f"format: {PACKAGE_FORMAT}",
        f"id: {json.dumps(metadata['id'])}",
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
    lines.append("documents:")
    packs = pack_paths(root, maturities)
    if not packs:
        raise ContentError(f"no packs under packs/{{{','.join(maturities)}}}")
    for maturity, path in packs:
        text = read_text(path, MAX_PACK_BYTES)
        pack_definitions(text, f"packs/{maturity}/{path.name}")
        lines.append(f"  # packs/{maturity}/{path.name}")
        for index, line in enumerate(text.splitlines()):
            if index == 0:
                lines.append(f"  - {line}")
            else:
                lines.append(f"    {line}" if line.strip() else "")
    return "\n".join(lines) + "\n"


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


def require_pinned_telltale(root: Path, telltale: Path) -> str:
    """Return the binary's version line if it reports the revision in pins.json."""
    pins = json.loads((root / "pins.json").read_text(encoding="utf-8"))
    revision = pins["telltale"]["revision"][:12]
    version = run_telltale(telltale, "--version")
    if version.returncode or not re.search(rf"\({revision}[0-9a-f]*\)", version.stdout):
        raise ContentError(f"Telltale binary must report revision {revision} (pins.json)")
    return version.stdout.strip()


def install_candidate(root: Path, telltale: Path, config_dir: Path) -> Path:
    """Install every candidate pack, at any maturity, as the community package.

    A package with the community ID replaces the snapshot embedded in Telltale,
    so Telltale's package loader validates exactly the content under review.
    Returns the installed package path.
    """
    metadata = load_metadata(root)
    expected = {
        str(definition["id"])
        for maturity, pack in pack_paths(root)
        for definition in pack_definitions(read_text(pack, MAX_PACK_BYTES), f"packs/{maturity}/{pack.name}")
    }
    text = compose_package(root, CANDIDATE_VERSION, None, MATURITIES)
    packages = config_dir / "rule-packages.d"
    packages.mkdir(parents=True)
    path = packages / "telltale.community.candidate.yaml"
    path.write_text(text, encoding="utf-8")
    result = run_telltale(telltale, "rules", "validate", "--config-dir", str(config_dir))
    if result.returncode:
        raise ContentError(f"candidate package validation failed: {result.stderr.strip()[-2000:]}")
    try:
        report = json.loads(result.stdout)
        active = [(p["id"], p["version"], p["origin"], p["content_sha256"]) for p in report["packages"]]
        loaded = {entry["id"] for entry in report["provenance"]
                  if entry["id"].startswith(metadata["rule_namespace"] + ".")}
    except (ValueError, KeyError, TypeError) as exc:
        raise ContentError("Telltale did not report rule packages; "
                           "the pinned revision must support rule packages") from exc
    package = (metadata["id"], CANDIDATE_VERSION, "installed", sha256_bytes(text.encode("utf-8")))
    if active != [package]:
        raise ContentError(f"Telltale did not load the candidate package as the only package: {active}")
    # Compare with Telltale's own parse, so a rule the text lint could not see fails here.
    if loaded != expected:
        raise ContentError("Telltale loaded different candidate definitions than the lint checked: "
                           f"unexpected {sorted(loaded - expected)}, missing {sorted(expected - loaded)}")
    return path


def validate(root: Path, telltale: Path) -> str:
    """Lint, then confirm the pinned Telltale loads exactly the linted rules."""
    lint(root)
    version = require_pinned_telltale(root, telltale)
    with tempfile.TemporaryDirectory(prefix="telltale-candidate-") as tmp:
        install_candidate(root, telltale, Path(tmp))
    return version


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build(root: Path, version: str, revision: str | None, out: Path) -> Path:
    lint(root)
    package = compose_package(root, version, revision)
    out.mkdir(parents=True, exist_ok=True)
    metadata = load_metadata(root)
    path = out / f"{metadata['id']}-{version}.package.yaml"
    path.write_text(package, encoding="utf-8")
    (out / "SHA256SUMS").write_text(
        f"{sha256_bytes(package.encode('utf-8'))}  {path.name}\n", encoding="utf-8"
    )
    return path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("lint", help="check contribution policy for packs, scenarios, and notes")
    validated = sub.add_parser("validate", help="lint, then load every candidate pack in the pinned Telltale")
    validated.add_argument("--telltale", required=True, help="Telltale binary built at the pins.json revision")
    built = sub.add_parser("build", help="lint, then write the released package and SHA256SUMS")
    built.add_argument("--version", required=True, help="package version, such as 0.1.0")
    built.add_argument("--revision", help="full Git commit SHA the package is built from")
    built.add_argument("--out", required=True, help="output directory")
    args = parser.parse_args()
    try:
        if args.command == "lint":
            ids = lint(ROOT)
            print(f"lint ok: {len(ids)} definitions")
        elif args.command == "validate":
            version = validate(ROOT, Path(args.telltale))
            print(f"validate ok: {version} loaded every candidate pack")
        else:
            path = build(ROOT, args.version, args.revision, Path(args.out))
            print(f"package: {path}")
    except (ContentError, OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
