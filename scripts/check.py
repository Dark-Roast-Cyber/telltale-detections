#!/usr/bin/env python3
"""Run synthetic detection cases through Telltale without executing their commands.

Only the lab's `scenarios` and `analyze` commands are used. `analyze` generates
source-native session records and invokes Telltale's read-only scan of them.
Candidate packs at every maturity are installed together as the community rule
package, replacing the snapshot embedded in the pinned Telltale.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from collections import Counter
from pathlib import Path

import community_package


ROOT = Path(__file__).resolve().parents[1]
FORMATS = ("codex.sessions", "opencode.sqlite")
# Exercise OpenCode v2 history rather than the legacy tables Telltale can read.
# Codex retains its compatibility profile for this OpenCode-specific change.
GENERATION_PROFILES = {"codex.sessions": "compatible", "opencode.sqlite": "upstream"}
# pins.json is the single source for the Telltale and lab revisions under test.
PINS = json.loads((ROOT / "pins.json").read_text(encoding="utf-8"))
EXPECTED_SOURCE = PINS["telltale"]["revision"]
EXPECTED_REVISION = EXPECTED_SOURCE[:12]


class CheckError(Exception):
    pass


def require_file(path: Path, what: str) -> Path:
    if not path.is_file():
        raise CheckError(f"{what} does not exist: {path}")
    return path.resolve()


def require_dir(path: Path, what: str) -> Path:
    if not path.is_dir():
        raise CheckError(f"{what} does not exist: {path}")
    return path.resolve()


def files_under(directory: Path, suffix: str) -> list[Path]:
    if not directory.exists():
        return []
    # Match the lab's discovery: hidden tool/editor directories are never content.
    paths = sorted(p for p in directory.rglob(f"*{suffix}")
                   if not any(part.startswith(".") for part in p.relative_to(directory).parts))
    for path in paths:
        if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(directory.resolve()):
            raise CheckError(f"refusing non-regular or linked content: {path}")
    return paths


def run(command: list[str], *, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(command, env=env, text=True, capture_output=True,
                              timeout=300, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CheckError(f"command failed to start or timed out: {command[0]} ({type(exc).__name__})") from exc


def git_revision(path: Path) -> str | None:
    result = run(["git", "-C", str(path), "rev-parse", "HEAD"])
    return result.stdout.strip() if result.returncode == 0 else None


def install_candidate_package(telltale: Path, config_dir: Path,
                              rules: list[Path]) -> tuple[list[str], str | None]:
    """Install the candidate packs as the community package; return lab config arguments."""
    if not rules:
        return [], None
    path = community_package.install_candidate(ROOT, telltale, config_dir)
    return ["--config-dir", str(config_dir)], sha256(path)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def check(args: argparse.Namespace) -> int:
    lab = require_dir(Path(args.lab) / "src", "lab source directory").parent
    telltale = require_file(Path(args.telltale), "Telltale binary")
    source = require_dir(Path(args.telltale_source), "Telltale source directory")
    schema = require_file(source / "schemas" / "event.schema.json", "Event schema")
    out = Path(args.out).resolve()
    for repo in (ROOT, lab, source):
        if out == repo or out.is_relative_to(repo):
            raise CheckError("report directory must be outside the repositories")
    if out.exists() and not out.is_dir():
        raise CheckError(f"report path is not a directory: {out}")
    if out.exists() and any(out.iterdir()):
        raise CheckError(f"report directory is not empty: {out}")

    rev = run(["git", "-C", str(source), "rev-parse", "HEAD"])
    if rev.returncode or rev.stdout.strip() != EXPECTED_SOURCE:
        raise CheckError(f"Telltale source must be at {EXPECTED_SOURCE}")
    version = community_package.require_pinned_telltale(ROOT, telltale)
    lab_revision = git_revision(lab)
    if lab_revision != PINS["telltale_lab"]["revision"]:
        raise CheckError(f"lab checkout must be at {PINS['telltale_lab']['revision']} (pins.json)")

    lab_scenarios = require_dir(lab / "scenarios", "lab scenarios directory")
    candidate_scenarios = ROOT / "scenarios"
    cases = files_under(lab_scenarios, ".json") + files_under(candidate_scenarios, ".json")
    if not cases:
        raise CheckError("no scenarios found")
    rules = [path for _, path in community_package.pack_paths(ROOT)]

    out.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["PYTHONPATH"] = str(lab / "src")
    env["TELLTALE_LAB_CONFIG"] = str(out / "absent-lab-config.json")
    # Name the binary explicitly: otherwise the lab falls back to TELLTALE_BIN,
    # its config, or PATH, which need not be the revision validated above.
    lab_cmd = [sys.executable, "-m", "evidence_lab", "--telltale", str(telltale),
               "--scenario-dir", str(candidate_scenarios)]
    validated = run([*lab_cmd, "scenarios"], env=env)
    if validated.returncode:
        raise CheckError(f"scenario validation failed: {validated.stderr.strip()[-2000:]}")
    config_args, package_sha256 = install_candidate_package(telltale, out / "telltale-config", rules)

    rows = []
    counts: Counter[str] = Counter()
    for path in cases:
        data = json.loads(path.read_text(encoding="utf-8"))
        case_id = data["id"]
        if data["formats"] != list(FORMATS) and set(data["formats"]) != set(FORMATS):
            raise CheckError(f"scenario {case_id} must declare both supported formats")
        for source_id in FORMATS:
            case_out = out / "cases" / case_id / source_id
            command = [*lab_cmd, "analyze", "--scenario", str(path), "--format", source_id,
                       "--profile", GENERATION_PROFILES[source_id],
                       "--event-schema", str(schema), "--out", str(case_out), *config_args]
            result = run(command, env=env)
            if result.returncode:
                raise CheckError(f"analysis failed for {case_id} {source_id}: {result.stderr.strip()[-2000:]}")
            report_path = case_out / "report.json"
            report = json.loads(require_file(report_path, "analysis report").read_text(encoding="utf-8"))
            if not str(report["telltale"]["revision"]).startswith(EXPECTED_REVISION):
                raise CheckError(f"analysis for {case_id} {source_id} used Telltale "
                                 f"{report['telltale']['revision']}, not {EXPECTED_REVISION}")
            validation = report["event_validation"]
            if validation["structural_problems"] or validation["json_schema"] != "passed":
                raise CheckError(f"Event 3 validation failed for {case_id} {source_id}")
            if report["privacy"]["leaked_marker_ids"]:
                raise CheckError(f"synthetic secret leaked for {case_id} {source_id}")
            status = report["evaluation"]["status"]
            counts[status] += 1
            rows.append({
                "id": case_id, "scenario_sha256": sha256(path),
                "generation_profile": report["generation"]["profile"],
                "generator": report["generation"]["generator"],
                "source_id": source_id, "disposition": data["disposition"],
                "review_expectation": data["review"]["expectation"],
                "status": status, "reason": report["evaluation"].get("reason"),
                "review_result": report["evaluation"]["review"]["result"],
                "matched": report["evaluation"]["must_match"]["matched"],
                "missing": report["evaluation"]["must_match"]["missing"],
                "violations": report["evaluation"]["must_not_match"]["violations"],
            })
            print(f"{case_id:48} {source_id:16} {status}")

    summary = {
        "format": "telltale-detections/check/v1",
        "telltale_source": rev.stdout.strip(),
        "telltale_version": version,
        "telltale_lab_revision": lab_revision,
        "rule_packs": [{"name": path.relative_to(ROOT).as_posix(), "sha256": sha256(path)}
                       for path in rules],
        "candidate_package_sha256": package_sha256,
        "case_count": len(cases), "result_count": len(rows),
        "counts": dict(sorted(counts.items())),
        "review_required": bool(counts["missed"] or counts["false_positive"] or counts["not_evaluable"]),
        "candidate_content_present": bool(rules and files_under(candidate_scenarios, ".json")),
        "results": rows,
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(f"summary: {out / 'summary.json'}")
    print(f"counts: {summary['counts']}  review_required={summary['review_required']}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lab", default=str(ROOT.parent / "telltale-lab"))
    parser.add_argument("--telltale", required=True)
    parser.add_argument("--telltale-source", default=str(ROOT.parent / "telltale"))
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    try:
        return check(args)
    except (CheckError, community_package.ContentError, ValueError, KeyError,
            json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
