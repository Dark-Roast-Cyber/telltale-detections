#!/usr/bin/env bash
# Local Linux CI entrypoint. Only synthetic fixtures are generated and scanned.
set -euo pipefail

DETECTIONS_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAB_ROOT="${TELLTALE_LAB_ROOT:-$(cd "$DETECTIONS_ROOT/../telltale-lab" && pwd)}"
TELLTALE_SOURCE="${TELLTALE_SOURCE:-$(cd "$DETECTIONS_ROOT/../telltale" && pwd)}"
REPORT_ROOT="${1:-$(mktemp -d /tmp/telltale-daybreak-check.XXXXXX)}"

EXPECTED_SOURCE="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["telltale"]["revision"])' "$DETECTIONS_ROOT/pins.json")"
if [[ "$(git -C "$TELLTALE_SOURCE" rev-parse HEAD)" != "$EXPECTED_SOURCE" ]]; then
  echo "Telltale source must be at $EXPECTED_SOURCE (pins.json)" >&2
  exit 2
fi

if [[ -n "${TELLTALE_BIN:-}" ]]; then
  if [[ ! -x "$TELLTALE_BIN" ]]; then
    echo "TELLTALE_BIN is not an executable file: $TELLTALE_BIN (unset it to build)" >&2
    exit 2
  fi
  BINARY="$TELLTALE_BIN"
else
  TARGET_DIR="${TELLTALE_TARGET_DIR:-/tmp/telltale-daybreak-target}"
  (cd "$TELLTALE_SOURCE" && CARGO_TARGET_DIR="$TARGET_DIR" cargo build --release --locked --offline --bin telltale)
  BINARY="$TARGET_DIR/release/telltale"
fi

export PYTHONDONTWRITEBYTECODE=1
export TELLTALE_BIN="$BINARY"
export TELLTALE_LAB_ROOT="$LAB_ROOT"
export TELLTALE_SOURCE

python3 "$DETECTIONS_ROOT/scripts/community_package.py" lint
# The lab's own characterization tests run in the lab repository; this gate
# uses only the lab's `scenarios` and `analyze` commands at the pinned revision.
python3 -m unittest discover -s "$DETECTIONS_ROOT/tests" -v
python3 "$DETECTIONS_ROOT/scripts/check.py" \
  --lab "$LAB_ROOT" --telltale "$BINARY" --telltale-source "$TELLTALE_SOURCE" \
  --out "$REPORT_ROOT"

echo "Linux check complete; review $REPORT_ROOT/summary.json and per-case reports"
