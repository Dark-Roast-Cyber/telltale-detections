#!/usr/bin/env bash
# Local Linux CI entrypoint. Only synthetic fixtures are generated and scanned.
set -euo pipefail

DETECTIONS_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAB_ROOT="${TELLTALE_LAB_ROOT:-$(cd "$DETECTIONS_ROOT/../telltale-lab" && pwd)}"
TELLTALE_SOURCE="${TELLTALE_SOURCE:-$(cd "$DETECTIONS_ROOT/../telltale" && pwd)}"
REPORT_ROOT="${1:-$(mktemp -d /tmp/telltale-daybreak-check.XXXXXX)}"

if [[ "$(git -C "$TELLTALE_SOURCE" rev-parse HEAD)" != 2e8c56aa45583525e4536640adb2c977ba45d46b ]]; then
  echo "Telltale source must be at 2e8c56aa45583525e4536640adb2c977ba45d46b" >&2
  exit 2
fi

if [[ -n "${TELLTALE_BIN:-}" ]]; then
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

python3 -m unittest discover -s "$LAB_ROOT/tests" -v
python3 -m unittest discover -s "$DETECTIONS_ROOT/tests" -v
python3 "$DETECTIONS_ROOT/scripts/check.py" \
  --lab "$LAB_ROOT" --telltale "$BINARY" --telltale-source "$TELLTALE_SOURCE" \
  --out "$REPORT_ROOT"

echo "Linux check complete; review $REPORT_ROOT/summary.json and per-case reports"
