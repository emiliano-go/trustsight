#!/usr/bin/env bash
# Gather fp_triage evidence for one alert from sibling checkouts.
set -euo pipefail

slug=${1:?usage: scripts/fp_evidence.sh <YYYY-MM-DD/HHMMSS> [out.json]}
out=${2:-fp-evidence.json}
harness=${TRUSTSIGHT_HARNESS:-../trustsight-harness}

cd "$harness"
uv run python -m harness fp_triage \
  --alert-slug "$slug" --out "$(pwd)/$out"
echo "wrote $harness/$out"
