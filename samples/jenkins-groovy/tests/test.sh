#!/usr/bin/env bash
# tests/test.sh  (FIXED — entry point Harbor calls to score a run)
# Scores /app against this range's manifest using the vendored rewardkit runtime. The runtime
# and criterion code are identical for every range in the subdomain; only manifest.json
# differs (doc 02 §3.0).
# NOTE: no `set -e` — we must ALWAYS write the reward file, even if the runtime errors.
set -uo pipefail

: "${REWARDKIT_JUDGE:=}"   # optional Tier-3 judge (provider/model); Tier 1+2 run without it

here="$(cd "$(dirname "$0")" && pwd)"          # the /tests directory (copied in by Harbor)
export PYTHONPATH="$here:${PYTHONPATH:-}"       # so `rewardkit` and `criteria` import
app="${RK_APP:-/app}"                           # the agent's workspace (deliverables)
out="${RK_OUT:-/logs/verifier}"                 # Harbor reads the reward from here
mkdir -p "$out"

python3 -m rewardkit --tests "$here" --app "$app" --disk "${RK_DISK:-/disk}" --sas "${RK_SAS:-/sas}" || true

# Harbor reads the numeric reward (float in [0,1]) from /logs/verifier/reward.txt. Always
# (re)write it — never trust a pre-existing file the agent may have dropped in /app.
reward="$(python3 -c "import os,json; p='$app/reward.json'; print(json.load(open(p))['reward'] if os.path.exists(p) else 0.0)" 2>/dev/null || echo 0.0)"
[ -z "$reward" ] && reward=0.0
printf '%s\n' "$reward" > "$out/reward.txt"
# IMPORTANT: the filename `reward.json` in /logs/verifier is RESERVED by Harbor — if present it
# is preferred over reward.txt and parsed as dict[str,float|int], so EVERY value must be numeric.
# The runtime's /app/reward.json is a human diagnostic that carries non-numeric fields (the
# `outcome` status string, and a null `quality` when the Tier-3 judge is off) — copying it here
# verbatim makes Harbor raise a ValidationError. Preserve it under a non-reserved name instead.
[ -f "$app/reward.json" ] && cp "$app/reward.json" "$out/reward-full.json" 2>/dev/null || true
echo "reward=$reward"
exit 0
