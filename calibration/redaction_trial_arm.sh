#!/bin/bash
# Arms ONE approved live attempt of the M7-12 redaction trial (Scope B). Read it before arming.
#
#   calibration/redaction_trial_arm.sh <start YYYY-MM-DDTHH:MM, UTC> <attempt 1|2> \
#       <expected HEAD sha> <worktree> <out dir> <env file>
#
# It waits for the start time, and sends only inside the two hours from it (the window is
# start + 2 h). The harness holds the window itself: it refuses to start unless the plan's
# estimate plus a margin ends before the window closes, and it sends no check within 10 seconds of
# it (it stops with run_stopped "window_closed", exit 3). It refuses, sending nothing, if anything
# differs from what was approved: the commit, a clean tree, the approved rows, counts, seed,
# margins and ceilings, every source file's hash, or if a run was already made into <out dir>
# (every attempt writes to a directory of its own). One run per attempt: the harness keeps a lock
# and a marker for each attempt outside <out dir> and the worktree (see Attempt in the harness),
# so a second arming of the same attempt into any directory is refused, and attempt 2 is refused
# unless attempt 1 has started. No marker is removed or bypassed. The key is read from the env
# file into this process only and is never printed. No tracing: do not run it under `bash -x`.
set -u
STARTARG=${1:?start time (YYYY-MM-DDTHH:MM, UTC)}; ATTEMPT=${2:?attempt (1 or 2)}
EXPECT_HEAD=${3:?head sha}; WT=${4:?worktree}; OUT=${5:?out dir}; ENVFILE=${6:?env file}
MANIFEST=calibration/results/m7-12-trial-manifest.json
case "$STARTARG" in
  [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]) ;;
  *) echo "the start time must look like 2026-11-26T08:00 (UTC)" >&2; exit 2 ;;
esac
case "$ATTEMPT" in 1|2) ;; *) echo "the attempt must be 1 or 2" >&2; exit 2 ;; esac
START=$(date -u -d "${STARTARG/T/ }:00" +%s) || { echo "not a time: $STARTARG" >&2; exit 2; }
END=$((START + 7200))
mkdir -p "$OUT"
fail() { echo "$1" > "$OUT/RESULT"; date -u >> "$OUT/RESULT"; exit "${2:-3}"; }
[ -e "$OUT/RESULT" ] && { echo "a run was already armed into $OUT" >&2; exit 3; }
[ -e "$OUT/records.jsonl" ] && fail "records already exist; nothing sent"
echo "waiting" > "$OUT/RESULT"
while [ "$(date -u +%s)" -lt "$START" ]; do sleep 30; done
[ "$(date -u +%s)" -le "$END" ] || fail "missed the window; nothing sent"
cd "$WT" || fail "no worktree; nothing sent"
export UV_LINK_MODE=copy
unset GEMINI_API_KEY
[ "$(git rev-parse HEAD)" = "$EXPECT_HEAD" ] || fail "worktree HEAD changed; nothing sent"
[ -z "$(git status --porcelain)" ] || fail "worktree not clean; nothing sent"
[ -s "$ENVFILE" ] || fail "no key file; nothing sent"
PLAN=$(uv run --frozen python -m calibration.redaction_trial plan --manifest "$MANIFEST") \
  || fail "the manifest does not verify; nothing sent"
echo "$PLAN" > "$OUT/plan.json"
set -a; . "$ENVFILE"; set +a
[ -n "${GEMINI_API_KEY:-}" ] || fail "no key in the env file; nothing sent"
echo "running" > "$OUT/RESULT"; date -u >> "$OUT/RESULT"
DEADLINE=$(date -u -d "@$END" +%Y-%m-%dT%H:%M:%S+00:00)
uv run --frozen python -m calibration.redaction_trial run --live --deadline "$DEADLINE" \
  --attempt "$ATTEMPT" --manifest "$MANIFEST" --out "$OUT/records.jsonl" > "$OUT/run.log" 2>&1
CODE=$?
uv run --frozen python -m calibration.redaction_trial report "$OUT/records.jsonl" \
  --manifest "$MANIFEST" --json "$OUT/report.json" > "$OUT/report.md" 2>> "$OUT/run.log"
echo "finished exit=$CODE" > "$OUT/RESULT"; date -u >> "$OUT/RESULT"
exit "$CODE"
