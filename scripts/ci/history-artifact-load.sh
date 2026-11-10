#!/usr/bin/env bash
# Restore the previous run's history state from the newest unexpired "wp-maintenance-history" artifact.
# Inputs (environment only): GH_TOKEN, GITHUB_REPOSITORY, RUNNER_TEMP
set -euo pipefail

mkdir -p history-state
id="$(gh api "repos/${GITHUB_REPOSITORY}/actions/artifacts?name=wp-maintenance-history&per_page=10" \
  --jq '[.artifacts[] | select(.expired == false)] | sort_by(.created_at) | last | .id // empty')"
if [ -z "${id}" ]; then
  echo "No previous history artifact found; this run becomes the baseline."
  exit 0
fi
gh api "repos/${GITHUB_REPOSITORY}/actions/artifacts/${id}/zip" > "${RUNNER_TEMP}/history.zip"
unzip -q -o "${RUNNER_TEMP}/history.zip" -d history-state
echo "Restored history from artifact ${id} (snapshots: $(find history-state -name '*.json' | wc -l))."
