#!/usr/bin/env bash
# Run the batch audit. All values arrive through environment variables and are passed as quoted arguments.
# The script never fails the step itself: the exit code is exposed as an output so that reports, history and
# artifacts are always saved before the job is failed by the final "Enforce audit result" step.
set -uo pipefail

args=(--scope "${INPUT_SCOPE:-all}" --report-mode "${INPUT_REPORT_MODE:-standard}" --output reports
      --run-id "${GITHUB_RUN_ID:-local}" --fail-on "${FAIL_ON:-critical,incomplete}"
      --retention-days "${RETENTION_DAYS:-365}")
if [ -n "${INPUT_SITE_ID:-}" ]; then args+=(--site "${INPUT_SITE_ID}"); fi
if [ -n "${INPUT_CUSTOM_URL:-}" ]; then args+=(--url "${INPUT_CUSTOM_URL}"); fi
if [ -n "${INPUT_MAX_URLS:-}" ]; then args+=(--max-urls "${INPUT_MAX_URLS}"); fi
if [ -n "${HISTORY_DIR:-}" ]; then mkdir -p "${HISTORY_DIR}"; args+=(--history-dir "${HISTORY_DIR}"); fi
if [ "${NOTIFY_ISSUES:-}" = "true" ]; then
  args+=(--notify github-issues)
  if [ "${ISSUES_ALLOW_PUBLIC:-}" = "true" ]; then args+=(--allow-public-issues); fi
fi

wp-maintenance audit-batch "${args[@]}"
code=$?
echo "exit_code=${code}" >> "${GITHUB_OUTPUT}"
exit 0
