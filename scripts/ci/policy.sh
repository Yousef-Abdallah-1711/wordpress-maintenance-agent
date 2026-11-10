#!/usr/bin/env bash
# Decide where audit history lives and whether reports may be uploaded as artifacts.
# Inputs (environment only): GH_TOKEN, GITHUB_REPOSITORY, HISTORY_REPO, HISTORY_KEY_SET, PUBLIC_ARTIFACTS
set -euo pipefail

private="$(gh api "repos/${GITHUB_REPOSITORY}" --jq '.private')"
backend="none"
upload="false"

if [ -n "${HISTORY_REPO:-}" ]; then
  if ! [[ "${HISTORY_REPO}" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
    echo "::error title=Invalid history repository::WP_MAINTENANCE_HISTORY_REPO must look like owner/name."
    exit 1
  fi
  if [ "${HISTORY_KEY_SET:-false}" = "true" ]; then
    backend="repo"
  else
    echo "::warning title=History repository ignored::WP_MAINTENANCE_HISTORY_REPO is set but the WP_MAINTENANCE_HISTORY_DEPLOY_KEY secret is missing."
  fi
fi

if [ "$private" = "true" ] || [ "${PUBLIC_ARTIFACTS:-}" = "true" ]; then
  upload="true"
fi
if [ "$backend" = "none" ] && [ "$upload" = "true" ]; then
  backend="artifact"
fi

history_dir=""
case "$backend" in
  repo) history_dir="history-repo/history" ;;
  artifact) history_dir="history-state" ;;
esac

{
  echo "history_backend=${backend}"
  echo "upload_artifacts=${upload}"
  echo "history_dir=${history_dir}"
} >> "$GITHUB_OUTPUT"

{
  echo "### Report storage"
  echo "- Repository visibility: $([ "$private" = "true" ] && echo private || echo public)"
  echo "- History backend: \`${backend}\`"
  echo "- Report artifacts: $([ "$upload" = "true" ] && echo uploaded || echo 'not uploaded')"
  if [ "$private" != "true" ] && [ "$upload" != "true" ]; then
    echo "- Reports and history are **not** stored: this repository is public, so artifacts would be visible to anyone."
    echo "  Configure a private history repository (docs/GITHUB_ACTIONS.md) or set \`WP_MAINTENANCE_PUBLIC_ARTIFACTS=true\` if the reports may be public."
  fi
  if [ "$private" != "true" ] && [ "$upload" = "true" ] && [ "$backend" = "artifact" ]; then
    echo "- :warning: This repository is public: report artifacts are visible to GitHub users who can read the repository."
  fi
} >> "$GITHUB_STEP_SUMMARY"
