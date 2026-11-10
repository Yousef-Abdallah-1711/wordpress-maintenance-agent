#!/usr/bin/env bash
# Clone the private history repository with a repository-scoped deploy key (never a personal token).
# Inputs (environment only): HISTORY_REPO (owner/name), HISTORY_KEY (private deploy key), RUNNER_TEMP
set -euo pipefail

if ! [[ "${HISTORY_REPO}" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
  echo "::error title=Invalid history repository::WP_MAINTENANCE_HISTORY_REPO must look like owner/name."
  exit 1
fi

umask 077
key_file="${RUNNER_TEMP}/wpm_history_key"
known_hosts="${RUNNER_TEMP}/wpm_known_hosts"
printf '%s\n' "${HISTORY_KEY}" > "${key_file}"
# Host keys come from GitHub's published metadata over TLS, not from a first-use scan.
curl -fsSL https://api.github.com/meta \
  | python -c 'import json,sys; print("\n".join("github.com " + k for k in json.load(sys.stdin)["ssh_keys"]))' > "${known_hosts}"

export GIT_SSH_COMMAND="ssh -i ${key_file} -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=${known_hosts}"
rm -rf history-repo
if git clone --depth 1 "git@github.com:${HISTORY_REPO}.git" history-repo; then
  mkdir -p history-repo/history
  echo "Loaded history repository (history snapshots: $(find history-repo/history -name '*.json' 2>/dev/null | wc -l))."
else
  rm -f "${key_file}"
  echo "::error title=History repository unavailable::Could not clone ${HISTORY_REPO}. Check the deploy key and repository name."
  exit 1
fi
rm -f "${key_file}"
