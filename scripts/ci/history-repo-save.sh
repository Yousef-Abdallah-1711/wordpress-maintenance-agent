#!/usr/bin/env bash
# Commit new history snapshots and the report archive to the private history repository.
# Inputs (environment only): HISTORY_REPO, HISTORY_KEY, REPORT_DIR, RETENTION_DAYS, RUNNER_TEMP, GITHUB_RUN_ID
set -euo pipefail

if [ ! -d history-repo/.git ]; then
  echo "History repository was not loaded; nothing to save."
  exit 0
fi

umask 077
key_file="${RUNNER_TEMP}/wpm_history_key"
known_hosts="${RUNNER_TEMP}/wpm_known_hosts"
printf '%s\n' "${HISTORY_KEY}" > "${key_file}"
trap 'rm -f "${key_file}"' EXIT
export GIT_SSH_COMMAND="ssh -i ${key_file} -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=${known_hosts}"

cd history-repo
git config user.name "github-actions[bot]"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com"

if [ -n "${REPORT_DIR:-}" ] && [ -d "../${REPORT_DIR}" ]; then
  name="$(basename "${REPORT_DIR}")"
  dest="archive/${name}/${GITHUB_RUN_ID}"
  mkdir -p "${dest}"
  cp -R "../${REPORT_DIR}/." "${dest}/"
fi

# Retention: drop archived report folders older than RETENTION_DAYS (folder names start with YYYY-MM-DD).
cutoff="$(date -u -d "-${RETENTION_DAYS:-365} days" +%Y-%m-%d)"
if [ -d archive ]; then
  for dir in archive/*; do
    [ -d "$dir" ] || continue
    day="$(basename "$dir")"; day="${day:0:10}"
    if [[ "$day" < "$cutoff" ]]; then rm -rf "$dir"; fi
  done
fi

git add -A
if git diff --cached --quiet; then
  echo "No history changes to commit."
  exit 0
fi
git commit -m "Audit run ${GITHUB_RUN_ID}" --quiet
for attempt in 1 2 3; do
  if git push --quiet origin HEAD; then
    local_sha="$(git rev-parse HEAD)"
    remote_sha="$(git ls-remote origin HEAD | cut -f1)"
    if [ "${local_sha}" != "${remote_sha}" ]; then
      echo "::error title=History verification failed::The pushed commit is not the remote head."
      exit 1
    fi
    snapshots="$(find history -name '*.json' 2>/dev/null | wc -l | tr -d ' ')"
    echo "History saved and verified on the remote (commit ${local_sha:0:7}, ${snapshots} snapshots)."
    {
      echo "### Private history"
      echo "- Snapshot saved and verified on the history repository (commit \`${local_sha:0:7}\`, ${snapshots} snapshots total)."
    } >> "${GITHUB_STEP_SUMMARY:-/dev/null}"
    exit 0
  fi
  git pull --rebase --quiet origin HEAD || true
done
echo "::error title=History not saved::Could not push to the history repository after 3 attempts."
exit 1
