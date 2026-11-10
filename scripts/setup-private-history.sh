#!/usr/bin/env bash
# One-time setup of the PRIVATE history repository credentials for the weekly workflow.
# Run it yourself from a machine where `gh` is logged in as a repository ADMIN:
#   bash scripts/setup-private-history.sh OWNER [SOURCE_REPO] [HISTORY_REPO]
#
# It creates (if missing) a PRIVATE history repository, generates a throw-away ed25519 key pair, registers the
# PUBLIC half as a write deploy key on the history repository ONLY, stores the PRIVATE half as the Actions secret
# WP_MAINTENANCE_HISTORY_DEPLOY_KEY on the source repository, sets the WP_MAINTENANCE_HISTORY_REPO variable and
# deletes the local key files. Nothing is printed. Re-running rotates the key.
set -euo pipefail

owner="${1:?usage: setup-private-history.sh OWNER [SOURCE_REPO] [HISTORY_REPO]}"
source_repo="${2:-${owner}/wordpress-maintenance-agent}"
history_repo="${3:-${owner}/wordpress-maintenance-history}"
title="wp-maintenance Actions history (write, this repository only)"

gh auth status >/dev/null

if ! gh repo view "${history_repo}" >/dev/null 2>&1; then
  gh repo create "${history_repo}" --private --add-readme \
    --description "Private audit history for wordpress-maintenance-agent (generated)"
fi
if [ "$(gh repo view "${history_repo}" --json isPrivate --jq .isPrivate)" != "true" ]; then
  echo "Refusing to continue: ${history_repo} is NOT private." >&2
  exit 1
fi

tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT
umask 077
ssh-keygen -t ed25519 -N "" -C "wp-maintenance-history" -f "${tmp}/key" -q

# Rotate: remove earlier deploy keys created by this script.
for id in $(gh api "repos/${history_repo}/keys" --jq ".[] | select(.title == \"${title}\") | .id"); do
  gh api -X DELETE "repos/${history_repo}/keys/${id}" >/dev/null
done
gh repo deploy-key add "${tmp}/key.pub" --repo "${history_repo}" --title "${title}" --allow-write
gh secret set WP_MAINTENANCE_HISTORY_DEPLOY_KEY --repo "${source_repo}" < "${tmp}/key"
gh variable set WP_MAINTENANCE_HISTORY_REPO --repo "${source_repo}" --body "${history_repo}"

echo "Private history configured: ${history_repo} <- ${source_repo}"
echo "Next: Actions -> WordPress Maintenance Audit -> Run workflow (twice) to create and compare snapshots."
