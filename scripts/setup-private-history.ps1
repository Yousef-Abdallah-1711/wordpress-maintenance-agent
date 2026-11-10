# One-time setup of the PRIVATE history repository credentials (Windows PowerShell version).
#   powershell -File scripts\setup-private-history.ps1 -Owner Yousef-Abdallah-1711
# Creates a throw-away ed25519 key, registers the public half as a write deploy key on the history repository ONLY,
# stores the private half as the Actions secret WP_MAINTENANCE_HISTORY_DEPLOY_KEY on the source repository, sets the
# WP_MAINTENANCE_HISTORY_REPO variable, then deletes the local key files. Nothing secret is printed.
param(
  [Parameter(Mandatory = $true)][string]$Owner,
  [string]$SourceRepo = "$Owner/wordpress-maintenance-agent",
  [string]$HistoryRepo = "$Owner/wordpress-maintenance-history"
)
$ErrorActionPreference = "Stop"
$title = "wp-maintenance Actions history (write, this repository only)"

gh auth status | Out-Null
gh repo view $HistoryRepo 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) {
  gh repo create $HistoryRepo --private --add-readme --description "Private audit history for wordpress-maintenance-agent (generated)"
}
if ((gh repo view $HistoryRepo --json isPrivate --jq .isPrivate) -ne "true") { throw "Refusing to continue: $HistoryRepo is NOT private." }

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("wpm-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
  ssh-keygen -t ed25519 -N '""' -C "wp-maintenance-history" -f (Join-Path $tmp "key") -q
  foreach ($id in (gh api "repos/$HistoryRepo/keys" --jq ".[] | select(.title == `"$title`") | .id")) {
    if ($id) { gh api -X DELETE "repos/$HistoryRepo/keys/$id" | Out-Null }
  }
  gh repo deploy-key add (Join-Path $tmp "key.pub") --repo $HistoryRepo --title $title --allow-write
  Get-Content -Raw (Join-Path $tmp "key") | gh secret set WP_MAINTENANCE_HISTORY_DEPLOY_KEY --repo $SourceRepo
  gh variable set WP_MAINTENANCE_HISTORY_REPO --repo $SourceRepo --body $HistoryRepo
  Write-Host "Private history configured: $HistoryRepo <- $SourceRepo"
} finally {
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
