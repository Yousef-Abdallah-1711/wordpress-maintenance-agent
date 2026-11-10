# Configuration

Copy `examples/sites.example.yaml` to `wp-maintenance.yaml` (ignored by Git). Required fields are `sites[].id`, `name`, and `url`. IDs are unique and URL hosts are validated at request time.

Use `environment` (`production`, `staging`, `development`), `access_mode` (`public`, `authenticated`), `credentials_ref`, `approved_hosts`, `exclude_paths`, and `sitemap_urls` per site. Global audit settings bound crawl size, XML bytes/depth, redirects, concurrency, delay, timeout and retries. `reports.directory` and `retention_days` configure report storage. The timezone is an IANA zone label; scheduler backends may use machine-local time instead. `notifications` records desired status preferences and a webhook environment-variable reference; outbound notification delivery is not implemented in this release.

Credentials use `${ENV_NAME}` or `${ENV_NAME:-default}` expansion. For authenticated sites, `credentials_ref` names an environment variable containing `username:application-password`. The password is never written into a report or config. `.env.example` documents names only; the CLI does not automatically load `.env` files.
