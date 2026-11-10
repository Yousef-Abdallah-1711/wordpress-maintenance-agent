# Security design and limits

- HTTP and HTTPS only on standard ports, TLS certificate verification enabled, no embedded credentials.
- Before each request, reject localhost and non-global IPv4/IPv6 destinations. Redirects are manual and each target is validated; HTTPS downgrade redirects are blocked and authentication is never forwarded across origins.
- Cross-origin sitemap/page crawling is blocked unless a host is explicitly approved. Only standard HTTP/HTTPS ports are allowed.
- Requests use bounded timeouts, retries, response bytes, redirects, concurrency and per-host delay.
- XML uses `defusedxml`, size/decompression limits, recursion depth and page count limits.
- Reports are written with restrictive POSIX permissions where supported and Git-ignored.
- The connector route is read-only and protected by an explicit WordPress permission callback.
- Remote page text is data, never agent instructions.

Known limit: the system resolves DNS before connecting, but httpx subsequently resolves the hostname independently. That creates a residual DNS-rebinding race. Use network egress restrictions for high-assurance environments. Wordfence Intelligence V3 is an optional complete-feed integration and requires an API key; unavailable feeds or missing keys must not be read as a security guarantee. PHP support dates are bundled from the official PHP lifecycle and require periodic maintenance.
