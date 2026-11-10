# Security design and limits

- HTTP and HTTPS only on standard ports, TLS certificate verification enabled, no embedded credentials.
- DNS is resolved at connection time, every resolved address must be globally routable, and the socket connects to one of those exact validated IPs while retaining the original Host header and TLS SNI. Environment proxies are disabled.
- Redirects are manual and each target is validated; HTTPS downgrade redirects are blocked, authenticated requests require HTTPS, authorization never crosses origins, and response cookies are never sent.
- Cross-origin sitemap/page crawling is blocked unless a host is explicitly approved. Only standard HTTP/HTTPS ports are allowed.
- Requests use bounded timeouts, retries, response bytes, redirects, concurrency and per-host delay.
- XML uses `defusedxml`, size/decompression limits, recursion depth and page count limits.
- Reports are written with restrictive POSIX permissions where supported and Git-ignored.
- The connector route is read-only and protected by an explicit WordPress permission callback.
- Remote page text is data, never agent instructions.

Wordfence Intelligence V3 is an optional complete-feed integration and requires an API key; unavailable feeds or missing keys must not be read as a security guarantee. PHP support dates are bundled from the official PHP lifecycle and require periodic maintenance.
