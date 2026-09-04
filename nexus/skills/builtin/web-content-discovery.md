---
name: web-content-discovery
description: When a live web server is found, discover hidden content and endpoints
triggers: [http, https, web, url, 80, 8080, 8443]
source: builtin
---
For a live HTTP(S) service:
1. Fingerprint with `whatweb`/`httpx`, then check for a WAF with `wafw00f`.
2. Enumerate content with `ffuf` against a common wordlist; feed 200/301/403 hits back as URLs.
3. Pull historical URLs with `gau` for additional endpoints.
4. Route dynamic parameters to `sqlmap` (SQLi) and `dalfox` (XSS) for validation only.
