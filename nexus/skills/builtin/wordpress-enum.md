---
name: wordpress-enum
description: When a site is fingerprinted as WordPress, enumerate and check known vulns
triggers: [wordpress, wp-content, wp-login, wpscan]
source: builtin
---
When whatweb/httpx/nuclei identifies WordPress on a URL:
1. Run `wpscan` against the URL to enumerate core version, themes, and plugins.
2. Run `nuclei` with WordPress/`cms` templates for known-CVE checks.
3. For each plugin/theme version reported, expect CVE enrichment to match NVD/OSV entries;
   prioritize plugins with a KEV or high-EPSS CVE.
4. If a login page is exposed, consider `nuclei-default-login` for weak/default credentials.
