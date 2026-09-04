---
name: exposed-secrets
description: When a source path, repo, or web root may hold secrets, scan for them
triggers: [secret, gitleaks, api key, token, .git, credentials, trufflehog]
source: builtin
---
When a filesystem path, exposed .git directory, or code artifact is reachable:
1. Run `gitleaks detect` over the source path to find committed secrets.
2. Run `trivy fs` / `grype` over the path for dependency CVEs at the same time.
3. Any confirmed secret is a critical finding; capture the file:line but never the secret value
   in the report evidence.
