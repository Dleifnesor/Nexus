---
name: tls-audit
description: When an HTTPS/TLS service is found, audit for protocol and cipher weaknesses
triggers: [tls, ssl, https, 443, certificate]
source: builtin
---
For any host:port exposing TLS:
1. Run `testssl` to enumerate protocol versions, cipher suites, and known issues
   (e.g. deprecated TLS1.0/1.1, weak ciphers, expired/misissued certs).
2. Run `ssh-audit` for SSH services in parallel where applicable.
3. Treat expired or self-signed certificates and weak protocols as low/medium findings unless
   tied to a specific CVE.
