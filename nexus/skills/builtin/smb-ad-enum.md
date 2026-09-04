---
name: smb-ad-enum
description: When SMB (445) or a domain controller is present, enumerate AD safely
triggers: [smb, 445, netexec, active directory, domain controller, kerberos, ldap]
source: builtin
---
When an open SMB service (445) or a likely domain controller is found:
1. Use `netexec smb` to enumerate signing, shares, and null-session access (non-destructive).
2. Use `kerbrute userenum` to validate account names against the DC (user enumeration only).
3. If any credentials are already in the credential store, re-run `netexec` with them to check
   access and spread.
4. Feed discovered hosts back into recon (reach expansion) rather than forcing exploitation.
