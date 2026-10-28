---
name: Bug report
about: Something in SSLense does not work as expected
labels: bug
---

<!--
Security problems: do not open a public issue. Report them privately as described in SECURITY.md.
-->

**What happened**
A clear description of the problem, and what you expected instead.

**Steps to reproduce**
1.
2.

**Environment**
- SSLense version:
- Windows Server version:
- How the site is reached from the internet (public IP, NAT, reverse proxy, Cloudflare Tunnel, ...):
- Let's Encrypt environment (staging or production):

**Health check**
Run `SSLense.Cli health` in an elevated terminal and paste the output:

```
paste here
```

**Diagnostic bundle**
Run `SSLense.Cli diagnostics` (add `--redact-hosts` if your host names are private) and attach the zip.
Secrets are removed automatically, but please review the files before attaching them.
