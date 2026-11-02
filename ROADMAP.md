# SSLense Roadmap

SSLense is free and open source under the [Apache License 2.0](LICENSE). This roadmap describes how it gets to a dependable 1.0 release and what comes after. It replaces the earlier commercial roadmap; commercial plans are on hold and may be revisited later.

## 1. Principles

- Certificate renewal is safe, automatic, observable, and recoverable.
- A failed operation never leaves a site without its previous working binding.
- Private keys and credentials are never logged or transmitted unexpectedly.
- GUI, CLI, and service call the same Core operations.
- Destructive actions require explicit confirmation.
- Let's Encrypt staging is the default; production requires an explicit choice.

## 2. Current status

Complete:

- IIS site and binding discovery; HTTP-01 issuance against separated Let's Encrypt staging and guarded production
- Certificate-store installation with non-exportable keys and no retained PFX files; SNI binding management with live HTTPS verification and automatic rollback
- Automatic renewal service: ARI-aware scheduling with a lifetime-relative fallback (also used when the CA's renewal window times out), a persisted retry schedule, hourly checks, rate-limit handling, and escalating failure notifications
- Notifications by email (any SMTP setup, including IP-based relays), Teams, Slack, Discord, Telegram, ntfy, generic webhooks, a heartbeat ping, and the Windows Event Log
- Certificates from other providers such as 123-reg (0.10): certificate requests (CSRs) whose private key is a non-exportable machine key, completion with the issued certificate and bundle, PFX import, and adoption of certificates already bound in IIS. Every install is validated first (host coverage, validity, server-authentication purpose, key match, and the full chain with its dates) and uses the same journal, HTTPS verification, and rollback as Let's Encrypt.
- Certificate authority profiles in place of the hard-coded Let's Encrypt environment (0.10): the groundwork for other ACME CAs
- Expiry reminders (0.11): one daily digest, sent only when a certificate needs attention, from a configurable number of days before expiry and repeating until it is renewed; a notice before each automatic renewal; per-certificate snooze, off until replaced, or off permanently; an optional weekly summary; and detection of certificates renewed outside SSLense
- Cross-process per-site locking, durable operation journals, and non-fatal startup recovery
- Health check (CLI and GUI) and redacted diagnostic bundles for support
- Versioned state schemas with backup before migration and safe refusal of newer schemas
- `C:\ProgramData\SSLense` restricted to Administrators and SYSTEM, with link-safe hardening
- WPF GUI (Dashboard, Issue Certificate, Other Providers, Certificate Details, Settings, Health, Logs) and matching CLI; the window header shows the quick health check result
- Log viewer with level and text filters, selectable and copyable text, older days and backups, and Clear log that keeps a backup; every SSLense process writes the shared log under one machine-wide lock
- .NET 10 (LTS); self-contained WiX v7 MSI with service registration, upgrades, and silent install
- Branding (icon and logo) across the apps, shortcut, and Add/Remove Programs

A real production issuance remains a manual acceptance test and is never run during development.

The first installation on a real server (October 31, 2026) found the problems fixed in 0.10.1 to 0.10.5: an FTP-only site broke site listing, the log folder could not be opened, and several screens hid their results.

## 3. Certificate lifetime requirements

Scheduling must not assume 90-day certificates.

- Let's Encrypt moved its staging default to 64-day certificates on October 14, 2026, and plans the same for production on February 10, 2027.
- Default lifetimes are expected to keep decreasing toward 45 days.
- SSLense uses ACME Renewal Information (ARI, RFC 9773) and falls back to lifetime-relative scheduling.

References:

- [Let's Encrypt: 64-Day Certificate Lifetimes Coming February 2027](https://letsencrypt.org/2026/10/07/64-day-certs)
- [Let's Encrypt: Decreasing Certificate Lifetimes to 45 Days](https://letsencrypt.org/2025/12/02/from-90-to-45)
- [Let's Encrypt: ACME Renewal Information Published as RFC 9773](https://letsencrypt.org/2025/09/16/ari-rfc)

## 4. Before 1.0

These keep users' sites safe and make SSLense supportable without paid support. Each must be done before a 1.0 release.

### 4.1 Remaining safety work

- Send the ARI `replaces` field on renewal orders (Certes does not expose it yet).
- ~~Journal challenge files so an interrupted validation is cleaned up on recovery.~~ Done October 28, 2026.
- Certificate private-key permissions for IIS application-pool identities.
- Configurable maintenance windows that can never let a certificate expire.
- Recovery procedures for a compromised ACME account or private key.

### 4.2 Diagnostics and health check

Done (October 28, 2026): `SSLense.Cli health` and the GUI Health page; a redacted diagnostic bundle (`SSLense.Cli diagnostics`, optional host redaction) with tests that scan it for seeded secrets; a service heartbeat recording each cycle; and a GitHub bug-report template that asks for both.

Remaining:

- Stable, searchable error codes.
- ~~Show the health summary on the Dashboard.~~ Done October 28, 2026: a banner appears when the quick local checks find a problem.

### 4.3 Distribution

- ~~Release builds from GitHub Actions with SHA-256 checksums attached to each GitHub Release.~~ Done October 28, 2026 (`.github/workflows/release.yml`); first used by the v0.9.10 tag.
- Authenticode signing of executables and the MSI, for example through the free [SignPath Foundation](https://signpath.org/) program for open-source projects. Unsigned MSIs trigger Windows SmartScreen warnings.
- ~~An installer UI showing the Apache-2.0 license.~~ Done October 28, 2026, with SSLense branding.
- A [winget](https://learn.microsoft.com/windows/package-manager/) package.
- Install, upgrade, repair, and uninstall verified on each supported Windows Server version.

### 4.4 Quality and compatibility

- A published support matrix of Windows Server and IIS versions, backed by repeatable tests on real IIS virtual machines.
- HTTP-01 tested through direct public IPs, NAT, reverse proxies, and Cloudflare Tunnel.
- IPv4, IPv6, internationalized domain names, SAN certificates, and large binding sets.
- HTTPS bindings without a host name, and on ports other than 443. SSLense manages SNI bindings on port 443, and adoption refuses the others with an explanation; common on servers with older sites.
- Outbound proxies, restricted firewalls, TLS inspection, and clock skew.
- Accessibility: keyboard navigation, high contrast, and scalable text.

### 4.5 Project health

- A documented threat model, updated with each major architecture change.
- Dependency and vulnerability scanning in CI, and a software bill of materials for each release.
- ~~Private vulnerability reporting (see [SECURITY.md](SECURITY.md)) with response targets.~~ Done October 28, 2026.
- Release notes, known issues, and an upgrade compatibility table.
- Documentation: a quick start, firewall/DNS/proxy requirements, troubleshooting runbooks, and migration guides from manual IIS certificates and other ACME clients.

## 5. After 1.0

Ordered roughly by expected demand. Community feedback decides the order.

- **DNS-01 and wildcard certificates:** a versioned DNS-provider plugin interface; Cloudflare first, then Azure DNS, AWS Route 53, and others; generic script hooks; CNAME delegation; propagation checks from several resolvers; least-privilege, DPAPI-protected provider credentials.
- **Several certificates per site:** move locks, journals, and CLI/GUI selection from site name to the certificate ID every record already has.
- **Existing-certificate discovery:** adopting a certificate already bound in IIS was added in 0.10. Remaining: find expired, duplicate, self-signed, and staging certificates in `LocalMachine\My` that no binding uses, and suggest clean-up.
- **More certificate authorities:** the certificate authority profiles from 0.10 are in place. Remaining: adding ACME CAs with External Account Binding (ZeroSSL, Google Trust Services, SSL.com, internal ACME servers), a CA choice in the Issue wizard, and Pebble-based tests in CI (steps 4 and 5 of [docs/design/certificate-sources.md](docs/design/certificate-sources.md)). SSLense never fails over to another CA without explicit configuration.
- **Automation:** JSON output for every CLI command, documented exit codes, a PowerShell module, and configuration import/export.
- **More notification channels:** signed webhook payloads, and email through the Microsoft Graph API for Microsoft 365 tenants that disable SMTP. (Teams, Slack, Discord, Telegram, ntfy, a heartbeat, the Event Log, and email for any SMTP setup were added October 28, 2026.)
- **HTTP-to-HTTPS redirect helper** using an IIS URL Rewrite rule.
- **Other deployment targets:** HTTP.sys, Kestrel, Remote Desktop Services, SQL Server, and Exchange, each with install, verify, rollback, and remove operations.
- **Multi-server management:** a possible later project, built so each server's renewal keeps working when any central component is unavailable.

## 6. Sustainability

SSLense is maintained voluntarily. Donations through [GitHub Sponsors](https://github.com/sponsors/panchalvimaldev) help pay for test infrastructure and code signing. Any future paid offering, such as optional services or support, would leave the open-source core intact. Contributions are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md).
