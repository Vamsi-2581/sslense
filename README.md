# SSLense

SSLense is a free, open-source .NET 10 (LTS) Windows tool for issuing and automatically renewing Let's Encrypt certificates for IIS. The CLI and Windows Service use the same `SSLense.Core` services and the same state under `C:\ProgramData\SSLense`.

Planned work is in [ROADMAP.md](ROADMAP.md). SSLense is licensed under the [Apache License 2.0](LICENSE).

> SSLense defaults to Let's Encrypt **staging**. Production issuance is guarded by an explicit environment choice and risk acknowledgement. Development and automated tests never contact the production endpoint.

## Requirements

- Windows Server or Windows with IIS installed
- IIS Management Scripts and Tools
- Nothing extra when installed from the MSI (the apps are self-contained); the .NET 10 SDK to build from source
- Administrator access
- An IIS HTTP binding on port 80 for every requested host
- Public HTTP access to `/.well-known/acme-challenge/` for HTTP-01 validation

If the IIS machine has no public IP, a Cloudflare Tunnel can route the hostname to the local IIS HTTP binding. The tunnel route must preserve the expected host header.

## Build and test

From an Administrator PowerShell terminal in the repository:

```powershell
dotnet build .\SSLense.sln
dotnet test .\SSLense.sln
```

## Building the installer

`installer\build.ps1` publishes the GUI, CLI, and service as self-contained x64 apps (the server needs no .NET installation) and builds `artifacts\installer\SSLense-<version>-x64.msi`. The version comes from `Directory.Build.props`; increase it for every release so upgrades apply.

The installer uses WiX Toolset v7, which requires accepting its [Open Source Maintenance Fee EULA](https://wixtoolset.org/osmf/). Read the EULA (`OSMFEULA.txt` in the `WixToolset.Sdk` package), then either pass `-AcceptWixEula` on each build or accept it once for your Windows account:

```powershell
dotnet build .\installer\SSLense.Installer -t:AcceptEula -p:EulaId=wix7
.\installer\build.ps1
```

The installer project is not part of `SSLense.sln`, so `dotnet build` and `dotnet test` never need WiX.

Release settings live in one place each:

- **Version, publisher, and product name:** `Directory.Build.props` (`Version`, `Company`, `Product`). These feed the program files' properties, Add/Remove Programs, and the MSI. The publisher must match the name on the code-signing certificate.
- **Branding:** `assets\branding` holds the icon (`sslense.ico`, 16–256 px) used by the executables, the GUI window and sidebar, the Start menu shortcut, and Add/Remove Programs, plus the SVG sources and the horizontal logo.
- **Bundled .NET runtime:** `build.ps1 -RuntimeVersion` (default `10.0.14`). Raise it to the latest .NET 10 servicing release before each SSLense release so customers receive runtime security fixes.

## Installing with the MSI

```powershell
msiexec /i SSLense-0.9.0-x64.msi                      # interactive
msiexec /i SSLense-0.9.0-x64.msi /qn                  # silent
msiexec /i SSLense-0.9.0-x64.msi /qn START_SERVICE=0  # silent, service installed but not started
msiexec /x SSLense-0.9.0-x64.msi /qn                  # silent uninstall
```

The MSI installs to `C:\Program Files\SSLense` (`gui`, `cli`, and `service` folders), registers and starts the `SSLense` renewal service as LocalSystem with restart-on-failure actions, adds a Start menu shortcut and an Add/Remove Programs entry, adds the CLI folder to the system `PATH`, and restricts `C:\ProgramData\SSLense`. Upgrades stop the service, replace the files, and start it again. A failed installation or upgrade is rolled back by Windows Installer.

Uninstalling removes the program and the service but **keeps** `C:\ProgramData\SSLense` (certificates, accounts, and settings) and leaves existing IIS bindings and certificates in place, so sites keep working. Delete that folder manually to remove all SSLense data.

If you previously registered the service with `install-service` during development, run `uninstall-service` before installing the MSI; Windows Installer cannot take over an existing service registration.

## CLI usage

List IIS sites and bindings:

```powershell
dotnet run --project .\src\SSLense.Cli -- list-sites
```

Issue and install a staging certificate:

```powershell
dotnet run --project .\src\SSLense.Cli -- issue `
  --site "My IIS Site" `
  --hosts example.com,www.example.com `
  --email admin@example.com `
  --staging
```

Use `--force` to replace an existing valid staging certificate. The command imports the certificate into `LocalMachine\My`, creates or updates SNI bindings, connects to each started site over HTTPS to confirm the new certificate is actually served, and saves the managed-certificate record. If the served certificate does not match within 15 seconds, the previous bindings are restored and the new certificate is removed. Existing SSL flags on a binding, such as disabled HTTP/2, are preserved.

Every CLI command except `--help` requires an elevated (Administrator) terminal.

After staging succeeds, production issuance requires both production flags:

```powershell
dotnet run --project .\src\SSLense.Cli -- issue `
  --site "My IIS Site" `
  --hosts example.com,www.example.com `
  --email admin@example.com `
  --production `
  --accept-production-risk
```

Staging and production use separate DPAPI-protected ACME accounts. The certificate private key is installed as non-exportable, and SSLense does not retain the transient PFX. `--output` saves only the public certificate PEM.

Show managed certificates:

```powershell
dotnet run --project .\src\SSLense.Cli -- status
```

Renew certificates according to the CA's ACME Renewal Information (ARI) window. If ARI is unavailable, SSLense uses a lifetime-relative schedule capped by the configured threshold:

```powershell
dotnet run --project .\src\SSLense.Cli -- renew --all
dotnet run --project .\src\SSLense.Cli -- renew --site "My IIS Site"
```

Exercise the complete staging renewal and safe-binding swap immediately:

```powershell
dotnet run --project .\src\SSLense.Cli -- renew --site "My IIS Site" --force
```

SSLense removes an old certificate only after the replacement binding is confirmed and no other IIS binding references the old thumbprint.

## Notifications

SMTP and webhook channels may be enabled together or independently. SMTP passwords and webhook URLs are encrypted using Windows DPAPI with `LocalMachine` scope. They are never written to logs or displayed by the CLI.

Configure authenticated SMTP; the password is requested without echoing it:

```powershell
dotnet run --project .\src\SSLense.Cli -- notifications configure `
  --smtp-host smtp.example.com `
  --smtp-port 587 `
  --smtp-user sslense@example.com `
  --smtp-from sslense@example.com `
  --smtp-to admin@example.com
```

Configure a webhook; its URL is requested without echoing it:

```powershell
dotnet run --project .\src\SSLense.Cli -- notifications configure --webhook
```

Pass both SMTP options and `--webhook` in one command to enable both channels. Add `--notify-success` to receive successful-renewal messages. Renewal failures and 14-day expiry warnings are always sent when a channel is configured.

Test or remove the configuration:

```powershell
dotnet run --project .\src\SSLense.Cli -- notifications test
dotnet run --project .\src\SSLense.Cli -- notifications clear
```

## Windows Service

Publish and install the renewal service:

```powershell
dotnet publish .\src\SSLense.Service -c Release -o .\publish\service
dotnet run --project .\src\SSLense.Cli -- install-service `
  --service-path ".\publish\service\SSLense.Service.exe"
```

The `SSLense` service checks immediately after startup and then every hour. Each check is cheap: certificates that are not due are skipped, and ACME Renewal Information is cached for the period the CA requests (6 hours by default).

Failed renewals are retried from a saved schedule, so retries survive service restarts and reboots:

| Consecutive failures | Next automatic attempt |
|---|---|
| 1 | after 1 hour |
| 2 | after 2 hours |
| 3 or more | every 6 hours (hourly once the certificate is within 2 days of expiry) |
| Let's Encrypt rate limit | after 24 hours, because retrying sooner only extends the limit |

The service sends a failure notification on the third consecutive failure and about once a day after that, and immediately for a rate limit. Manual renewals from the GUI or CLI ignore the backoff, run immediately, and always notify on failure. `status` shows the failure count and the next automatic attempt. Existing IIS bindings remain in place when issuance fails. The service is registered to restart one minute after each of its first three unexpected exits in a day.

Expiry is monitored separately from renewal, so an alert is still sent if renewal itself is broken. Each level is sent once per certificate; the thresholds scale with the certificate lifetime:

| Level | 90-day certificate | 45-day certificate | 6-day certificate |
|---|---|---|---|
| Expires soon (lifetime ÷ 6, at most 14 days) | 14 days left | 7.5 days left | 1 day left |
| Expires very soon (lifetime ÷ 18, at most 3 days) | 3 days left | 2.5 days left | 8 hours left |
| Expired | at expiry | at expiry | at expiry |

On startup the service, GUI, and CLI complete or abandon interrupted certificate operations. A problem with one operation is logged as a warning and never prevents startup.

Check or remove the service:

```powershell
Get-Service SSLense
dotnet run --project .\src\SSLense.Cli -- uninstall-service
```

## Desktop GUI

Start the WPF dashboard from PowerShell or Visual Studio:

```powershell
dotnet run --project .\src\SSLense.Gui
```

Windows displays an administrator elevation prompt because the application manifest requests `requireAdministrator`. The GUI provides:

- A professional application shell with consistent navigation, typography, controls, and operation feedback
- Dashboard summary cards for total, healthy, expiring, and failed certificates
- A certificate table with readable health badges that do not rely on full-row coloring
- Immediate renewal of the selected certificate
- Renewal checks for all due certificates
- Cancellable operations with live progress
- A live log viewer with level filtering and access to the log folder
- A visual three-step issuance wizard with IIS selection, guarded environment choice, pre-flight checks, live progress, and cancellation
- Certificate details, renewal, confirmed removal, bindings, issuer, validity, and recent logs
- General, SMTP/webhook, and Windows Service settings

Staging remains the wizard default. Production requires a separate selection and acknowledgement before the Issue button is enabled. Use **Issue certificate** on the Dashboard to open the wizard. Removing a certificate requires confirmation and removes only matching HTTPS bindings; a certificate still used by another IIS site is retained in the Windows certificate store.

The Phase 7 Core operations also have CLI equivalents:

```powershell
dotnet run --project .\src\SSLense.Cli -- preflight --site "My IIS Site" --hosts example.com
dotnet run --project .\src\SSLense.Cli -- details --site "My IIS Site"
dotnet run --project .\src\SSLense.Cli -- configure --email admin@example.com --renewal-days 30
dotnet run --project .\src\SSLense.Cli -- service-status
dotnet run --project .\src\SSLense.Cli -- start-service
dotnet run --project .\src\SSLense.Cli -- stop-service
```

Certificate removal is destructive and therefore requires explicit CLI confirmation:

```powershell
dotnet run --project .\src\SSLense.Cli -- remove --site "My IIS Site" --yes
```

## Data and logs

SSLense stores files under `C:\ProgramData\SSLense`:

- `config.json`: non-secret settings and DPAPI-protected notification values
- `managed-certificates.json`: sites, hosts, certificate dates, thumbprints, and renewal results
- `account-key.staging.dat`: DPAPI-protected staging ACME account key
- `account-key.production.dat`: separate DPAPI-protected production ACME account key, created only when production is used
- `certificates\`: saved public certificate PEM files; transient PFX data is not retained
- `locks\`: per-site cross-process operation locks shared by the GUI, CLI, and service
- `transactions\`: durable certificate-operation journals, normally removed automatically after commit or recovery
- `logs\sslense-YYYYMMDD.log`: rolling logs retained for 30 days

`config.json`, `managed-certificates.json`, and transaction journals carry a `schemaVersion`. Before SSLense first rewrites a file from an older schema, it saves the original as `<file>.v<old version>.bak` (for example `managed-certificates.json.v0.bak`). A file written by a newer SSLense version is never modified: SSLense stops with a message to install the newer version, so a downgrade cannot corrupt state.

Private keys, PFX passwords, SMTP passwords, webhook URLs, and the ACME account key must never appear in logs.

### Data directory permissions

DPAPI `LocalMachine` protection lets any account on the machine decrypt a protected value it can read, so folder permissions are what actually protect SSLense's secrets. Every time the service, GUI, or an elevated CLI starts, SSLense:

- restricts `C:\ProgramData\SSLense` to **Administrators** and **SYSTEM** (the service account), removing the default ProgramData access for Users;
- makes Administrators the owner of the folder and everything in it, because a previous owner could otherwise change the permissions back;
- removes any extra permissions on files inside, so everything inherits the restricted rules.

SSLense never creates links in this folder. If it finds a symbolic link, junction, or file with more than one hard link, it **changes nothing** and logs a warning naming the item, because Windows would otherwise apply the permission change through the link to a location outside the folder. Remove the item and start SSLense again.

Check the current state at any time (read-only; exits with code 1 if there is a problem):

```powershell
dotnet run --project .\src\SSLense.Cli -- check-permissions
```

The service runs as LocalSystem. Running it under a different account would also require granting that account access to this folder.

## Health check and diagnostics

Run the health check first when something is wrong. It is read-only, apart from a probe file that the pre-flight check writes to each site's challenge folder and removes:

```powershell
SSLense.Cli health
```

It checks elevation, data-folder permissions, configuration and state files, interrupted operations, the renewal service and its heartbeat (the service records each hourly cycle), IIS, and, for every managed certificate, that it is installed with its private key, bound on port 443, not close to expiry, and renewing successfully. It then checks DNS, port 80 reachability, and the challenge folder for each host, outbound HTTPS to Let's Encrypt (a read-only request for the ACME directory of each environment in use), and whether a notification channel is configured. Each problem comes with a suggested fix. The exit code is 1 if any check failed and 0 otherwise, warnings included, so it can be used in monitoring scripts.

To ask for help, create a diagnostic bundle and attach it to a GitHub issue:

```powershell
SSLense.Cli diagnostics                  # sslense-diagnostics-<timestamp>.zip in the current folder
SSLense.Cli diagnostics --redact-hosts   # also replaces site and host names, for public posts
```

The bundle contains a system summary (SSLense, Windows, .NET, and IIS versions), the health check results, configuration, managed certificates, IIS sites and bindings, interrupted operations, the service heartbeat, and the three newest log files. It never contains private keys, ACME account keys, PFX files, SMTP passwords, webhook URLs, or DPAPI-protected values. Email addresses are masked, and URL paths and query strings are removed except for Let's Encrypt and HTTP-01 challenge URLs. Thumbprints are kept because they are public identifiers. Review the files before sharing them.

The GUI's **Health** page runs the same checks and saves the bundle to your Desktop.

## Troubleshooting

- **Access denied:** run PowerShell as Administrator.
- **IIS sites cannot be read:** install IIS Management Scripts and Tools.
- **HTTP-01 returns 404:** confirm the hostname's port 80 IIS binding, tunnel host header, and that `/.well-known/acme-challenge/<token>` reaches the same site.
- **HTTP-01 returns unexpected content:** check authentication, URL Rewrite, MVC routing, proxies, and cached responses for the challenge path.
- **ACME validation times out:** confirm public DNS/tunnel routing and that inbound HTTP remains available throughout validation.
- **SMTP test fails:** verify the port, TLS mode, credentials, outbound firewall policy, and provider-specific authentication requirements.
- **Webhook test fails:** verify that the receiving endpoint accepts an HTTP POST containing `kind`, `subject`, `body`, and `occurredAtUtc` JSON fields.

Review the current daily log in `C:\ProgramData\SSLense\logs` for the full exception and remediation context. Sensitive values are excluded.

## Contributing, security, and support

- **Contributing:** see [CONTRIBUTING.md](CONTRIBUTING.md). Commits are signed off under the Developer Certificate of Origin.
- **Security issues:** report them privately as described in [SECURITY.md](SECURITY.md), never in a public issue.
- **Bugs and questions:** open a GitHub issue with the output of `SSLense.Cli health` and a bundle from `SSLense.Cli diagnostics` (add `--redact-hosts` if your host names are private).

## License

SSLense is licensed under the [Apache License 2.0](LICENSE); see [NOTICE](NOTICE). Third-party components and their licenses are listed in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md). The SSLense name and logo are covered by [TRADEMARKS.md](TRADEMARKS.md), not by the code license.
