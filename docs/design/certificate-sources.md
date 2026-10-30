# Design: certificate sources (other CAs and bring-your-own certificates)

Status: **approved** October 30, 2026, with every decision in section 8 accepted as proposed. Branch: `feature/certificate-sources`.

## 1. Goals

Today SSLense only manages certificates it obtains from Let's Encrypt. This change lets it manage certificates from two more sources:

1. **Any ACME certificate authority** (ZeroSSL, Google Trust Services, Sectigo, DigiCert, SSL.com, internal ACME servers), including commercial CAs that require External Account Binding (EAB). These renew automatically, exactly like Let's Encrypt certificates.
2. **Certificates obtained outside SSLense**, such as those bought from a reseller like 123-reg. SSLense cannot renew these, but it installs them safely, monitors them, and makes replacement routine.

Everything SSLense already does for Let's Encrypt certificates (safe binding swaps with HTTPS verification and rollback, health checks, notifications, the Dashboard) applies to every source.

### Out of scope

- Buying, paying for, or renewing certificates through a reseller's website or API (123-reg, GoDaddy, Namecheap). Resellers have no common API.
- Completing a CA's own validation outside ACME (approval emails, DNS records requested by a reseller).
- DNS-01 validation and wildcard certificates (a separate roadmap item; this design does not block it).

## 2. What users get

### 2.1 Bring your own certificate (manual CAs such as 123-reg)

| Task | GUI | CLI |
|---|---|---|
| Create a certificate request: the private key is generated in the Windows machine key store and never leaves the server | **Certificates → Request certificate (CSR)** | `SSLense.Cli csr --site <site> --hosts <hosts> [--key rsa2048\|rsa3072\|ec256] [--out request.csr]` |
| Complete the request with the certificate the CA issued (and its intermediate bundle) | **Complete request** on the pending item | `SSLense.Cli complete --site <site> --certificate issued.crt [--chain bundle.crt]` |
| Import a certificate that already has its key (PFX) | **Import certificate** | `SSLense.Cli import --site <site> --pfx file.pfx` (password prompted) |
| Start monitoring a certificate already bound in IIS, without reinstalling | **Adopt** on the discovered list | `SSLense.Cli adopt --site <site>` / `SSLense.Cli discover` |
| Replace it when the next certificate arrives | **Replace** (new CSR, then Complete) | `csr` then `complete` again, or `import` again (replacing a certificate SSLense renews itself needs `--force`) |

What happens on install, for every path above:

1. **Validation before anything changes:** the certificate's host names cover the requested hosts; it is currently valid; it has a private key (or matches the pending one); the chain builds to a trusted root, with any intermediates from the bundle added to the machine's Intermediate store.
2. **Safe binding:** the same transaction journal, SNI binding, live HTTPS verification and automatic rollback as Let's Encrypt certificates. The previous certificate stays until the new one is confirmed.
3. **Recorded as managed**, with its source shown as "Imported, renewed manually" and the issuer's name.

Monitoring and reminders for imported certificates:

- Reminders through all notification channels at **30, 14, 7 and 1 days** before expiry, then at expiry. These are fixed, earlier points than the lifetime-relative ones used for ACME certificates, because ordering from a CA takes time. The message says the renewal must be ordered from the issuer and links to the `csr` command.
- The health check reports pending requests older than 30 days, missing intermediates, bindings no longer using the certificate, and a private key that is missing or not accessible.
- The renewal service never tries to renew these certificates and never treats them as failed renewals.

Private-key handling for requests: the key is created as a **persisted, non-exportable machine key** (CNG, Microsoft Software Key Storage Provider), named after the pending request. On completion it is associated with the issued certificate; an abandoned request can be cancelled, which deletes the key. No PFX or key file is ever written.

The default CSR key is **RSA 2048**, because some resellers still reject ECDSA requests; RSA 3072 and ECDSA P-256 are options.

### 2.2 Any ACME certificate authority

Users add a **certificate authority profile** once, then issue against it:

```powershell
SSLense.Cli ca add --preset zerossl            # prompts for the EAB key ID and HMAC key
SSLense.Cli ca add --name "Internal CA" --directory https://acme.internal.example/directory
SSLense.Cli ca list
SSLense.Cli issue --site "Shop" --hosts shop.example.com --email ops@example.com --ca zerossl
```

| Preset | Directory URL | EAB | Notes |
|---|---|---|---|
| `letsencrypt`, `letsencrypt-staging` | built in today | No | Existing behaviour; unchanged |
| `zerossl` | `https://acme.zerossl.com/v2/DV90` | Required | EAB credentials from the ZeroSSL dashboard |
| `sectigo-dv`, `sectigo-ov` | `https://acme.sectigo.com/v2/DV`, OV URL per account | Required | Sectigo Certificate Manager accounts |
| `google` | to verify before release | Required | Free; EAB key from Google Cloud |
| `sslcom` | to verify before release | Required | Paid accounts |
| `custom` | any HTTPS directory | Optional | Internal CAs, DigiCert, GlobalSign, and others with per-account URLs |

Preset URLs not confirmed against each CA's current documentation are marked "to verify" and must be checked before release.

Rules:

- **Each profile has its own ACME account and key**, encrypted with DPAPI like today's. EAB HMAC keys are encrypted with DPAPI too, used once when the account is created, and never logged or included in diagnostics.
- **No silent fallback.** A certificate always renews with the CA that issued it. If that CA fails, SSLense reports the failure; it never switches CAs on its own. Moving a certificate to another CA is an explicit `issue --ca <other> --force`.
- **Production guard for every non-test CA.** Anything other than a profile marked as a test endpoint needs the same explicit acknowledgement that Let's Encrypt production needs today, once per profile.
- **Detect EAB from the CA.** If the directory says external account binding is required and none was given, setup stops with a clear message, before anything is sent.
- Renewal timing still uses ARI where the CA offers it, otherwise the lifetime-relative fallback. Rate-limit handling becomes CA-neutral wording.

## 3. Data and configuration changes

| File | Change | Schema |
|---|---|---|
| `config.json` | New `certificateAuthorities` list: id, name, directory URL, is-test flag, EAB key ID, DPAPI-protected HMAC key, production acknowledged | 2 → 3 |
| `managed-certificates.json` | Each record gains `source` (`Acme` or `Imported`), `authorityId` (ACME), `issuer`, and `reminderDaysSent` (the last imported-certificate reminder sent) | 1 → 2 |
| Account keys | `account-key.<profile-id>.dat` per profile; existing `account-key.staging.dat` and `account-key.production.dat` keep working as the Let's Encrypt profiles | n/a |
| `pending-requests.json` (new) | Open certificate requests, one per site: site, hosts, key name, key type, the CSR, created date. Kept apart from the managed record so a pending replacement never disturbs the certificate in use | 1 |

Migration, using the existing pattern (backup first, refuse newer schemas): every existing record becomes `source = Acme` with `authorityId = letsencrypt` or `letsencrypt-staging` from its current `environment`. Nothing else changes for existing installations.

In code, `AcmeEnvironment` (an enum with two hard-coded Let's Encrypt URLs, used in 19 files) is replaced by a `CertificateAuthority` profile resolved by ID. The two built-in Let's Encrypt profiles keep today's behaviour and guards.

## 4. Product surfaces

- **GUI:** the Dashboard and Details show source, CA and issuer per certificate. A new **Certificates** area adds Request (CSR), Complete, Import, Adopt and Replace. The Issue wizard gains a CA picker (Let's Encrypt staging stays the default). Settings gains **Certificate authorities** (add from preset, EAB fields, test connection, remove).
- **CLI:** `csr`, `complete`, `import`, `discover`, `adopt`, `ca add|list|remove|test`, and `--ca` on `issue`. `status` shows source and issuer.
- **Health check:** CA directory reachability per profile in use; the imported-certificate checks in 2.1.
- **Diagnostics bundle:** profiles included with EAB keys and account keys redacted; the seeded-secret test is extended with an EAB HMAC key.

## 5. Safety requirements (must hold before merge)

1. A failed import, completion or replacement never changes an existing working binding.
2. Private keys from SSLense requests are non-exportable and never written to disk outside the Windows key store.
3. EAB keys, ACME account keys and PFX passwords never appear in logs, the CLI output, or diagnostics.
4. Renewal never moves a certificate to a different CA without an explicit user command.
5. Existing installations migrate without any change in behaviour.

## 6. Testing

- Unit tests for every new Core service with mocks, as today, including migration of real version-1 and version-2 files.
- Real-crypto tests (no network): CSR generation with a persisted machine key, completing it with a certificate signed by a local test CA, chain validation, PFX import, hostname mismatch, and rejection of expired or keyless certificates.
- ACME with EAB tested against **Pebble**, Let's Encrypt's local ACME test server, which supports EAB. It would run in CI without contacting any real CA.
- Manual acceptance on a test server: Let's Encrypt staging (as today), one real EAB CA on its test or free tier, and the 123-reg flow (CSR, order, complete) on a sandbox site.

## 7. Delivery plan on this branch

| Step | Contents | Ships |
|---|---|---|
| 1 | Data model, `CertificateAuthority` profiles replacing `AcmeEnvironment`, migrations; no visible change. **Done.** | Internal |
| 2 | Bring your own certificate: import, adopt, CSR and complete, replace; reminders; health checks; CLI. **Done.** | CLI |
| 3 | GUI for step 2 | GUI |
| 4 | Any ACME CA: profiles, presets, EAB, guards, `--ca`; health and diagnostics; CLI and GUI | Both |
| 5 | Pebble EAB tests in CI, documentation, website and roadmap updates | Docs |

Each step builds, passes all tests, and is reviewed before the next. The branch merges to `main` through a pull request once all steps and the manual acceptance pass.

## 8. Decisions needed

1. **Reminder schedule for imported certificates:** 30, 14, 7 and 1 days, then expired (proposed).
2. **Default CSR key type:** RSA 2048 (proposed) for compatibility with resellers.
3. **Production guard for all non-test CAs:** one-time explicit acknowledgement per CA profile (proposed).
4. **Order:** bring-your-own first (steps 2–3), then other ACME CAs (step 4), as proposed, or the reverse.
5. **Pebble in CI:** downloads Pebble's release binary during the CI run. No NuGet package is needed.
