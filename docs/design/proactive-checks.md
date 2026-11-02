# Design: renewal readiness and served-certificate checks

Status: approved on November 2, 2026, with the decisions in section 7. Built in the steps in section 8.

## 1. Problem

Certificate lifetimes are getting shorter, so renewals happen more often and leave less time to react. Today SSLense finds most problems only when they have already happened:

- A closed port 80, a removed binding, or a changed site folder is found when renewal fails, which may be only a few weeks before expiry.
- A site can serve a different certificate from the one SSLense recorded, for example after a manual change in IIS, and nothing reports it until someone opens the Health page.

Both problems can be found earlier with checks SSLense already has.

## 2. What the administrator gets

Two new kinds of line in the daily digest:

> **api.example.com (Let's Encrypt): renewal is likely to fail.** Renewal is due around 15 Jan 2027, but `HTTP binding: api.example.com` failed: add an IIS HTTP binding on port 80 for this host.

> **shop.example.com (Sectigo RSA DV): this server is serving a different certificate from the one SSLense expects.** Expected AABB…, served CCDD…, which expires on 1 Mar 2027. Check the site's HTTPS binding in IIS.

Nothing changes on the server: these checks only report.

## 3. Renewal readiness

- **Which certificates:** automatic certificates with reminders on, whose scheduled renewal is within 30 days or has passed. Imported certificates are renewed by hand, so a pre-flight check says nothing useful about them.
- **What runs:** the existing pre-flight checks: the port 80 binding, HTTP reachability, and the challenge folder. The folder check briefly writes and removes a small file in the site's `.well-known\acme-challenge` folder, as it does today.
- **Honest limit:** these checks run from the server itself. They find local problems and, in many cases, DNS problems. They cannot prove that Let's Encrypt can reach the site from outside. The digest and documentation say "likely to fail" for a failure and never claim that a pass guarantees renewal.

## 4. Served-certificate check

- **Which certificates:** every managed certificate with reminders on, on sites that are started. Stopped sites are skipped.
- **What runs:** the existing HTTPS probe connects to each host's port 443 binding on this server, with the host name for SNI, and reads the certificate served.
- **What is reported:**
  - a served certificate that differs from the record;
  - a served certificate that has expired;
  - no HTTPS binding for the host on port 443, or no answer from it.
- **Order:** the check runs after the detection of renewals made outside SSLense, so an imported certificate replaced on purpose is recorded rather than reported as wrong.
- **Honest limit:** it shows what this server serves, not necessarily what visitors receive through a CDN, reverse proxy, or load balancer. Checking through public DNS would raise false alarms for sites behind a CDN that serves its own certificate, so it is left out of this version.

The chain is not checked here. The health check already reports chain problems for imported certificates, and staging chains are untrusted by design.

## 5. Behaviour

- **When:** once a day, as part of building the digest at the send hour, not on every hourly check.
- **Busy sites:** a site whose operation lock is held is skipped for that day.
- **Avoiding false alarms:** a problem is reported only after it fails on two daily checks in a row, so a brief outage or a site restart does not cause an email. A pass resets the count.
- **Repeats:** reported lines follow the existing reminder rules: the repeat interval, daily in the last 7 days, and the per-certificate snooze and off settings. A failed check on a muted certificate is not reported.
- **Failures in the checks themselves:** if a check cannot run, for example because IIS cannot be read, the digest is still sent without it, and the problem is logged.
- **Preview and sample digest:** they run the checks and show current results without the two-day rule, and record nothing.
- **Turning it off:** a new setting, on by default: **Check readiness and served certificates daily** in Settings → Reminders, and `reminders set --checks on|off`.
- **Health page:** the full health check gains a `Served certificate: <site>` entry, so the same answer is available on demand.

## 6. Data changes

| File | Change | Schema |
|---|---|---|
| `config.json` | `reminders.proactiveChecks`, default true | 4 → 5 |
| `reminder-state.json` | Consecutive failure counts per site and check, so a restart does not reset them | 1 → 2 |

Both follow the existing pattern: a backup before migration, and refusal of newer schemas.

## 7. Decisions for approval

1. **On by default**, with a setting to turn it off. The daily check writes and removes one small file in each site's challenge folder.
2. **Report after two daily failures in a row**, which delays the first report by a day in exchange for fewer false alarms.
3. **Readiness starts 30 days before the scheduled renewal**, so a certificate far from renewal does not cause daily emails.
4. **The served-certificate check runs from this server only** in this version. Hosts on other machines, such as load balancers and appliances, are a later step.

## 8. Steps

| Step | Content |
|---|---|
| 1 | Readiness checks: the setting, failure counts, digest lines, and tests. **Done.** |
| 2 | Served-certificate check: the digest lines, the health entry, and tests. **Done.** |
| 3 | GUI setting, CLI option, and README. **Done.** Release as 0.12.0 after the first feedback from the launch posts. |
