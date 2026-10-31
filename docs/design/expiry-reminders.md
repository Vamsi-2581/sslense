# Design: expiry reminders

Status: approved on October 31, 2026, with the decisions in section 9. Built in the steps in section 8.

## 1. Problem

An administrator should not have to log on to the server to know whether a certificate is about to expire. Today:

- Imported certificates get one email each at fixed points (30, 14, 7 and 1 days, then at expiry), with no way to change the schedule or silence a certificate.
- Let's Encrypt certificates get lifetime-relative warnings only when they are close to expiry, which normally means renewal is already failing. Nothing says in advance "this will be renewed on date X".
- "Renewal threshold" in Settings looks like a reminder setting but only affects the Let's Encrypt fallback schedule, capped at a third of the lifetime.
- A certificate renewed outside SSLense (for example, a new 123-reg certificate installed through IIS Manager) keeps being treated as the old one.

## 2. What the administrator gets

1. **A daily digest email, sent only when something needs attention.** One email per day at a configured time, listing every certificate that needs attention. No email on days when nothing does.
2. **Reminders that start a configurable number of days before expiry and repeat until the certificate is renewed**, automatically or by hand.
3. **One upcoming-renewal notice for automatic certificates:** "expires on X; SSLense will renew it automatically around Y".
4. **Per-certificate control:** on, snoozed, off until the certificate is replaced, or off permanently.
5. **Renewals done outside SSLense are detected**, so reminders stop when a site starts serving a newer certificate.

Failure notifications for automatic renewal stay immediate, as today. They are failures, not reminders, and they are sent even when reminders are off for that certificate.

## 3. Settings (Settings → Reminders; `config.json` → `reminders`)

| Setting | Default | Range | Notes |
|---|---|---|---|
| Start reminding | 30 days before expiry | 1–365 | Replaces "Renewal threshold" in the GUI. The Let's Encrypt fallback keeps its own lifetime-relative rule. |
| Repeat every | 1 day | 1–30 days | In the last 7 days before expiry, reminders are daily whatever this says. |
| Send at | 09:00 server local time | any hour | The digest is sent at the first hourly check at or after this time. |
| Upcoming renewal notices | On | on/off | Section 4.2. |
| Weekly summary | Off | on/off, day of week | Section 4.4. |

The digest goes to every configured channel (email, chat, ntfy, Event Log), like other notifications.

## 4. Behaviour

### 4.1 Which certificates appear in a digest

A certificate is **due** in today's digest when its reminders are on (or its snooze has ended) and any of these holds:

| Case | Condition | Message |
|---|---|---|
| Manual renewal (imported) | Within the start window, and the repeat interval has passed since it was last in a digest (daily in the last 7 days) | Expires on X, N days left; order the renewal from the provider; how to complete it in SSLense |
| Automatic renewal overdue | Past its expected renewal time plus one day, still not renewed | Should have renewed on Y; last result; what to check |
| Expired | Not after now | Expired on X; the site is serving an expired certificate |

Automatic renewal *failures* are notified immediately as today, and also appear in the digest while they persist.

### 4.2 Upcoming-renewal notice

When an automatic certificate enters the start window, today's digest includes one line for it: expires on X; SSLense will renew it automatically around Y. Y is the ARI-selected time, or the fallback schedule when the CA has no ARI. It is sent once per certificate and is not repeated. If this is the only content, the digest is still sent, because the administrator asked to be told.

### 4.3 Per-certificate reminder setting

| Value | Effect | Reset when the certificate is replaced |
|---|---|---|
| On (default) | As above | — |
| Snoozed until D | Not included until D | Yes, back to On |
| Off until replaced | Not included | Yes, back to On |
| Off permanently | Never included | No |

Muted certificates are listed in a short "Not reminding" section at the end of any digest that is sent, so nothing is silently forgotten. Changed in the GUI (Dashboard column, Certificate Details) and the CLI (`SSLense.Cli reminders --site <site> --on | --snooze <days> | --off-until-replaced | --off`).

### 4.4 Weekly summary (optional)

When enabled, it is sent on the chosen day even if nothing needs attention. It says how many certificates are managed, which expires next, and any muted certificates. Silence from SSLense then means a problem, which the existing heartbeat also covers.

### 4.5 Renewals made outside SSLense

On each hourly check, for every managed certificate, SSLense looks at the site's HTTPS bindings on port 443 for its hosts. If all of them now use another certificate that is in `LocalMachine\My` with its private key, covers the hosts, and expires later:

- **Imported certificate:** the record is updated (thumbprint, dates, issuer) and a "replaced outside SSLense" line is added to the next digest. The reminder setting resets unless it is Off permanently.
- **Automatic certificate:** the record is not changed, because the next renewal would put a Let's Encrypt certificate back. The digest and the health check report that the binding was changed outside SSLense, and suggest either adopting the new certificate or reissuing.

## 5. Data and configuration changes

| File | Change | Schema |
|---|---|---|
| `config.json` | New `reminders` section (section 3). `renewalThresholdDays` stays for the fallback schedule but leaves the main settings view | 3 → 4 |
| `managed-certificates.json` | Each record gains `reminderMode` (`On`, `Snoozed`, `OffUntilReplaced`, `Off`), `snoozedUntil`, `lastRemindedAt`, `upcomingNoticeSent`. The fixed-schedule `reminderDaysSent` is removed, and `expiryWarningSent` is no longer used for emails | 2 → 3 |
| `reminder-state.json` (new) | Date of the last digest and the last weekly summary, so a restart does not send twice | 1 |

Migrations follow the existing pattern: the old file is backed up first, and newer schemas are refused. Existing certificates start with reminders On.

## 6. Product surfaces

- **Settings:** a new Reminders group (section 3) with **Send sample digest**, which sends today's digest as it would be sent, marked as a sample, without recording anything.
- **Dashboard:** a Reminders column (On, Snoozed until D, Off until replaced, Off).
- **Certificate Details:** the reminder setting, when the last reminder was sent, and the next expected one.
- **CLI:** `reminders show`, `reminders set --start-days --repeat-days --send-at --notices on|off --weekly off|<day>`, `reminders --site ...` (section 4.3), `reminders preview` (prints the digest without sending it).
- **Health:** a check that reminders are configured and that at least one channel works.

## 7. Safety

- Reminders never change a certificate or a binding. Detection of outside renewals only updates the record of an imported certificate, after the same checks as adoption: covers the hosts, has a private key, and is on port 443.
- A failed digest send is retried at the next hourly check and recorded only after delivery, as with notifications today.
- Turning reminders off never silences failure alerts for automatic renewal.

## 8. Steps

| Step | Content |
|---|---|
| 1 | Data model and migrations; reminder settings; the digest builder (pure, fully unit-tested); digest scheduling in the service replacing the fixed imported schedule and the expiry-level emails. **Done.** The digest uses the existing Event Log IDs 1002 and 1003. |
| 2 | Per-certificate reminder setting; detection of renewals made outside SSLense; CLI |
| 3 | GUI: Settings → Reminders with Send sample digest, Dashboard column, Certificate Details |
| 4 | README, health check, release |

## 9. Decisions

1. **Digest:** one daily digest, sent only when something needs attention (or when weekly summaries are on).
2. **Repeat interval:** configurable, default daily, always daily in the last 7 days.
3. **Off:** two options, off until the certificate is replaced and off permanently, plus snooze.
4. **Outside renewals:** detected automatically (section 4.5).
