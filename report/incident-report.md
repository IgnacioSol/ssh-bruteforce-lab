# Incident Report — SSH Brute-Force Intrusion (Simulated)

**Case ID:** LAB-2026-001 | **Analyst:** Ignacio Solano | **Severity:** High | **Status:** Contained (Lab)

---

## Executive Summary

An external host (`192.168.64.1`) conducted a dictionary-based brute-force attack
against the SSH service on `192.168.64.8`, recovering valid credentials for the account
`testuser` (password: `123456`) in under two seconds. The compromised account had been
misconfigured with `sudo` privileges, allowing the attacker to immediately establish
two independent persistence mechanisms: a backdoor account (`sysupdate`) and a
system-wide cron job disguised as a routine maintenance task (`/etc/cron.d/system-check`),
which beaconed every 60 seconds without interruption — including across a multi-day gap
caused by an unrelated target clock desynchronization discovered during the
investigation.

## Attack Timeline

| Time (target-local) | Technique | Evidence |
|---|---|---|
| — | T1046 Recon | `nmap -sV` fingerprinted OpenSSH 10.2p1 on port 22 |
| `03:09:32` | T1110 Brute Force | Successful login: `testuser` from `192.168.64.1` |
| `03:09:34`–`35` | T1110 Brute Force | 10 failed password attempts (parallel Hydra tasks) |
| `03:16:38` | — | Attacker re-authenticates with compromised credentials via SSH |
| `03:20:11`–`52` | T1136 Create Account | Backdoor account `sysupdate` created and password set |
| `03:26:33` | T1053.003 Cron | Persistence file `/etc/cron.d/system-check` created |
| `03:27:01` onward | T1053.003 Cron | Beacon job fires every minute, unattended, ongoing |

## Indicators of Compromise (IOCs)

### Network
| Indicator | Type | Context |
|---|---|---|
| `192.168.64.1` | IP | Attacker source — origin of the brute-force and all follow-on activity |
| `192.168.64.8` (`ignaciolinux`) | Host | Compromised target |

### Accounts
| Indicator | Type | Context |
|---|---|---|
| `testuser` | Account | Initial access vector — weak password (`123456`), misconfigured with `sudo` |
| `sysupdate` | Account | Backdoor account created post-compromise, named to blend in with legitimate service accounts |

### Files
| Indicator | Type | Context |
|---|---|---|
| `/etc/cron.d/system-check` | Persistence artifact | Cron job disguised as routine maintenance, runs as root every minute |
| `/var/log/beacon.log` | Artifact | Output of the periodic cron beacon |

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Detection Method |
|---|---|---|---|
| Discovery (pre-attack, attacker-side) | Network Service Discovery | T1046 | N/A — occurs before target logging is relevant |
| Credential Access | Brute Force | T1110 | Repeated `Failed password` entries, same account + source IP, dense time window |
| Persistence | Create Account | T1136 | `sudo` log actor changes from admin to the compromised low-priv account when running `useradd` |
| Persistence | Scheduled Task/Job: Cron | T1053.003 | New file under `/etc/cron.d/`; corresponding `CRON[...]: (root) CMD` entries firing on schedule |

## Findings by Phase

### Phase 1 — Reconnaissance
`nmap -sV -p 22` confirmed SSH exposed on the target, running OpenSSH 10.2p1 on Ubuntu.
No banner obfuscation — version was disclosed freely, which in a non-lab context would
let an attacker cross-reference known CVEs before choosing an attack path.

### Phase 2 — Credential Access (T1110)
A firewall rule restricted inbound port 22 to a single source (`192.168.64.1`), and no
`fail2ban` or equivalent brute-force protection was present. Hydra completed a
12-password dictionary attack against `testuser` in under one second, recovering the
password `123456` with zero throttling from the target.

### Phase 3 — Persistence: Backdoor Account (T1136)
The compromised account had been provisioned with `sudo` rights — a common real-world
misconfiguration where overprivileged low-trust accounts turn a simple credential leak
into full system compromise. Using this access, the attacker created `sysupdate`, an
account independent of the originally compromised credentials, ensuring continued
access even if `testuser` were disabled or its password rotated.

### Phase 4 — Persistence: Scheduled Task (T1053.003)
A cron job was installed under `/etc/cron.d/`, executing as root every minute
regardless of any active session. This simulates a C2 beacon pattern (periodic
"check-in") without making real outbound network calls. The job's execution log
provided independent, continuous proof of persistence — including surviving a manual
system clock correction performed mid-investigation, which is itself notable: the
target's clock was found to be running ~7 days 44 minutes behind its own hardware
clock, a side effect of the VM being resumed from a suspended state with no NTP
correction yet applied. This was documented as an investigative finding rather than
silently corrected, since it affects how the raw timestamps above should be interpreted
against real calendar time (see [`../investigation/auth-log-analysis.md`](../investigation/auth-log-analysis.md)
for the full breakdown).

### Phase 5 — Investigation Methodology Note
The target had no `/var/log/auth.log` — a modern-Ubuntu characteristic where logging
lives solely in `systemd-journald` without `rsyslog` writing flat files. All evidence
was gathered via `journalctl` instead of `grep` on a log file; the investigative logic
is identical, only the tooling differs.

## Remediation Recommendations

1. **Rotate** the `testuser` password immediately and enforce a minimum password
   complexity policy — the root cause of this entire chain was a single weak,
   guessable password
2. **Remove** `testuser` from the `sudo` group — least privilege would have contained
   this incident to a single non-privileged account with no path to persistence
3. **Delete** the backdoor account `sysupdate` and audit `/etc/passwd` for any other
   unrecognized accounts
4. **Remove** `/etc/cron.d/system-check` and review all cron directories
   (`/etc/cron.d/`, `/etc/crontab`, per-user crontabs) for unauthorized entries
5. **Deploy** `fail2ban` or equivalent to throttle/block repeated failed SSH logins
6. **Migrate** to key-based SSH authentication and disable password authentication
   entirely (`PasswordAuthentication no`) — this attack class is not possible without
   password auth as a fallback
7. **Ensure** NTP time sync is verified after resuming any VM/host from a suspended
   state — an unreliable clock complicates incident timeline reconstruction, as seen
   directly in this investigation
8. **Forward** logs to a centralized, external log store — a local-only journal can be
   tampered with or cleared by an attacker who gains root, destroying the evidence
   trail this investigation depended on
