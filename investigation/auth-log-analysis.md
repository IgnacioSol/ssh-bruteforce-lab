# Investigation — Authentication Log Analysis

## Objective

Reconstruct the attack timeline from log evidence alone, as a SOC analyst would —
without relying on prior knowledge of how the attack was actually carried out.

## A Note on Log Source

The target's expected log file, `/var/log/auth.log`, **does not exist** on this system.
Modern Ubuntu releases (this target runs 26.04) frequently ship without `rsyslog`
installed, relying solely on `systemd-journald` for logging instead of writing to flat
text files. All commands below use `journalctl` in place of `grep`-on-a-file — the same
investigative logic applies, only the tool changes.

## Step 1 — Isolating Failed Login Attempts

```bash
sudo journalctl -u ssh | grep "Failed password"
```

**Result:** 10 lines, all within `03:09:34`–`03:09:35`, all `Failed password for testuser
from 192.168.64.1`, each with a distinct source port and PID.

**Finding:** this is the signature of a brute-force/dictionary attack — same target
account, same source IP, dense burst of failures in under two seconds. The distinct
source ports and PIDs per attempt indicate a tool running multiple parallel connection
attempts (consistent with Hydra's default multi-task behavior), not a human typing
passwords by hand.

## Step 2 — Isolating Successful Logins

```bash
sudo journalctl -u ssh | grep "Accepted password"
```

**Result:** 3 lines:

| Time | User | Assessment |
|---|---|---|
| `01:56:52` | ignacio | Unrelated noise — legitimate admin login predating the incident |
| `03:09:32` | testuser | **The brute-force success** |
| `03:16:38` | testuser | Follow-up login using the now-compromised credentials |

**Finding of note:** the successful login (`03:09:32`) timestamps *before* most of the
failed attempts (`03:09:34`–`35`). This isn't a logging error — Hydra fires several
parallel connection attempts at once; the attempt using the correct password completed
its handshake faster than the other in-flight attempts, which kept failing and logging
a couple seconds later. Log order does not always match intuitive chronological
expectation, and this is a useful reminder not to assume causality from ordering alone.
Also of note: distinguishing the unrelated `ignacio` login required treating it as
signal-vs-noise rather than assuming every log line is part of the incident.

## Step 3 — Privilege Escalation and Backdoor Account Creation

```bash
sudo journalctl | grep -iE "useradd|usermod|sysupdate"
```

**Result (grouped):**

**Environment setup (by `ignacio`, predates the attack — not malicious):**
```
03:02:06  sudo[2816]: ignacio ... COMMAND=/usr/sbin/useradd -m testuser
03:02:06  useradd[2819]: new user: name=testuser, UID=1001...
03:15:58  sudo[3048]: ignacio ... COMMAND=/usr/sbin/usermod -aG sudo testuser
03:15:58  usermod[3051]: add 'testuser' to group 'sudo'
03:16:00  sudo[3069]: ignacio ... COMMAND=/usr/sbin/usermod -aG sudo testuser
```

**Attacker activity (by `testuser`, using the compromised account):**
```
03:20:11  sudo[3191]: testuser ... COMMAND=/usr/sbin/useradd -m -s /bin/bash sysupdate
03:20:11  useradd[3202]: new user: name=sysupdate, UID=1002, home=/home/sysupdate, from=/dev/pts/1
03:20:44  sudo[3209]: testuser ... COMMAND=/usr/bin/passwd sysupdate
03:20:52  passwd[3212]: password changed for sysupdate
```

**Finding:** the `sudo` log format records *who* requested privilege elevation, not just
that elevation happened. The actor field changing from `ignacio` to `testuser` at
`03:20:11` is the exact boundary between legitimate administration and abuse of the
compromised account (T1136 — Create Account). The `from=/dev/pts/1` on the `useradd`
line confirms this originated from a remote pty (SSH session), not the local console.

## Step 4 — Cron Persistence

```bash
sudo journalctl | grep -iE "cron.d/system-check|CRON\[.*root"
```

**Result:**
```
03:26:33  sudo[3253]: testuser ... COMMAND=/usr/bin/tee /etc/cron.d/system-check
03:27:01  CRON[3257]: (root) CMD (echo "beacon: $(date)" >> /var/log/beacon.log)
03:28:01  CRON[3275]: (root) CMD (echo "beacon: $(date)" >> /var/log/beacon.log)
...continues every minute through 03:35:01...
Jul 02 21:19:21  CRON[3786]: (root) CMD (echo "beacon: $(date)" >> /var/log/beacon.log)
Jul 02 21:20:01  CRON[17107]: (root) CMD (echo "beacon: $(date)" >> /var/log/beacon.log)
...continues every minute...
```

**Finding:** confirms both halves of T1053.003 — the file was created by `testuser`
(again via a remote session), and it actually executed unattended, every minute,
without fail. The jump from `03:35:01` straight to `Jul 02 21:19:21` lines up exactly
with the manual clock correction (`sudo hwclock --hctosys`) performed mid-investigation
— independent corroboration of the clock-skew finding from the persistence phase, found
here in the execution log itself.

## Reconstructed Timeline

All times below are as logged by the target's own clock at the time (see clock-skew note).

| Time (target-local) | Actor | Event |
|---|---|---|
| `01:56:52` | ignacio | Unrelated legitimate login (pre-incident noise) |
| `03:02:06` | ignacio | Test account `testuser` created (environment setup) |
| `03:09:32` | testuser | **Brute-force success** — correct password found by Hydra |
| `03:09:34`–`35` | testuser | 10 failed login attempts logged (parallel Hydra tasks completing) |
| `03:15:58`–`03:16:00` | ignacio | `testuser` granted sudo (environment setup — intentional misconfiguration) |
| `03:16:38` | testuser | Attacker logs in via SSH using compromised credentials |
| `03:20:11` | testuser | Backdoor account `sysupdate` created (T1136) |
| `03:20:44`–`52` | testuser | Password set on `sysupdate` |
| `03:26:33` | testuser | Cron persistence file `/etc/cron.d/system-check` created (T1053.003) |
| `03:27:01`–`03:35:01` | root (via cron) | Beacon cron job fires every minute |
| *(clock corrected)* | ignacio | `sudo hwclock --hctosys` — system clock resynced to RTC |
| `Jul 02 21:19:21` onward | root (via cron) | Beacon cron job continues firing every minute, uninterrupted |

## Automated Detection Script

_Pending: `detect_bruteforce.py`, a script to automate Steps 1–2 above, built and
tested against [`sample-ssh-auth.log`](sample-ssh-auth.log) (the real captured lines
from this incident)._

## Clock Skew — Impact on This Timeline

See [`../persistence/backdoor-notes.md`](../persistence/backdoor-notes.md) for the full
finding. Summary: the target's system clock was ~7 days 44 minutes behind its own
hardware clock (RTC) throughout recon, the attack, and initial persistence setup — all
timestamps above through `03:35:01` are as logged under that skewed clock, not real
calendar time. The *relative* sequencing and intervals between events remain accurate;
only the absolute date/time is offset. This was corrected mid-investigation and is
documented rather than silently adjusted, consistent with how a real investigation
would handle a log source with an unreliable clock.
