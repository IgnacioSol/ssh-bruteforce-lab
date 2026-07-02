# Persistence

After brute-forcing valid credentials (`testuser:123456`), two persistence mechanisms
were installed to simulate an attacker securing long-term access beyond the initially
compromised account.

## Privilege Context

The compromised test account was deliberately configured with `sudo` rights
(`sudo usermod -aG sudo testuser`), simulating a common real-world misconfiguration:
an overprivileged low-trust account. A weak password alone is serious; combined with
excessive privileges, it enables full system compromise instead of limited access.

## T1136 — Create Account

A backdoor account was created, independent of the originally brute-forced credentials,
so access survives even if `testuser` is disabled or its password is rotated.

```bash
sudo useradd -m -s /bin/bash sysupdate
sudo passwd sysupdate
```

The account name (`sysupdate`) was chosen to blend in with legitimate system/service
accounts rather than stand out during casual inspection of `/etc/passwd`.

## T1053.003 — Scheduled Task/Job: Cron

A system-wide cron job was placed to simulate a periodic C2 beacon — persistence that
runs unattended, without an active login session, and survives a reboot.

```bash
echo '* * * * * root echo "beacon: $(date)" >> /var/log/beacon.log' | sudo tee /etc/cron.d/system-check
```

- Runs every minute (`* * * * *`)
- Executes as `root` regardless of which account created the file — persists even if
  `testuser` and `sysupdate` are both later removed
- No real outbound network call is made; the local log write simulates the same
  "check in periodically" pattern a real C2 beacon exhibits, without standing up
  attacker infrastructure for the lab
- Disguised under a legitimate-sounding name (`system-check`) for the same reason as
  the backdoor account

## Finding: Target Clock Skew

At the time of the attack, the target VM's system clock was **~7 days 44 minutes
behind** its own hardware clock (RTC):

```
Local time: Thu 2026-06-25 03:32:16 UTC
RTC time:   Thu 2026-07-02 21:15:52 UTC
System clock synchronized: no
NTP service: active
```

Likely cause: the VM was resumed from a paused/suspended UTM state and `systemd-timesyncd`
had not yet corrected the drift. The clock was corrected mid-lab via `sudo hwclock --hctosys`.

**Impact on this investigation:** all `auth.log` entries generated during recon, the
brute-force attack, and persistence setup were logged under the *pre-correction* clock,
so their timestamps read as late June instead of July 2. The relative timing between
events (interval between failed logins, gap before persistence commands) remains
internally consistent and reliable — only the absolute date/time is offset. This is
noted explicitly in the incident report rather than corrected after the fact, since in
a real investigation you cannot retroactively fix already-written log timestamps
either — you document the skew and account for it.
