# Reconnaissance — nmap

## Objective

Confirm the target's SSH service is exposed and fingerprint its version before attempting
any credential attack.

## Command

```bash
nmap -sV -p 22 192.168.64.8
```

- `-sV`: service/version detection (banner grabbing)
- `-p 22`: scoped to SSH, the confirmed attack surface for this lab

## Result

```
Starting Nmap 7.99 ( https://nmap.org ) at 2026-07-02 14:49 -0600
Nmap scan report for 192.168.64.8
Host is up (0.88s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 10.2p1 Ubuntu 2ubuntu3.2 (Ubuntu Linux; protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Findings

- Target: `192.168.64.8`
- SSH exposed on port 22, protocol 2.0
- Service: OpenSSH 10.2p1 on Ubuntu (package `2ubuntu3.2`)
- No banner obfuscation — version disclosure would let a real attacker cross-reference
  known CVEs for this exact build before choosing an attack path. In this lab, brute
  force (T1110) was chosen regardless of version, since the target's weak-credential
  test account is the intended vulnerability.
