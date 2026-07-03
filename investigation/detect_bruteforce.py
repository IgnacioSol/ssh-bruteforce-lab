#!/usr/bin/env python3
"""Detect SSH brute-force patterns from journalctl/auth.log-style SSH logs.

Usage:
    journalctl -u ssh | ./detect_bruteforce.py
    ./detect_bruteforce.py sample-ssh-auth.log
"""

import argparse
import re
import sys
from collections import defaultdict
from datetime import datetime

LOG_PATTERN = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+\S+\s+"
    r"sshd(?:-session)?\[\d+\]:\s+(?P<result>Failed|Accepted)\s+password\s+for\s+"
    r"(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+\d+"
)


def parse_line(line, year):
    match = LOG_PATTERN.match(line)
    if not match:
        return None
    ts_str = f"{year} {match.group('month')} {match.group('day')} {match.group('time')}"
    timestamp = datetime.strptime(ts_str, "%Y %b %d %H:%M:%S")
    return {
        "timestamp": timestamp,
        "result": match.group("result"),
        "user": match.group("user"),
        "ip": match.group("ip"),
    }


def analyze(events, threshold, window_seconds, grace_seconds):
    failed_by_key = defaultdict(list)
    findings = []

    for event in events:
        key = (event["user"], event["ip"])

        if event["result"] == "Failed":
            failed_by_key[key].append(event["timestamp"])
            recent = [
                t for t in failed_by_key[key]
                if (event["timestamp"] - t).total_seconds() <= window_seconds
            ]
            failed_by_key[key] = recent
            if len(recent) == threshold:
                findings.append({
                    "type": "BRUTE_FORCE_DETECTED",
                    "user": event["user"],
                    "ip": event["ip"],
                    "attempts": len(recent),
                    "window_start": recent[0],
                    "window_end": recent[-1],
                })

        elif event["result"] == "Accepted":
            recent_fails = failed_by_key.get(key, [])
            if recent_fails and (event["timestamp"] - recent_fails[-1]).total_seconds() <= grace_seconds:
                findings.append({
                    "type": "SUCCESSFUL_COMPROMISE",
                    "user": event["user"],
                    "ip": event["ip"],
                    "login_time": event["timestamp"],
                    "preceded_by_failures": len(recent_fails),
                })

    return findings


def main():
    parser = argparse.ArgumentParser(
        description="Detect SSH brute-force attempts and follow-on compromise from "
                    "journalctl or auth.log style SSH logs."
    )
    parser.add_argument(
        "logfile", nargs="?", type=argparse.FileType("r"), default=sys.stdin,
        help="Log file to analyze (defaults to stdin, e.g. 'journalctl -u ssh | %(prog)s')",
    )
    parser.add_argument(
        "--threshold", type=int, default=5,
        help="Failed attempts within --window to flag as brute force (default: 5)",
    )
    parser.add_argument(
        "--window", type=int, default=60,
        help="Time window in seconds for the threshold (default: 60)",
    )
    parser.add_argument(
        "--grace", type=int, default=600,
        help="Seconds after the last failed attempt in which a successful login is "
             "treated as a resulting compromise (default: 600)",
    )
    parser.add_argument(
        "--year", type=int, default=datetime.now().year,
        help="Year to assume for timestamps, since syslog format omits it (default: current year)",
    )
    args = parser.parse_args()

    events = [
        parsed for line in args.logfile
        if (parsed := parse_line(line.strip(), args.year)) is not None
    ]

    if not events:
        print("No SSH authentication events found in input.")
        return

    findings = analyze(events, args.threshold, args.window, args.grace)

    if not findings:
        print(f"Analyzed {len(events)} SSH auth events — no brute-force pattern detected.")
        return

    print(f"Analyzed {len(events)} SSH auth events — {len(findings)} finding(s):\n")
    for f in findings:
        if f["type"] == "BRUTE_FORCE_DETECTED":
            print(
                f"[BRUTE FORCE] {f['attempts']} failed logins for '{f['user']}' from "
                f"{f['ip']} between {f['window_start']} and {f['window_end']}"
            )
        elif f["type"] == "SUCCESSFUL_COMPROMISE":
            print(
                f"[COMPROMISE]  '{f['user']}' from {f['ip']} logged in successfully at "
                f"{f['login_time']}, following {f['preceded_by_failures']} recent failed "
                f"attempt(s) — credentials likely compromised"
            )


if __name__ == "__main__":
    main()
