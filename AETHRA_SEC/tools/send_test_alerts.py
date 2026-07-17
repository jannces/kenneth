"""Send sample intrusion alerts to a running AETHRA-SEC (no Snort required).

This is a *learning / demonstration* helper. It connects to the AETHRA-SEC
Alert Socket exactly the way Snort (or a forwarder) would, and streams a few
realistic alerts so you can watch them appear on the Intrusion Alerts page and
the dashboard - including deduplication (a repeated attack shows one row with a
rising occurrence counter) and correlation.

Usage (with AETHRA-SEC already running and logged in):

    python tools/send_test_alerts.py
    python tools/send_test_alerts.py --host 127.0.0.1 --port 9000

It only sends alert text over a local socket; it does not touch the network or
attack anything.
"""

from __future__ import annotations

import argparse
import socket
import time

# Sample alerts in Snort "fast" single-line format:
#   MM/DD-HH:MM:SS.uuuuuu [**] [gid:sid:rev] MESSAGE [**]
#   [Classification: ...] [Priority: N] {PROTO} SRC:SPORT -> DST:DPORT
SAMPLE_ALERTS = [
    # A port scan (medium).
    "[**] [1:1000001:1] Nmap port scan detected [**] "
    "[Classification: Attempted Recon] [Priority: 2] {TCP} "
    "10.0.0.50:44321 -> 10.0.0.10:1",
    # An ICMP flood (medium/high after repetition).
    "[**] [1:1000002:1] ICMP flood detected [**] "
    "[Classification: Denial of Service] [Priority: 2] {ICMP} "
    "10.0.0.66 -> 10.0.0.10",
    # SSH brute force, sent several times to demonstrate DEDUPLICATION.
    "[**] [1:1000003:1] SSH brute force login attempt [**] "
    "[Classification: Attempted Admin] [Priority: 1] {TCP} "
    "10.0.0.77:51234 -> 10.0.0.10:22",
    "[**] [1:1000003:1] SSH brute force login attempt [**] "
    "[Classification: Attempted Admin] [Priority: 1] {TCP} "
    "10.0.0.77:51235 -> 10.0.0.10:22",
    "[**] [1:1000003:1] SSH brute force login attempt [**] "
    "[Classification: Attempted Admin] [Priority: 1] {TCP} "
    "10.0.0.77:51236 -> 10.0.0.10:22",
    # A TCP SYN flood (high).
    "[**] [1:1000004:1] TCP SYN flood [**] "
    "[Classification: Denial of Service] [Priority: 1] {TCP} "
    "10.0.0.88:60001 -> 10.0.0.10:80",
    # Abnormal HTTP traffic (high).
    "[**] [1:1000005:1] HTTP abnormal request rate [**] "
    "[Classification: Web Application Attack] [Priority: 2] {TCP} "
    "10.0.0.99:40000 -> 10.0.0.10:80",
]


def send_alerts(host: str, port: int, repeat_ssh: int, delay: float) -> None:
    print(f"Connecting to AETHRA-SEC Alert Socket at {host}:{port} ...")
    try:
        sock = socket.create_connection((host, port), timeout=5)
    except OSError as exc:
        print(f"\nCould not connect: {exc}")
        print("Make sure AETHRA-SEC is running and you are logged in "
              "(the listener starts automatically after login).")
        return

    print("Connected. Sending sample alerts...\n")
    try:
        for line in SAMPLE_ALERTS:
            # Repeat the SSH brute-force alert to show deduplication in action.
            times = repeat_ssh if "SSH brute force" in line else 1
            for _ in range(times):
                sock.sendall((line + "\n").encode("utf-8"))
                label = line.split("]")[2].strip() if "]" in line else line[:40]
                print(f"  -> sent: {label}")
                time.sleep(delay)
        print("\nAll sample alerts sent. Check the Intrusion Alerts page and the "
              "dashboard - the repeated SSH alert should appear as ONE row with a "
              "high occurrence count.")
    finally:
        sock.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Send test alerts to AETHRA-SEC.")
    parser.add_argument("--host", default="127.0.0.1", help="Alert socket host")
    parser.add_argument("--port", type=int, default=9000, help="Alert socket port")
    parser.add_argument("--repeat-ssh", type=int, default=8,
                        help="How many times to send the SSH alert (shows dedup)")
    parser.add_argument("--delay", type=float, default=0.3,
                        help="Seconds between messages")
    args = parser.parse_args()
    send_alerts(args.host, args.port, args.repeat_ssh, args.delay)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
