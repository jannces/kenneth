"""Bridge Snort alert output into the AETHRA-SEC Alert Socket.

AETHRA-SEC listens on a TCP socket and expects one alert per line (Snort "fast"
text or JSON). Snort on Windows writes alerts to a log file, so this small
forwarder tails that file and streams each *new* line to the socket in real
time. This keeps AETHRA-SEC's design (a live socket listener) while working with
a stock Snort installation.

Run this AFTER starting both AETHRA-SEC and Snort:

    python tools/snort_forwarder.py --file "C:\\Snort\\log\\alert.ids"
    python tools/snort_forwarder.py --file "C:\\Snort\\log\\alert.ids" --host 127.0.0.1 --port 9000

It reads only NEW lines appended to the file (it does not re-send history), and
reconnects automatically if AETHRA-SEC restarts.
"""

from __future__ import annotations

import argparse
import os
import socket
import time


def connect(host: str, port: int) -> socket.socket | None:
    try:
        return socket.create_connection((host, port), timeout=5)
    except OSError:
        return None


def tail_and_forward(path: str, host: str, port: int) -> None:
    print(f"Snort forwarder: watching {path}")
    print(f"                 streaming to {host}:{port}")

    # Wait for the alert file to exist.
    while not os.path.exists(path):
        print("Waiting for the Snort alert file to appear...")
        time.sleep(2)

    sock = None
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        fh.seek(0, os.SEEK_END)  # start at the end - only forward NEW alerts
        buffer: list[str] = []
        while True:
            line = fh.readline()
            if not line:
                # No new data; Snort's fast format is one alert per line, but
                # some formats span blank-line-separated blocks. Flush and wait.
                if buffer:
                    _send(sock, host, port, " ".join(b.strip() for b in buffer))
                    buffer = []
                time.sleep(0.5)
                continue
            stripped = line.strip()
            if not stripped:
                if buffer:
                    sock = _send(sock, host, port, " ".join(b.strip() for b in buffer))
                    buffer = []
                continue
            # A "[**]" line marks the start of a new fast-format alert.
            if "[**]" in stripped and buffer:
                sock = _send(sock, host, port, " ".join(b.strip() for b in buffer))
                buffer = []
            buffer.append(stripped)
            # Single-line alerts (contain both [**] markers) send immediately.
            if stripped.count("[**]") >= 2 or stripped.startswith("{"):
                sock = _send(sock, host, port, stripped)
                buffer = []


def _send(sock, host, port, message: str):
    if not message.strip():
        return sock
    if sock is None:
        sock = connect(host, port)
        if sock is None:
            print("AETHRA-SEC not reachable yet; retrying...")
            time.sleep(2)
            return None
    try:
        sock.sendall((message + "\n").encode("utf-8"))
        print(f"  forwarded: {message[:80]}")
        return sock
    except OSError:
        print("Connection lost; will reconnect.")
        try:
            sock.close()
        except OSError:
            pass
        return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Forward Snort alerts to AETHRA-SEC.")
    parser.add_argument("--file", required=True,
                        help=r'Snort alert file, e.g. C:\Snort\log\alert.ids')
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    args = parser.parse_args()
    try:
        tail_and_forward(args.file, args.host, args.port)
    except KeyboardInterrupt:
        print("\nForwarder stopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
