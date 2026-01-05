#!/usr/bin/env python3
"""
Cold TLS client spawner + fine-grained RSS measurement.

Measures:
- Peak VmRSS (kB)
- Average VmRSS (kB) over the lifetime of the handshake

Timing is intentionally ignored.
"""

import argparse
import csv
import os
import subprocess
import time
import socket
from pathlib import Path

PAYLOAD = "But when can we hear the next one?\n"


def send_control_message(server_ip: str, control_port: int, message: str) -> None:
    with socket.create_connection((server_ip, control_port), timeout=20) as s:
        s.sendall((message + "\n").encode())
        reply = s.recv(4096).decode(errors="replace").strip()
        print(f"[control] {reply}")


def read_rss_kb(pid: int) -> int:
    """
    Read VmRSS from /proc/<pid>/status.
    Returns RSS in kilobytes, or 0 if unavailable.
    """
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except FileNotFoundError:
        pass
    return 0


# Run a single cold OpenSSL s_client connection
def run_once(args, idx: int):
    cmd = [
        args.openssl_bin, "s_client",
        "-tls1_3",
        "-provider", "default",
        "-provider", "oqsprovider",
        "-connect", f"{args.server_ip}:{args.port}",
        "-groups", args.group,
        "-sigalgs", args.sigalgs,
        "-no_ticket",
        "-ciphersuites", args.ciphersuite,
    ]

    env = os.environ.copy()
    env["OPENSSL_CONF"] = args.openssl_conf

    print(f"[{idx}] spawning cold client for memory measurement…")

    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
        text=True,
    )

    rss_samples = []

    try:
        proc.stdin.write(PAYLOAD)
        proc.stdin.flush()
        proc.stdin.close()
    except Exception:
        print("Error sending payload")

    while proc.poll() is None:
        # Read the child's VmRSS from /proc/<pid>/status.
        # VmRSS is the resident set size (physical memory used at that moment).
        rss = read_rss_kb(proc.pid)
        if rss > 0:
            rss_samples.append(rss)
        time.sleep(args.sample_interval)

    if not rss_samples:
        return 0, 0, 0

    peak_rss = max(rss_samples)
    avg_rss = sum(rss_samples) / len(rss_samples)

    return peak_rss, avg_rss, len(rss_samples)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Cold TLS client spawner with peak and average RSS measurement"
    )

    parser.add_argument("--group", required=True)
    parser.add_argument("--sigalgs", required=True)
    parser.add_argument("--ciphersuite", required=True)

    parser.add_argument("--iterations", type=int, default=10)

    parser.add_argument("--server-ip", default="192.168.57.10")
    parser.add_argument("--port", type=int, default=4433)
    parser.add_argument("--control-port", type=int, default=9000)

    parser.add_argument("--server-cert", required=True)
    parser.add_argument("--server-key", required=True)

    parser.add_argument("--openssl-conf", required=True)
    parser.add_argument("--openssl-bin", required=True)

    parser.add_argument(
        "--sample-interval",
        type=float,
        default=0.002,
        help="RSS sampling interval in seconds"
    )

    parser.add_argument(
        "--out-csv",
        required=True,
        help="Output CSV for memory usage"
    )

    args = parser.parse_args()

    out_csv = Path(args.out_csv).expanduser().resolve()
    out_csv.parent.mkdir(parents=True, exist_ok=True)

    # ---- START server (ROSP) ----
    send_control_message(
        args.server_ip,
        args.control_port,
        f"START {args.group} {args.server_cert} {args.server_key} "
        f"{args.ciphersuite}"
    )

    try:
        with open(out_csv, "w", newline="") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=[
                    "handshake_index",
                    "peak_rss_kb",
                    "avg_rss_kb",
                    "peak_rss_mb",
                    "avg_rss_mb",
                    "num_samples",
                ],
            )
            writer.writeheader()

            for i in range(1, args.iterations + 1):
                peak_kb, avg_kb, n = run_once(args, i)
                writer.writerow({
                    "handshake_index": i,
                    "peak_rss_kb": f"{peak_kb:.0f}",
                    "avg_rss_kb": f"{avg_kb:.2f}",
                    "peak_rss_mb": f"{peak_kb / 1024.0:.2f}",
                    "avg_rss_mb": f"{avg_kb / 1024.0:.2f}",
                    "num_samples": n,
                })

        print(f"Wrote memory measurements to {out_csv}")

    finally:
        # ---- STOP server (ROSP) ----
        send_control_message(
            args.server_ip,
            args.control_port,
            "STOP"
        )


if __name__ == "__main__":
    main()
