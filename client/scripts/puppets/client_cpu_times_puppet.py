#!/usr/bin/env python3
"""
Cold TLS client spawner + CPU time measurement (children only).

Each iteration runs a batch of N cold TLS handshakes.
CPU time is measured over the batch and normalized per handshake.

Measures per handshake:
- User CPU time (s)
- System CPU time (s)
- Total CPU time (s, ms)

Wall-clock timing is intentionally ignored.
Memory usage is intentionally ignored.
"""

import argparse
import csv
import os
import subprocess
import resource
import socket
from pathlib import Path

PAYLOAD = "But when can we hear the next one?\n"

# Send a control message to the server and print the reply
def send_control_message(server_ip: str, control_port: int, message: str) -> None:
    with socket.create_connection((server_ip, control_port), timeout=20) as s:
        s.sendall((message + "\n").encode())
        reply = s.recv(4096).decode(errors="replace").strip()
        print(f"[control] {reply}")


# Run a batch of cold OpenSSL s_client connections
def run_batch(args, idx: int):
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
    
    # Print batch info 
    print(
        f"[{idx}] running batch of {args.batch_size} cold handshakes "
        f"(ciphersuite={args.ciphersuite})…"
    )

    # Measure CPU time of child processes over the batch
    r0 = resource.getrusage(resource.RUSAGE_CHILDREN)

    for _ in range(args.batch_size):
        # Spawn OpenSSL s_client process
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env,
            text=True,
        )

        try:
            proc.stdin.write(PAYLOAD)
            proc.stdin.flush()
            proc.stdin.close()
        except Exception:
            print("Error sending payload")

        # Reap child
        proc.wait()

    # Get CPU time after batch
    r1 = resource.getrusage(resource.RUSAGE_CHILDREN)

    # Compute CPU time deltas and normalize per handshake
    user_cpu = r1.ru_utime - r0.ru_utime
    sys_cpu = r1.ru_stime - r0.ru_stime
    total_cpu = user_cpu + sys_cpu

    user_cpu /= args.batch_size
    sys_cpu /= args.batch_size
    total_cpu /= args.batch_size

    return user_cpu, sys_cpu, total_cpu


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Cold TLS client spawner with batched CPU time measurement"
    )

    parser.add_argument("--group", required=True)
    parser.add_argument("--sigalgs", required=True)
    parser.add_argument("--ciphersuite", required=True)

    parser.add_argument("--iterations", type=int, default=10)
    parser.add_argument("--batch-size", type=int, default=10)

    parser.add_argument("--server-ip", default="192.168.57.10")
    parser.add_argument("--port", type=int, default=4433)
    parser.add_argument("--control-port", type=int, default=9000)

    parser.add_argument("--server-cert", required=True)
    parser.add_argument("--server-key", required=True)

    parser.add_argument("--openssl-conf", required=True)
    parser.add_argument("--openssl-bin", required=True)

    parser.add_argument("--out-csv", required=True)

    args = parser.parse_args()

    out_csv = Path(args.out_csv).expanduser().resolve()
    out_csv.parent.mkdir(parents=True, exist_ok=True)

    # ---- START server ----
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
                    "iteration",
                    "batch_size",
                    "user_cpu_s_per_handshake",
                    "sys_cpu_s_per_handshake",
                    "total_cpu_s_per_handshake",
                    "total_cpu_ms_per_handshake",
                ],
            )
            writer.writeheader()

            for i in range(1, args.iterations + 1):
                u_cpu, s_cpu, t_cpu = run_batch(args, i)
                writer.writerow({
                    "iteration": i,
                    "batch_size": args.batch_size,
                    "user_cpu_s_per_handshake": f"{u_cpu:.6f}",
                    "sys_cpu_s_per_handshake": f"{s_cpu:.6f}",
                    "total_cpu_s_per_handshake": f"{t_cpu:.6f}",
                    "total_cpu_ms_per_handshake": f"{t_cpu * 1000.0:.3f}",
                })

        print(f"Wrote batched CPU time measurements to {out_csv}")

    finally:
        # ---- STOP server ----
        send_control_message(
            args.server_ip,
            args.control_port,
            "STOP"
        )


if __name__ == "__main__":
    main()
