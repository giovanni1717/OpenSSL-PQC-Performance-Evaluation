#!/usr/bin/env python3
"""
Client-side controller for PQC TLS experiments.

Responsibilities:
- Connect to server control socket
- Send START command (including number of handshakes and ciphersuite)
- Perform N cold TLS handshakes (openssl s_client)
- Optional sleep between handshakes
- Send STOP command
"""

import argparse
import os
import socket
import subprocess
import time

PAYLOAD = "But when can we hear the next one?\n"


def send_control_message(server_ip: str, control_port: int, message: str) -> None:
    with socket.create_connection((server_ip, control_port), timeout=20) as s:
        s.sendall((message + "\n").encode())
        reply = s.recv(4096).decode(errors="replace").strip()
        print(f"[control] {reply}")


def run_once(args, idx: int) -> None:
    cmd = [
        args.openssl_bin, "s_client",
        "-tls1_3",
        "-provider", "default",
        "-provider", "oqsprovider",
        "-connect", f"{args.server_ip}:{args.port}",
        "-groups", args.group,
        "-sigalgs", args.sigalgs,
        "-no_ticket",
        "-ciphersuites", args.ciphersuites,
    ]

    env = os.environ.copy()
    env["OPENSSL_CONF"] = args.openssl_conf

    print(f"[{idx}] spawning cold client…")
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
        print(f"[{idx}] warning: failed to write payload to client stdin")
        pass

    proc.wait()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Client controller: START server, run N TLS handshakes, STOP server"
    )

    # Core crypto knobs
    parser.add_argument("--group", required=True, help="TLS group (used for client and server)")
    parser.add_argument("--sigalgs", required=True, help="Signature algorithms (used for cert/key)")
    parser.add_argument("--ciphersuites", required=True, help="TLS 1.3 ciphersuites string")
    parser.add_argument("--iterations", type=int, required=True)

    parser.add_argument("--server-ip", required=True)
    parser.add_argument("--port", type=int, default=4433)

    # OpenSSL paths
    parser.add_argument("--openssl-bin", required=True)
    parser.add_argument("--openssl-conf", required=True)

    # Control channel
    parser.add_argument("--control-ip", required=True)
    parser.add_argument("--control-port", type=int, default=9000)

    # Server-side paths
    parser.add_argument(
        "--server-cert-dir",
        default="/home/server/pqc/pqc_certificates",
        help="Base directory for server certificates"
    )
    parser.add_argument(
        "--server-key-dir",
        default="/home/server/pqc/pqc_keys",
        help="Base directory for server private keys"
    )
    parser.add_argument("--server-out-csv", required=True)

    parser.add_argument("--sleep", type=float, default=0.0)

    args = parser.parse_args()

    # ---- derive server parameters ----
    server_groups = args.group
    server_cert = os.path.join(args.server_cert_dir, f"{args.sigalgs}.crt")
    server_key = os.path.join(args.server_key_dir, f"{args.sigalgs}.key")

    # ---- START server ----
    start_msg = (
        f"START {server_groups} "
        f"{server_cert} "
        f"{server_key} "
        f"{args.ciphersuites} "
        f"{args.server_out_csv} "
        f"{args.iterations}"
    )

    print("[client] sending START to server")
    send_control_message(args.control_ip, args.control_port, start_msg)

    # ---- Run N handshakes ----
    for i in range(1, args.iterations + 1):
        run_once(args, i)
        if args.sleep > 0:
            time.sleep(args.sleep)

    # ---- STOP server ----
    send_control_message(args.control_ip, args.control_port, "STOP")
    print("[client] sending STOP to server")


if __name__ == "__main__":
    main()
