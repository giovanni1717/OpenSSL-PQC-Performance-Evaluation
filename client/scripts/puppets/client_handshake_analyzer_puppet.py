#!/usr/bin/env python3
"""
Cold TLS client spawner + tshark capture + handshake-time extraction.

Design goals:
- Spawn a fresh OpenSSL s_client per iteration (stone-cold).
- Capture packets with tshark (same capture stack as Wireshark).
- Write capture to /tmp as root (avoids vboxsf / mount permission issues).
- Relax temp pcap permissions so the invoking user can copy it.
- Copy capture to the requested destination path.
- Analyze capture with tshark + keylog file and extract client Finished timing.

Metric:
- tcp.time_relative of TLS Finished (handshake.type==20) sent by the client.
"""

import argparse
import csv
import os
import signal
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


# Run a single cold OpenSSL s_client connection
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
        "-ciphersuites", args.ciphersuite,
        "-keylogfile", args.keylogfile,
    ]

    env = os.environ.copy()
    env["OPENSSL_CONF"] = args.openssl_conf

    print(f"[{idx}] spawning cold client...")

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

    proc.wait()


def copy_pcap_as_user(tmp_pcap: str, dest_pcap: str) -> None:
    sudo_user = os.environ.get("SUDO_USER")

    subprocess.run(["sudo", "chmod", "644", tmp_pcap], check=True)
    Path(dest_pcap).parent.mkdir(parents=True, exist_ok=True)

    if sudo_user:
        cmd = ["sudo", "-u", sudo_user, "cp", "-f", tmp_pcap, dest_pcap]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError(
                "Failed to copy pcap as SUDO_USER:\n" + (r.stderr or "")
            )
    else:
        r = subprocess.run(["cp", "-f", tmp_pcap, dest_pcap], capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError(
                "Failed to copy pcap:\n" + (r.stderr or "")
            )


def extract_finished_times(args, pcap_path: str) -> None:
    from decimal import Decimal, InvalidOperation, getcontext
    getcontext().prec = 50

    pcap = str(Path(pcap_path).expanduser().resolve())
    keylog = str(Path(args.keylogfile).expanduser().resolve())
    out_csv = str(Path(args.out_csv).expanduser().resolve())

    cmd = [
        args.tshark_bin,
        "-r", pcap,
        "-o", f"tls.keylog_file:{keylog}",
        "-T", "fields",
        "-E", "separator=\t",
        "-e", "tcp.stream",
        "-e", "tcp.time_relative",
        "-e", "frame.time_relative",
        "-e", "ip.src",
        "-e", "tcp.len",
        "-e", "tls.handshake.type",
    ]

    print("Extracting handshake data with single-pass tshark…")
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError("tshark analysis failed:\n" + (proc.stderr or ""))

    packets_by_stream = {}
    finished_info = {}

    for ln in proc.stdout.splitlines():
        if not ln.strip():
            continue

        parts = ln.split("\t")
        if len(parts) != 6:
            continue

        stream, tcp_t_rel, frame_t_rel, src_ip, tcp_len, hs_type = parts

        try:
            frame_t_dec = Decimal(frame_t_rel)
        except (InvalidOperation, TypeError):
            continue

        try:
            tcp_len_i = int(tcp_len) if tcp_len else 0
        except ValueError:
            tcp_len_i = 0

        packets_by_stream.setdefault(stream, []).append((frame_t_dec, src_ip, tcp_len_i))

        if (
            hs_type == "20"
            and src_ip == args.client_ip
            and stream not in finished_info
        ):
            finished_info[stream] = (tcp_t_rel, frame_t_rel)

    with open(out_csv, "w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "handshake_index",
                "tcp_stream",
                "time_s",
                "time_ms",
                "client_bytes",
                "server_bytes",
                "total_bytes",
            ],
        )
        writer.writeheader()

        idx = 0
        for stream, (tcp_time_str, finished_frame_time_str) in finished_info.items():
            try:
                t_s = float(tcp_time_str)
                boundary = Decimal(finished_frame_time_str)
            except (ValueError, InvalidOperation):
                continue

            client_bytes = 0
            server_bytes = 0

            for frame_t_dec, src_ip, tcp_len_i in packets_by_stream.get(stream, []):
                if frame_t_dec > boundary:
                    continue
                if src_ip == args.client_ip:
                    client_bytes += tcp_len_i
                elif src_ip == args.server_ip:
                    server_bytes += tcp_len_i

            idx += 1
            writer.writerow({
                "handshake_index": idx,
                "tcp_stream": stream,
                "time_s": f"{t_s:.6f}",
                "time_ms": f"{t_s * 1000.0:.3f}",
                "client_bytes": client_bytes,
                "server_bytes": server_bytes,
                "total_bytes": client_bytes + server_bytes,
            })

    print(f"Wrote {idx} handshake timings to {out_csv}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Cold TLS client spawner with key logging, tshark capture, and pcap analysis"
    )

    parser.add_argument("--group", required=True)
    parser.add_argument("--sigalgs", required=True)
    parser.add_argument("--ciphersuite", required=True)

    parser.add_argument("--iterations", type=int, default=10)
    parser.add_argument("--server-ip", default="192.168.57.10")
    parser.add_argument("--port", type=int, default=4433)
    parser.add_argument("--control-port", type=int, default=9000)

    parser.add_argument("--iface", required=True)

    parser.add_argument("--server-cert", required=True)
    parser.add_argument("--server-key", required=True)

    parser.add_argument("--openssl-conf", required=True)
    parser.add_argument("--openssl-bin", default="/home/client/pqc/build/bin/openssl")
    parser.add_argument("--keylogfile", required=True)
    parser.add_argument("--sleep", type=float, default=0.0)

    parser.add_argument("--pcap", required=True)
    parser.add_argument("--client-ip", required=True)
    parser.add_argument("--out-csv", required=True)
    parser.add_argument("--tshark-bin", default="tshark")

    args = parser.parse_args()

    Path(args.keylogfile).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
    open(args.keylogfile, "a").close()

    dest_pcap = str(Path(args.pcap).expanduser().resolve())
    tmp_pcap = str(Path("/tmp") / (Path(dest_pcap).name + f".{os.getpid()}.pcapng"))

    # ---- START server (ROSP) ----
    send_control_message(
        args.server_ip,
        args.control_port,
        f"START {args.group} {args.server_cert} {args.server_key} "
        f"{args.ciphersuite}"
    )

    try:
        print(f"Starting tshark capture on interface {args.iface} -> {tmp_pcap}")

        tshark_cmd = [
            "sudo",
            args.tshark_bin,
            "-i", args.iface,
            "-w", tmp_pcap,
            "-f", f"tcp port {args.port}",
        ]

        capture = subprocess.Popen(
            tshark_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        print("Sleeping for 5 seconds...")
        time.sleep(5)

        if capture.poll() is not None:
            out, err = capture.communicate(timeout=2)
            raise RuntimeError(
                "tshark capture failed immediately.\n"
                + "STDOUT:\n" + (out or "") + "\n"
                + "STDERR:\n" + (err or "")
            )

        for i in range(1, args.iterations + 1):
            run_once(args, i)
            if args.sleep > 0:
                time.sleep(args.sleep)

    finally:
        print("Finished capturing...")
        time.sleep(5)
        print("Stopping capture…")
        capture.send_signal(signal.SIGINT)
        try:
            capture.wait(timeout=5)
        except subprocess.TimeoutExpired:
            capture.kill()
            capture.wait()

        print(f"Copying capture to destination -> {dest_pcap}")
        copy_pcap_as_user(tmp_pcap, dest_pcap)

        try:
            os.remove(tmp_pcap)
        except OSError:
            pass

        # ---- STOP server (ROSP) ----
        send_control_message(
            args.server_ip,
            args.control_port,
            "STOP"
        )

    extract_finished_times(args, dest_pcap)


if __name__ == "__main__":
    main()
