#!/usr/bin/env python3
import argparse
import os
import socket
import subprocess
import time
from pathlib import Path
import traceback
import math

CLK_TCK = os.sysconf(os.sysconf_names["SC_CLK_TCK"])

# ----------------------------
# Helpers
# ----------------------------

def read_rss_kb(pid: int) -> int:
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except FileNotFoundError:
        print(f"[sample] /proc/{pid}/status not found")
    return 0


def read_cpu_seconds(pid: int):
    try:
        with open(f"/proc/{pid}/stat") as f:
            fields = f.read().split()
            utime_ticks = int(fields[13])
            stime_ticks = int(fields[14])
            return utime_ticks / CLK_TCK, stime_ticks / CLK_TCK
    except FileNotFoundError:
        print(f"[sample] /proc/{pid}/stat not found")
        return 0.0, 0.0


def stddev(values):
    if not values:
        return 0.0
    mean = sum(values) / len(values)
    var = sum((x - mean) ** 2 for x in values) / len(values)
    return math.sqrt(var)


# ----------------------------
# Controller
# ----------------------------

class Controller:
    def __init__(self, args):
        self.args = args
        self.server_proc = None

        self.rss_samples = []
        self.sampling = False
        self.last_out_csv = None

        self.cpu_start = None
        self.num_handshakes = None

    def start_openssl(
        self,
        groups: str,
        cert: str,
        key: str,
        ciphersuite: str,
        out_csv: str,
        num_handshakes: int,
    ):
        if self.server_proc and self.server_proc.poll() is None:
            raise RuntimeError("s_server already running")

        env = os.environ.copy()
        env["OPENSSL_CONF"] = self.args.openssl_conf

        cmd = [
            self.args.openssl_bin, "s_server",
            "-tls1_3",
            "-provider", "default",
            "-provider", "oqsprovider",
            "-accept", f"0.0.0.0:{self.args.port}",
            "-cert", cert,
            "-key", key,
            "-groups", groups,
            "-no_ticket",
            "-num_tickets", "0",
            "-ciphersuites", ciphersuite,
            "-www",
        ]

        print(
            f"[controller] START\n"
            f"  groups       = {groups}\n"
            f"  cert         = {Path(cert).name}\n"
            f"  key          = {Path(key).name}\n"
            f"  ciphersuite  = {ciphersuite}\n"
            f"  handshakes   = {num_handshakes}\n"
            f"  out_csv      = {out_csv}"
        )

        self.server_proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env,
            text=True,
        )

        time.sleep(0.2)

        self.cpu_start = read_cpu_seconds(self.server_proc.pid)
        self.num_handshakes = num_handshakes

        self.rss_samples = []
        self.sampling = True
        self.last_out_csv = out_csv

    def stop_and_write(self):
        if not self.server_proc or self.server_proc.poll() is not None:
            raise RuntimeError("s_server not running")

        self.sampling = False

        cpu_end = read_cpu_seconds(self.server_proc.pid)

        self.server_proc.terminate()
        try:
            self.server_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            print("[controller] server did not exit, killing…")
            self.server_proc.kill()
            self.server_proc.wait()

        # ---- CPU (average per handshake) ----
        user_cpu = cpu_end[0] - self.cpu_start[0]
        sys_cpu = cpu_end[1] - self.cpu_start[1]
        total_cpu = user_cpu + sys_cpu

        user_cpu /= self.num_handshakes
        sys_cpu /= self.num_handshakes
        total_cpu /= self.num_handshakes

        # ---- Memory statistics ----
        peak = max(self.rss_samples) if self.rss_samples else 0
        avg  = sum(self.rss_samples) / len(self.rss_samples) if self.rss_samples else 0
        std  = stddev(self.rss_samples)

        out = Path(self.last_out_csv).expanduser().resolve()
        out.parent.mkdir(parents=True, exist_ok=True)

        # ---- Write summary CSV ----
        with open(out, "w") as f:
            f.write(
                "peak_rss_kb,avg_rss_kb,std_rss_kb,"
                "peak_rss_mb,avg_rss_mb,std_rss_mb,"
                "user_cpu_s,sys_cpu_s,total_cpu_s,total_cpu_ms,num_samples\n"
            )
            f.write(
                f"{peak},{avg:.2f},{std:.2f},"
                f"{peak/1024:.2f},{avg/1024:.2f},{std/1024:.2f},"
                f"{user_cpu:.6f},{sys_cpu:.6f},{total_cpu:.6f},"
                f"{total_cpu*1000:.3f},{len(self.rss_samples)}\n"
            )

        # ---- Write raw RSS samples ----
        samples_path = out.with_suffix(".rss_samples.csv")
        with open(samples_path, "w") as f:
            f.write("sample_index,rss_kb,rss_mb\n")
            for i, rss in enumerate(self.rss_samples):
                f.write(f"{i},{rss},{rss/1024:.2f}\n")

        print(f"[controller] STOP → wrote {out}")
        print(f"[controller] RSS samples → wrote {samples_path}")

        return out

    def sample_loop_tick(self):
        if self.sampling and self.server_proc and self.server_proc.poll() is None:
            rss = read_rss_kb(self.server_proc.pid)
            if rss > 0:
                self.rss_samples.append(rss)


# ----------------------------
# Main loop
# ----------------------------

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--bind-ip", required=True)
    p.add_argument("--control-port", type=int, default=9000)
    p.add_argument("--port", type=int, default=4433)
    p.add_argument("--openssl-bin", required=True)
    p.add_argument("--openssl-conf", required=True)
    p.add_argument("--sample-interval", type=float, default=0.01)

    args = p.parse_args()
    ctl = Controller(args)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.bind_ip, args.control_port))
    srv.listen(5)
    srv.settimeout(args.sample_interval)

    print(f"[controller] listening on {args.bind_ip}:{args.control_port}")

    try:
        while True:
            ctl.sample_loop_tick()

            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue

            with conn:
                try:
                    data = conn.recv(8192).decode(errors="replace").strip()

                    if data.startswith("START "):
                        parts = data.split(" ", 6)
                        if len(parts) != 7:
                            msg = "bad START format"
                            print(f"[controller][ERROR] {msg}: {data}")
                            conn.sendall(f"ERR {msg}\n".encode())
                            continue

                        (
                            _,
                            groups,
                            cert,
                            key,
                            ciphersuite,
                            out_csv,
                            n,
                        ) = parts

                        ctl.start_openssl(
                            groups=groups,
                            cert=cert,
                            key=key,
                            ciphersuite=ciphersuite,
                            out_csv=out_csv,
                            num_handshakes=int(n),
                        )
                        conn.sendall(b"OK started\n")

                    elif data == "STOP":
                        out = ctl.stop_and_write()
                        conn.sendall(f"OK stopped {out}\n".encode())

                    elif data == "QUIT":
                        conn.sendall(b"OK bye\n")
                        break

                    else:
                        print(f"[controller][ERROR] unknown command: {data}")
                        conn.sendall(b"ERR unknown command\n")

                except Exception as e:
                    print("[controller][EXCEPTION] while handling command")
                    print(traceback.format_exc())
                    conn.sendall(f"ERR {e}\n".encode())

    except Exception:
        print("[controller][FATAL] unhandled exception in main loop")
        print(traceback.format_exc())

    finally:
        srv.close()
        print("[controller] server socket closed")


if __name__ == "__main__":
    main()
