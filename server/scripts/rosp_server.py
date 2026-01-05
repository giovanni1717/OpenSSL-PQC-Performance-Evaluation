#!/usr/bin/env python3
import argparse
import os
import socket
import subprocess
import time
from pathlib import Path
import traceback


class Controller:
    def __init__(self, args):
        self.args = args
        self.server_proc = None

    def start_openssl(
        self,
        groups: str,
        cert: str,
        key: str,
        ciphersuite: str,
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

        print("\n[controller] ===== START REQUEST =====")
        print(f"[controller] TLS groups      : {groups}")
        print(f"[controller] Certificate     : {cert}")
        print(f"[controller] Private key     : {key}")
        print(f"[controller] Ciphersuite     : {ciphersuite}")
        print(f"[controller] Listening port  : {self.args.port}")
        print("[controller] =========================")

        self.server_proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env,
            text=True,
        )

        # Small grace period so s_server binds before client connects
        time.sleep(0.2)

        print("[controller] s_server started successfully\n")

    def stop(self):
        if not self.server_proc or self.server_proc.poll() is not None:
            raise RuntimeError("s_server not running")

        print("\n[controller] ===== STOP REQUEST =====")

        self.server_proc.terminate()
        try:
            self.server_proc.wait(timeout=5)
            print("[controller] s_server terminated cleanly")
        except subprocess.TimeoutExpired:
            print("[controller] s_server did not exit, killing…")
            self.server_proc.kill()
            self.server_proc.wait()
            print("[controller] s_server killed")

        self.server_proc = None
        print("[controller] =========================\n")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--bind-ip", required=True)
    p.add_argument("--control-port", type=int, default=9000)
    p.add_argument("--port", type=int, default=4433)
    p.add_argument("--openssl-bin", required=True)
    p.add_argument("--openssl-conf", required=True)

    args = p.parse_args()
    ctl = Controller(args)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.bind_ip, args.control_port))
    srv.listen(5)

    print("\n[controller] ====================================")
    print(f"[controller] ROSP server listening on {args.bind_ip}:{args.control_port}")
    print("[controller] ====================================\n")

    try:
        while True:
            conn, peer = srv.accept()
            with conn:
                peer_ip, peer_port = peer
                print(f"[controller] Connection from {peer_ip}:{peer_port}")

                try:
                    data = conn.recv(8192).decode(errors="replace").strip()
                    print(f"[controller] Received command: {data}")

                    if data.startswith("START "):
                        parts = data.split(" ", 4)
                        if len(parts) != 5:
                            msg = "bad START format"
                            print(f"[controller][ERROR] {msg}: {data}")
                            conn.sendall(f"ERR {msg}\n".encode())
                            continue

                        _, groups, cert, key, ciphersuite = parts

                        ctl.start_openssl(
                            groups=groups,
                            cert=cert,
                            key=key,
                            ciphersuite=ciphersuite,
                        )
                        conn.sendall(b"OK started\n")

                    elif data == "STOP":
                        ctl.stop()
                        conn.sendall(b"OK stopped\n")

                    elif data == "QUIT":
                        print("[controller] QUIT received, shutting down server")
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
        print("\n[controller] Server socket closed")


if __name__ == "__main__":
    main()
