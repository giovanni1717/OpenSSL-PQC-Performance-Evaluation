#!/usr/bin/env python3
"""
Puppeteer for client_handshake_analyzer_puppet.py

Runs a reduced full-stack comparison:
- Pure PQC (128 / 192)
- Hybrid PQC (128 / 192)
- Classical baseline (128 / 192)

Total runs: 6
"""

import subprocess
import time
from pathlib import Path

# ============================================================
# Puppet-specific configuration
# ============================================================

PUPPET_SCRIPT = "/home/client/pqc/scripts/puppets/client_handshake_analyzer_puppet.py"

# ---- fixed OpenSSL paths (canonical) ----
OPENSSL_BIN = "/home/client/pqc/build/bin/openssl"
OPENSSL_CONF = "/home/client/pqc/build/ssl/openssl.cnf"

# ---- network / ROSP ----
SERVER_IP = "192.168.57.10"
SERVER_PORT = "4433"
CONTROL_PORT = "9000"

CLIENT_IP = "192.168.56.10"
CAPTURE_IFACE = "enp0s8"

# ---- experiment constants ----
ITERATIONS = "1000"
SLEEP_BETWEEN_RUNS = 20

RESULTS_BASE = "/home/client/pqc/results/handshake_analyzer/full_comparison"

TSHARK_BIN = "tshark"


def run_experiment(group, sigalgs, ciphersuite, label):
    """
    Run a single handshake analyzer experiment.
    """

    out_dir = Path(RESULTS_BASE) / label
    out_dir.mkdir(parents=True, exist_ok=True)

    out_csv = out_dir / "handshake_times.csv"
    pcap = out_dir / "capture.pcapng"
    keylog = out_dir / "keys.log"

    # ---- derive server certificate + key from signature algorithm ----
    server_cert = f"/home/server/pqc/pqc_certificates/{sigalgs}.crt"
    server_key  = f"/home/server/pqc/pqc_keys/{sigalgs}.key"

    print("\n→ Launching handshake analyzer experiment")
    print(f"  group        = {group}")
    print(f"  sigalgs      = {sigalgs}")
    print(f"  ciphersuite  = {ciphersuite}")
    print(f"  iterations   = {ITERATIONS}")
    print(f"  server cert  = {server_cert}")
    print(f"  server key   = {server_key}")
    print(f"  output dir   = {out_dir}")

    cmd = [
        "python3", PUPPET_SCRIPT,
        "--group", group,
        "--sigalgs", sigalgs,
        "--ciphersuite", ciphersuite,
        "--iterations", ITERATIONS,
        "--server-ip", SERVER_IP,
        "--port", SERVER_PORT,
        "--control-port", CONTROL_PORT,
        "--iface", CAPTURE_IFACE,
        "--client-ip", CLIENT_IP,
        "--server-cert", server_cert,
        "--server-key", server_key,
        "--openssl-bin", OPENSSL_BIN,
        "--openssl-conf", OPENSSL_CONF,
        "--keylogfile", str(keylog),
        "--pcap", str(pcap),
        "--out-csv", str(out_csv),
        "--tshark-bin", TSHARK_BIN,
    ]

    subprocess.run(cmd, check=True)

    print(f"✓ Experiment completed. Sleeping {SLEEP_BETWEEN_RUNS}s…")
    time.sleep(SLEEP_BETWEEN_RUNS)


def main():

    print("\n=== Full PQC vs Hybrid vs Classical — Handshake Time Analysis ===")

    experiments = [
        # ---- Pure PQC ----
        ("MLKEM512",      "ML-DSA-44",  "TLS_AES_128_GCM_SHA256", "pqc_128"),
        ("MLKEM768",      "ML-DSA-65",  "TLS_AES_256_GCM_SHA384", "pqc_192"),

        # ---- Hybrid PQC ----
        ("p256_mlkem512", "p256_mldsa44", "TLS_AES_128_GCM_SHA256", "hybrid_128"),
        ("p384_mlkem768", "p384_mldsa65", "TLS_AES_256_GCM_SHA384", "hybrid_192"),

        # ---- Classical baseline ----
        ("secp256r1", "ecdsa_secp256r1_sha256", "TLS_AES_128_GCM_SHA256", "classical_128"),
        ("secp384r1", "ecdsa_secp384r1_sha384", "TLS_AES_256_GCM_SHA384", "classical_192"),
    ]

    for group, sigalgs, ciphersuite, label in experiments:
        run_experiment(
            group=group,
            sigalgs=sigalgs,
            ciphersuite=ciphersuite,
            label=label,
        )

    print("\n=== All full-comparison handshake experiments completed ===")


if __name__ == "__main__":
    main()
