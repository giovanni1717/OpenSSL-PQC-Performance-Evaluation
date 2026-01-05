#!/usr/bin/env python3
"""
Batch experiment runner for server-side PQC TLS measurements.

Runs a reduced full-stack comparison:
- Pure PQC (128 / 192)
- Hybrid PQC (128 / 192)
- Classical baseline (128 / 192)

Total runs: 6
"""

import subprocess
import time
from pathlib import Path

# ---- fixed paths and common parameters ----

CLIENT_SCRIPT = "/home/client/pqc/scripts/puppets/client_server_measures_initializer_puppet.py"
OPENSSL_BIN = "/home/client/pqc/build/bin/openssl"
OPENSSL_CONF = "/home/client/pqc/build/ssl/openssl.cnf"

SERVER_IP = "192.168.57.10"
SERVER_PORT = "4433"
CONTROL_IP = "192.168.57.10"
CONTROL_PORT = "9000"

ITERATIONS = "1000"
SLEEP_BETWEEN_RUNS = 5

RESULTS_BASE = "/home/server/pqc/results/full_comparison"


def run_experiment(group, sigalgs, ciphersuite, label):
    """
    Run a single server measurement experiment.
    """
    out_dir = Path(RESULTS_BASE) / label

    out_csv = out_dir / "server_mem_cpu.csv"

    cmd = [
        "python3", CLIENT_SCRIPT,
        "--group", group,
        "--sigalgs", sigalgs,
        "--iterations", ITERATIONS,
        "--server-ip", SERVER_IP,
        "--port", SERVER_PORT,
        "--openssl-bin", OPENSSL_BIN,
        "--openssl-conf", OPENSSL_CONF,
        "--control-ip", CONTROL_IP,
        "--control-port", CONTROL_PORT,
        "--ciphersuites", ciphersuite,
        "--server-out-csv", str(out_csv),
    ]

    print("\n→ Launching server-side experiment")
    print(f"  group        = {group}")
    print(f"  sigalgs      = {sigalgs}")
    print(f"  ciphersuite  = {ciphersuite}")
    print(f"  output       = {out_csv}")

    subprocess.run(cmd, check=True)

    print(f"✓ Experiment completed. Sleeping {SLEEP_BETWEEN_RUNS}s…")
    time.sleep(SLEEP_BETWEEN_RUNS)


def main():
    print("\n=== Full PQC vs Hybrid vs Classical — Server Measurements ===")

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

    print("\n=== All server-side experiments completed successfully ===")


if __name__ == "__main__":
    main()
