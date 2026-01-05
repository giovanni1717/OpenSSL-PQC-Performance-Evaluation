#!/usr/bin/env python3
"""
Batch experiment runner for PQC TLS measurements.

This script orchestrates four experimental iterations:
- KEM-only (128-bit tier)
- KEM-only (192-bit tier)
- Signature-only (128-bit tier)
- Signature-only (192-bit tier)

Each experiment invokes client_server_measures_initializer_puppet.py once per algorithm,
waits 5 seconds between runs, and prints clear progress messages.
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


def run_experiment(group, sigalgs, ciphersuite, out_dir):
    """
    Run a single experiment invocation.
    """
    out_csv = f"{out_dir}/server_mem_cpu.csv"
    
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
        "--server-out-csv", out_csv,
    ]

    print(f"\n→ Launching experiment")
    print(f"  group        = {group}")
    print(f"  sigalgs      = {sigalgs}")
    print(f"  ciphersuite  = {ciphersuite}")
    print(f"  output       = {out_csv}")

    subprocess.run(cmd, check=True)

    print(f"✓ Experiment completed. Sleeping {SLEEP_BETWEEN_RUNS}s…")
    time.sleep(SLEEP_BETWEEN_RUNS)


def main():
    print("\n=== Iteration 1: KEM-only (128-bit tier, classical auth) ===")

    sigalgs = "ecdsa_secp256r1_sha256"
    ciphersuite = "TLS_AES_128_GCM_SHA256"

    groups_128 = [
        "MLKEM512",
        "bikel1",
        "frodo640aes",
        "p256_mlkem512",
        "p256_bikel1",
        "p256_frodo640aes",
        "secp256r1",
    ]

    for group in groups_128:
        run_experiment(
            group=group,
            sigalgs=sigalgs,
            ciphersuite=ciphersuite,
            out_dir=f"/home/server/pqc/results/{group}",
        )

    print("\n=== Iteration 2: KEM-only (192-bit tier, classical auth) ===")

    sigalgs = "ecdsa_secp384r1_sha384"
    ciphersuite = "TLS_AES_256_GCM_SHA384"

    groups_192 = [
        "MLKEM768",
        "bikel3",
        "frodo976aes",
        "p384_mlkem768",
        "p384_bikel3",
        "p384_frodo976aes",
        "secp384r1",
    ]

    for group in groups_192:
        run_experiment(
            group=group,
            sigalgs=sigalgs,
            ciphersuite=ciphersuite,
            out_dir=f"/home/server/pqc/results/{group}",
        )

    print("\n=== Iteration 3: Signature-only (128-bit tier, fixed group) ===")

    group = "secp256r1"
    ciphersuite = "TLS_AES_128_GCM_SHA256"

    sigalgs_128 = [
        "ML-DSA-44",
        "sphincssha2128fsimple",
        "falconpadded512",
        "mayo1",
        "p256_mldsa44",
        "p256_sphincssha2128fsimple",
        "p256_falconpadded512",
        "p256_mayo1",
        "ecdsa_secp256r1_sha256",
    ]

    for sigalgs in sigalgs_128:
        run_experiment(
            group=group,
            sigalgs=sigalgs,
            ciphersuite=ciphersuite,
            out_dir=f"/home/server/pqc/results/{sigalgs}",
        )

    print("\n=== Iteration 4: Signature-only (192-bit tier, fixed group) ===")

    group = "secp384r1"
    ciphersuite = "TLS_AES_256_GCM_SHA384"

    sigalgs_192 = [
        "ML-DSA-65",
        "sphincssha2192fsimple",
        "mayo3",
        "p384_mldsa65",
        "p384_sphincssha2192fsimple",
        "p384_mayo3",
        "ecdsa_secp384r1_sha384",
    ]

    for sigalgs in sigalgs_192:
        run_experiment(
            group=group,
            sigalgs=sigalgs,
            ciphersuite=ciphersuite,
            out_dir=f"/home/server/pqc/results/{sigalgs}",
        )

    print("\n=== All experiments completed successfully ===")


if __name__ == "__main__":
    main()
