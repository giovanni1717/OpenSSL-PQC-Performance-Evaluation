#!/usr/bin/env python3
"""
Puppeteer for client_handshake_analyzer_puppet.py

Runs the full PQC TLS experimental matrix:
- KEM-only (128-bit)
- KEM-only (192-bit)
- Signature-only (128-bit)
- Signature-only (192-bit)

Between each experiment run, sleeps 20 seconds.
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

RESULTS_BASE = "/home/client/pqc/results/handshake_analyzer"

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

    # ========================================================
    # Iteration 1 — KEM-only (128-bit)
    # ========================================================

    print("\n=== Iteration 1: KEM-only (128-bit, classical auth) ===")

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
            label=f"kem128/{group}",
        )

    # ========================================================
    # Iteration 2 — KEM-only (192-bit)
    # ========================================================

    print("\n=== Iteration 2: KEM-only (192-bit, classical auth) ===")

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
            label=f"kem192/{group}",
        )

    # ========================================================
    # Iteration 3 — Signature-only (128-bit)
    # ========================================================

    print("\n=== Iteration 3: Signature-only (128-bit, fixed group) ===")

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
            label=f"sig128/{sigalgs}",
        )

    # ========================================================
    # Iteration 4 — Signature-only (192-bit)
    # ========================================================

    print("\n=== Iteration 4: Signature-only (192-bit, fixed group) ===")

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
            label=f"sig192/{sigalgs}",
        )

    print("\n=== All handshake analyzer experiments completed successfully ===")


if __name__ == "__main__":
    main()
