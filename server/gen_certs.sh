#!/usr/bin/env bash
set -euo pipefail

KEYDIR="/home/server/pqc/pqc_keys"
CERTDIR="/home/server/pqc/pqc_certificates"
OPENSSL="/home/server/pqc/build/bin/openssl"

mkdir -p "$KEYDIR" "$CERTDIR"
umask 077

# Common cert params
DAYS=3650
SUBJ_BASE="/CN=pqc-server"

# 1) Classical baseline certs (ECDSA P-256 / P-384)
# (Note: TLS sigalgs are ecdsa_secp256r1_sha256 / ecdsa_secp384r1_sha384,
# but for *certificate generation* we generate EC keys on the right curves.)
"$OPENSSL" req -new -x509 -newkey ec \
  -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout "$KEYDIR/ecdsa_secp256r1_sha256.key" \
  -out    "$CERTDIR/ecdsa_secp256r1_sha256.crt" \
  -nodes -days "$DAYS" -subj "${SUBJ_BASE}-ecdsa-p256"

"$OPENSSL" req -new -x509 -newkey ec \
  -pkeyopt ec_paramgen_curve:secp384r1 \
  -keyout "$KEYDIR/ecdsa_secp384r1_sha384.key" \
  -out    "$CERTDIR/ecdsa_secp384r1_sha384.crt" \
  -nodes -days "$DAYS" -subj "${SUBJ_BASE}-ecdsa-p384"

# 2) PQC + Hybrid signature certs (one-to-one with your algorithm list)
algs=(
  "ML-DSA-44"
  "ML-DSA-65"
  "sphincssha2128fsimple"
  "sphincssha2192fsimple"
  "falconpadded512"
  "mayo1"
  "mayo3"
  "p256_mldsa44"
  "p384_mldsa65"
  "p256_sphincssha2128fsimple"
  "p384_sphincssha2192fsimple"
  "p256_falconpadded512"
  "p256_mayo1"
  "p384_mayo3"
)

for alg in "${algs[@]}"; do
  safe="${alg//[^A-Za-z0-9._-]/_}"   # file-safe name
  key="$KEYDIR/${safe}.key"
  crt="$CERTDIR/${safe}.crt"

  "$OPENSSL" genpkey -algorithm "$alg" -out "$key"
  "$OPENSSL" req -new -x509 -key "$key" -out "$crt" \
    -nodes -days "$DAYS" -subj "${SUBJ_BASE}-${safe}"
done

echo "Done. Keys in: $KEYDIR   Certs in: $CERTDIR"
