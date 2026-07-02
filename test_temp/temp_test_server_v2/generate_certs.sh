#!/bin/bash
###############################################################################
# generate_certs.sh — Generate a full PKI for TLCP/GMSSL testing
#
# Creates (in ./certs/):
#   rootca.key / rootca.crt         — Root CA (SM2, self-signed)
#   sign.key / sign.crt             — Server Signing certificate
#   enc.key / enc.crt               — Server Encryption certificate
#   sign_chain.pem / enc_chain.pem  — Server cert chains
#   client_sign.key / client_sign.crt — Client signing cert
#   client_enc.key / client_enc.crt   — Client encryption cert
#   client_sign_chain.pem / client_enc_chain.pem — Client cert chains
#
# All private keys are decrypted to unencrypted PKCS#8 PEM.
#
# Usage:
#   ./generate_certs.sh               (uses gmssl from PATH)
#   GMSSL=/path/to/gmssl ./generate_certs.sh
###############################################################################
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Try to find gmssl binary
GMSSL="${GMSSL:-}"
if [ -z "$GMSSL" ]; then
    for candidate in \
        "$SCRIPT_DIR/../shared/offline/GmSSL/build/bin/gmssl" \
        /usr/local/bin/gmssl \
        /usr/bin/gmssl; do
        if [ -x "$candidate" ]; then
            GMSSL="$candidate"
            break
        fi
    done
fi
if [ -z "$GMSSL" ]; then
    echo "ERROR: gmssl binary not found. Set GMSSL=/path/to/gmssl" >&2
    exit 1
fi

echo "Using gmssl: $GMSSL"
$GMSSL version 2>/dev/null || true

PASS="12345678"

# Build decrypt_key helper if needed
if [ ! -x "$SCRIPT_DIR/decrypt_key" ]; then
    echo ""
    echo "Building decrypt_key helper..."
    GMSSL_DIR="$SCRIPT_DIR/../shared/offline/GmSSL"
    if [ -d "$GMSSL_DIR" ]; then
        gcc -o "$SCRIPT_DIR/decrypt_key" "$SCRIPT_DIR/decrypt_key.c" \
            -I"$GMSSL_DIR/include" \
            -L"$GMSSL_DIR/build/lib" \
            -lgmssl -Wl,-rpath,"$GMSSL_DIR/build/lib" 2>/dev/null && \
            echo "  -> decrypt_key built successfully" || \
            echo "  WARNING: Could not build decrypt_key"
    fi
fi

# Create output directory
rm -rf certs
mkdir -p certs
cd certs

gen_keypair() {
    local name="$1"
    local cn="$2"
    local usage="$3"

    echo "  Generating keypair for: $cn"
    $GMSSL sm2keygen -pass $PASS -out "${name}.key"
    $GMSSL reqgen \
        -C CN -ST Beijing -L Beijing -O "TestOrg" -OU "TestUnit" \
        -CN "$cn" \
        -key "${name}.key" -pass $PASS \
        -out "${name}.req"
    
    # Split usage into separate -key_usage flags
    local usage_flags=""
    for u in $usage; do
        usage_flags="$usage_flags -key_usage $u"
    done
    
    $GMSSL reqsign \
        -in "${name}.req" -serial_len 12 -days 365 \
        -cacert rootca.crt -key rootca.key -pass $PASS \
        $usage_flags \
        -out "${name}.crt"
    
    rm -f "${name}.req"
}

echo ""
echo "========================================"
echo "  Step 1/6: Root CA"
echo "========================================"
$GMSSL sm2keygen -pass $PASS -out rootca.key
$GMSSL certgen \
    -C CN -ST Beijing -L Beijing -O "TestOrg" -OU "TestUnit" \
    -CN "GMSSL Test Root CA" \
    -days 3650 \
    -key rootca.key -pass $PASS \
    -ca -path_len_constraint 6 \
    -key_usage keyCertSign -key_usage cRLSign \
    -out rootca.crt
echo "  -> rootca.key, rootca.crt"

echo ""
echo "========================================"
echo "  Step 2/6: Server Sign Cert"
echo "========================================"
gen_keypair "sign" "GMSSL Test Server Sign" "digitalSignature nonRepudiation"

echo ""
echo "========================================"
echo "  Step 3/6: Server Enc Cert"
echo "========================================"
gen_keypair "enc" "GMSSL Test Server Enc" "keyEncipherment dataEncipherment keyAgreement"

echo ""
echo "========================================"
echo "  Step 4/6: Client Sign Cert"
echo "========================================"
gen_keypair "client_sign" "GMSSL Test Client Sign" "digitalSignature nonRepudiation"

echo ""
echo "========================================"
echo "  Step 5/6: Client Enc Cert"
echo "========================================"
gen_keypair "client_enc" "GMSSL Test Client Enc" "keyEncipherment dataEncipherment keyAgreement"

echo ""
echo "========================================"
echo "  Step 6/6: Build Chains & Decrypt Keys"
echo "========================================"

# Build chains
cat sign.crt rootca.crt > sign_chain.pem
cat enc.crt rootca.crt > enc_chain.pem
cat client_sign.crt rootca.crt > client_sign_chain.pem
cat client_enc.crt rootca.crt > client_enc_chain.pem
echo "  -> certificate chains created"

# Decrypt private keys to unencrypted PKCS#8
DECRYPT="$SCRIPT_DIR/decrypt_key"
if [ -x "$DECRYPT" ]; then
    for keyfile in rootca.key sign.key enc.key client_sign.key client_enc.key; do
        "$DECRYPT" "$keyfile" "$PASS"
        mv "${keyfile}.unencrypted" "$keyfile"
        echo "  -> decrypted $keyfile"
    done
else
    echo "  WARNING: decrypt_key not available"
    echo "  Keys remain encrypted with password '$PASS'"
fi

echo ""
echo "========================================"
echo "  DONE!"
echo "========================================"
echo ""
echo "Certificate files in: $(pwd)"
ls -la *.key *.crt *.pem 2>/dev/null
echo ""
echo "Next steps:"
echo "  1. Start the Erlang server:    ./run_server.sh"
echo "  2. Test with Erlang client:    ./run_erlang_client.sh"
echo "  3. Test with gmssl client:     ./run_gmssl_client.sh"
echo "  4. Test with openssl s_client: ./run_openssl_client.sh"
