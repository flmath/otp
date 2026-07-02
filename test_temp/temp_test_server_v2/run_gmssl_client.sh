#!/bin/bash
###############################################################################
# run_gmssl_client.sh — Test Erlang server with the GmSSL native TLCP client
#
# This is the KEY script for cross-implementation debugging!
# It uses the gmssl CLI tool (C-based) to connect to the Erlang server.
# Any handshake failures here help debug the Erlang GMSSL implementation.
#
# Usage:
#   ./run_gmssl_client.sh              # Default: localhost:8443
#   ./run_gmssl_client.sh 9443         # Custom port
###############################################################################
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

PORT="${1:-8443}"
HOST="${2:-127.0.0.1}"

# Find gmssl binary
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

echo "========================================"
echo "  GmSSL TLCP Client -> Erlang Server"
echo "  Target: $HOST:$PORT"
echo "  Binary: $GMSSL"
echo "========================================"
echo ""

echo "--- Test 1: TLCP with ECC_SM4_CBC_SM3 cipher (verbose) ---"
echo ""
echo "Running: gmssl tlcp_client -host $HOST -port $PORT \\"
echo "    -cipher_suite ECC_SM4_CBC_SM3 \\"
echo "    -cacert certs/rootca.crt \\"
echo "    -verbose"
echo ""
echo "(Will send 'Hello from gmssl client' and wait for echo)"
echo "Press Ctrl+C to abort."
echo ""

echo "Hello from gmssl client" | \
    $GMSSL tlcp_client \
        -host "$HOST" \
        -port "$PORT" \
        -cipher_suite ECC_SM4_CBC_SM3 \
        -cacert certs/rootca.crt \
        -in stdin \
        -verbose 2>&1

RESULT=$?
echo ""
if [ $RESULT -eq 0 ]; then
    echo "=== Test 1 PASSED ==="
else
    echo "=== Test 1 FAILED (exit code $RESULT) ==="
    echo ""
    echo "Troubleshooting:"
    echo "  1. Is the Erlang server running? (./run_server.sh)"
    echo "  2. Check the server output for handshake debug info"
    echo "  3. Try with ECDHE cipher: ./run_gmssl_client_ecdhe.sh"
fi

echo ""
echo "--- Test 2: TLCP with ECDHE_SM4_CBC_SM3 cipher (verbose) ---"
echo ""
echo "Running: gmssl tlcp_client -host $HOST -port $PORT \\"
echo "    -cipher_suite ECDHE_SM4_CBC_SM3 \\"
echo "    -cacert certs/rootca.crt \\"
echo "    -cert certs/client_sign_chain.pem \\"
echo "    -key certs/client_sign.key \\"
echo "    -verbose"
echo ""

# ECDHE requires client certificate
if [ -f "certs/client_sign_chain.pem" ] && [ -f "certs/client_sign.key" ]; then
    echo "Hello from gmssl ECDHE client" | \
        $GMSSL tlcp_client \
            -host "$HOST" \
            -port "$PORT" \
            -cipher_suite ECDHE_SM4_CBC_SM3 \
            -cacert certs/rootca.crt \
            -cert certs/client_sign_chain.pem \
            -key certs/client_sign.key \
            -in stdin \
            -verbose 2>&1
    
    RESULT=$?
    echo ""
    if [ $RESULT -eq 0 ]; then
        echo "=== Test 2 PASSED ==="
    else
        echo "=== Test 2 FAILED (exit code $RESULT) ==="
    fi
else
    echo "  SKIPPED: Client certs not found. Run ./generate_certs.sh first."
fi
