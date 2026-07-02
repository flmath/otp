#!/bin/bash
###############################################################################
# run_all_tests.sh — Run all client tests against the server
#
# Prerequisites:
#   1. Generate certs:  ./generate_certs.sh
#   2. Start server:    ./run_server.sh  (in a separate terminal)
#   3. Run tests:       ./run_all_tests.sh
###############################################################################
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

PORT="${1:-8443}"
PASS=0
FAIL=0

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║       Running All Client Tests                   ║"
echo "║       Server expected on localhost:$PORT          ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""

###############################################################################
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Test 1: Erlang TLCP Client"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if bash run_erlang_client.sh "$PORT" 2>&1 | head -50; then
    echo "  -> RESULT: Check above output"
    ((PASS++)) || true
else
    echo "  -> RESULT: FAILED"
    ((FAIL++)) || true
fi

###############################################################################
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Test 2: GmSSL Native TLCP Client"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if bash run_gmssl_client.sh "$PORT" 2>&1 | head -80; then
    ((PASS++)) || true
else
    echo "  -> RESULT: FAILED"
    ((FAIL++)) || true
fi

###############################################################################
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Test 3: OpenSSL s_client (expected to fail for TLCP)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
timeout 5 bash run_openssl_client.sh "$PORT" 2>&1 | head -30 || true
echo "  -> (OpenSSL failure is expected in TLCP mode)"

###############################################################################
echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║  Test Summary                                    ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""
echo "  Check the SERVER terminal for detailed handshake logs"
echo "  for each client connection."
echo ""
