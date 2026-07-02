#!/bin/bash
###############################################################################
# run_curl_test.sh — Test with curl (HTTP over TLCP/TLS)
#
# Tests HTTP-level communication through the TLS tunnel.
# Most useful with TLS 1.3 mode since curl doesn't support TLCP.
#
# Usage:
#   ./run_curl_test.sh              # Default: localhost:8443
#   ./run_curl_test.sh 9443         # Custom port
###############################################################################
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

PORT="${1:-8443}"
HOST="${2:-127.0.0.1}"

echo "========================================"
echo "  curl -> Server (TLS debug)"
echo "  Target: https://$HOST:$PORT"
echo "========================================"
echo ""
echo "NOTE: curl does NOT support TLCP."
echo "      Start server in tls13 mode first: ./run_server.sh $PORT tls13"
echo ""

curl -v \
    --cacert certs/rootca.crt \
    --connect-timeout 5 \
    "https://$HOST:$PORT/" 2>&1 || true

echo ""
echo "If curl failed with a TLS error, the server might be in TLCP mode."
echo "Use ./run_gmssl_client.sh for TLCP testing."
