# GMSSL/TLCP Debug Test Server

A comprehensive test environment for debugging TLCP (Transport Layer Cryptography Protocol) handshakes between Erlang OTP's SSL implementation and GmSSL.

## Quick Start

```bash
# 1. Generate all certificates
./generate_certs.sh

# 2. Start the debug server (Terminal 1)
./run_server.sh

# 3. Test with different clients (Terminal 2)
./run_erlang_client.sh      # Erlang TLCP client
./run_gmssl_client.sh       # GmSSL native C client (key for debugging!)
./run_openssl_client.sh     # OpenSSL (will fail for TLCP — that's expected)
./run_all_tests.sh          # Run all tests
```

## Files

| File | Description |
|------|-------------|
| `generate_certs.sh` | Generates full PKI: Root CA, server sign/enc, client sign/enc certs |
| `decrypt_key.c` | Helper to decrypt GmSSL encrypted keys to unencrypted PKCS#8 |
| `server.erl` | **Erlang debug server** — prints every handshake step with timing |
| `client.erl` | Erlang mock client with verbose logging |
| `run_server.sh` | Start the Erlang server (TLCP or TLS 1.3 mode) |
| `run_erlang_client.sh` | Test with Erlang client |
| `run_gmssl_client.sh` | **Test with GmSSL native client** (cross-implementation debug) |
| `run_gmssl_server.sh` | Run GmSSL's native server (for comparison) |
| `run_openssl_client.sh` | Test with OpenSSL (TLS 1.3 mode only) |
| `run_curl_test.sh` | Test with curl (TLS 1.3 mode only) |
| `run_all_tests.sh` | Run all client tests |

## Server Modes

### TLCP Mode (default)
```bash
./run_server.sh 8443 tlcp
```
- Uses TLCP v1.1 (Chinese national standard)
- SM2 key exchange, SM4-CBC cipher, SM3 MAC
- Requires dual certificates (sign + enc)
- Only GmSSL clients and Erlang clients can connect

### TLS 1.3 Mode
```bash
./run_server.sh 8443 tls13
```
- Standard TLS 1.3
- AES-GCM ciphers
- Any TLS 1.3 client can connect (OpenSSL, curl, etc.)

## What the Server Shows

The server prints **every step** of the handshake:

```
[CONN #1][STEP 4] transport_accept — waiting for TCP connection...
[CONN #1]  -> TCP connection accepted
[CONN #1]  -> Client address: {127,0,0,1}:54321

[CONN #1][STEP 5] ssl:handshake — starting TLS/TLCP handshake...
[CONN #1]  This is where the magic happens:
[CONN #1]    1. ClientHello  (client -> server)
[CONN #1]    2. ServerHello  (server -> client)
[CONN #1]    3. Certificate  (server -> client)
[CONN #1]    4. ServerKeyExchange (if DHE)
[CONN #1]    5. ServerHelloDone
[CONN #1]    6. ClientKeyExchange
[CONN #1]    7. ChangeCipherSpec
[CONN #1]    8. Finished
  (OTP SSL debug log follows with actual wire data)

[CONN #1][STEP 5 DONE] Handshake SUCCESSFUL! (42 ms)
[CONN #1]  === Connection Details ===
[CONN #1]    Protocol:          'tlcpv1.1'
[CONN #1]    Cipher Suite:      #{cipher => sm4_cbc, ...}
[CONN #1]    Peer Cert:         (none — no client auth)
[CONN #1]  =========================
```

## Cross-Implementation Debugging

The most important debugging scenario is:

1. **Erlang Server + GmSSL Client** — Tests if Erlang's SSL correctly implements TLCP server-side
2. **GmSSL Server + Erlang Client** — Tests if Erlang's SSL correctly implements TLCP client-side

```bash
# Scenario 1: Erlang server, GmSSL client
Terminal 1: ./run_server.sh           # Erlang server
Terminal 2: ./run_gmssl_client.sh     # GmSSL client

# Scenario 2: GmSSL server, Erlang client
Terminal 1: ./run_gmssl_server.sh     # GmSSL server (port 8444)
Terminal 2: ./run_erlang_client.sh 8444  # Erlang client
```

## Certificate Structure

```
Root CA (self-signed, SM2)
├── Server Sign Cert (digitalSignature)
├── Server Enc Cert (keyEncipherment)
├── Client Sign Cert (digitalSignature)
└── Client Enc Cert (keyEncipherment)
```

TLCP requires **dual certificates** for the server:
- **Sign cert**: Used for digital signatures in the handshake
- **Enc cert**: Used for key exchange/encryption

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GMSSL` | auto-detect | Path to `gmssl` binary |
| `ERL` | auto-detect | Path to `erl` binary |
| `OPENSSL` | `openssl` | Path to `openssl` binary |
