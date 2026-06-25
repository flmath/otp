# SSL Application Analysis

The `ssl` application in Erlang/OTP provides the implementation for the Secure Sockets Layer (SSL), Transport Layer Security (TLS), and Datagram Transport Layer Security (DTLS) protocols. It relies on the `crypto` application for cryptographic primitives and `public_key` for certificate handling.

## Core Architecture
The `ssl` application is structured as a supervision tree, managing connections, sessions, caches, and listening sockets.
Key components:
1. **Connection Processes**: Each active SSL/TLS/DTLS connection is managed by a separate process (typically utilizing `gen_statem` behavior) to handle the complex handshake and data exchange state machine.
2. **Session Cache**: Caches TLS sessions and tickets to support session resumption and abbreviated handshakes.
3. **Record Protocol**: Encapsulates data into records, handling fragmentation, compression, encryption, and MAC verification.

## Handshake State Machines (TLS/DTLS)
The connection process relies on robust state machines (implemented in modules like `ssl_gen_statem.erl`, `tls_connection.erl`, `tls_handshake_1_3.erl`, etc.). 

### Pre-TLS 1.3 State Flow
1. **Hello**: Exchange `ClientHello` and `ServerHello`. Negotiate protocol version, cipher suite, and random nonces.
2. **Certify**: Exchange certificates and perform key exchange (e.g., ECDHE). 
3. **Cipher**: Exchange `ChangeCipherSpec` and `Finished` messages to verify the handshake and activate encryption.
4. **Connection**: The secure tunnel is established. Application data can be sent and received.
5. **Downgrade**: Transitioning from a secure connection back to a cleartext socket (if supported/requested).

### TLS 1.3 State Flow
TLS 1.3 drastically simplifies the state machine for lower latency (1-RTT or 0-RTT handshakes) and improved security (more of the handshake is encrypted).
1. **Start**: Initialize and process `ClientHello`.
2. **Negotiated / Recv Server Hello**: Negotiate cryptographic parameters and keys early.
3. **Wait Cert / Wait CV**: Verify client/server certificates and certificate verify messages.
4. **Wait Finished**: Process the `Finished` MAC over the transcript.
5. **Connection**: Established secure channel.

## Erlang Concurrency Model
The state machines leverage Erlang's actor model. Each connection operates asynchronously, reacting to incoming TCP/UDP packets (often active-N or passive socket modes) and mapping them through the `gen_statem` states to trigger transitions.
