# Crypto Application Analysis

The `crypto` application provides an Erlang API to cryptographic functions, implemented as NIFs (Native Implemented Functions) wrapping the OpenSSL library or dynamically linked cryptolibs.

## Core Features
1. **Hash Functions**: MD5, SHA-1, SHA-2, SHA-3, BLAKE2, etc.
2. **Message Authentication Codes (MAC)**: HMAC, CMAC.
3. **Block and Stream Ciphers**: AES (CBC, GCM, CTR, etc.), ChaCha20, RC4.
4. **Public Key Cryptography**: RSA, DSA, ECDSA, EdDSA primitives.
5. **Key Agreement**: Diffie-Hellman (DH), Elliptic Curve Diffie-Hellman (ECDH).

## State Management
While `crypto` is mostly a stateless functional wrapper, certain operations require stateful context management (e.g., streaming encryption/decryption or progressive hashing).

1. **Application Lifecycle**: The application itself transitions from `unloaded` to `loaded` when the NIFs are initialized.
2. **Context Lifecycles**: 
   - **Hash Contexts**: `init` -> `update` -> `final`
   - **Cipher Contexts**: `init` -> `update` (encryption/decryption) -> `final` (padding/auth tag validation)

## Security Characteristics
- Memory is managed by the Erlang VM and NIF resource objects, which correctly handle wiping of sensitive context data when garbage collected.
- Cryptographic operations block the scheduler thread if they take too long, so `crypto` offloads heavy operations to dirty schedulers where necessary.
