# Proposal

## Why

1. A background part of a macOS app often needs a TLS client identity, so that a server can tell its requests from anyone else's.
   The private key of that identity should never leave the Mac and never sit in a file.
2. The Secure Enclave keeps such a key.
   A keychain access group shared by apps of one team lets one app create the identity and another app sign with it.
   A measurement on 2026-11-24, on a locked Mac, showed:
   - An app started by launchd signed with a key that another app of its team created, through a shared group.
   - The median time was 4.63 ms per signature.
3. No package gives a Swift app that whole path today.
   The path has these parts:
   - key creation
   - a certificate signing request
   - the certificate stored beside the key
   - a signer that a SwiftNIO TLS client accepts
4. This is the package's first release.
   A mirror client certificate needs it first (operator, 2026-11-25).

## What Changes

1. The package gets its `Package.swift`, CI and the shared Swift checks, through the template's Swift pieces.
2. A `KeychainIdentity` library product with:
   - Secure Enclave keys and TLS client identities in a team keychain group
   - a certificate signing request
   - the certificate chain, stored so macOS forms a `SecIdentity`
3. A `KeychainIdentityNIOSSL` library product: a `NIOSSLCustomPrivateKey` that signs a TLS handshake with a stored identity's key.
4. A `KeychainIdentityProbe` test app, signed and run by hand on a Mac, since hosted runners have no Secure Enclave and no signed keychain group.

## Capabilities

### New Capabilities

- `keychain-identity`: create, store, read and remove a Secure Enclave TLS identity, build its signing request, and sign with it.
- `keychain-identity-niossl`: present that identity in a SwiftNIO TLS handshake.

## Impact

1. Dependencies: `apple/swift-certificates` with `swift-asn1` in `KeychainIdentity` (operator, 2026-11-25), and `apple/swift-nio-ssl` in `KeychainIdentityNIOSSL` only.
2. macOS 27 and Swift 6.4, as the package's rules set.
