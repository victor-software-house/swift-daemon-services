# Design

## Context

See [proposal.md](proposal.md) for why, and the two spec files under [specs/](specs/) for what.

Package rules every product follows:

1. It works on any Mac on the supported macOS as a person installs it (operator, 2026-11-24).
   It needs no device management profile, no System Integrity Protection change, and no pre-granted privacy access.
2. Nothing resident when idle, and no measurable cost on a hot path; every speed claim comes from a release-build measurement.
3. The signing team is read from the running code's signature, never written in source.
4. Every check on a boundary fails closed.
5. Dependencies: Apple's frameworks, and Apple's Swift packages where the frameworks have no API, as `swift-certificates` for X.509 (operator, 2026-11-25).
   A product that needs a networking stack, such as SwiftNIO, is its own product.
6. macOS 27 and Swift 6.4 with strict concurrency.

Facts read on 2026-11-25:

1. `swift-certificates` 1.21.2 signs with a `SecureEnclave.P256.Signing.PrivateKey` or a `SecKey` (`Certificate.PrivateKey.init(_:)`).
2. `swift-nio-ssl` 2.37.7 calls `NIOSSLCustomPrivateKey.sign(channel:algorithm:data:)` on an event loop thread and asks that blocking work move to another thread.
3. A Secure Enclave signature took 4.63 ms median on an M-series Mac, through CryptoKit, in the 2026-11-24 measurement.

## Goals / Non-Goals

**Goals:**

1. One app creates a Secure Enclave identity in a team keychain group.
   Another app of the team signs with it while the Mac is locked after its first unlock.
2. macOS itself sees the identity: the stored key and certificate form a `SecIdentity` that URLSession or Network.framework can present.
3. A SwiftNIO TLS client presents the identity with no file on disk.

**Non-Goals:**

1. Issuing certificates; the caller sends the signing request to its own authority.
2. Server identities, Rivest–Shamir–Adleman (RSA) keys, and keys that leave the Mac or sync through iCloud.
3. The other products of the package, which come in their own changes.

## Decisions

### 1. Keys are Secure Enclave `SecKey` items

1. `create(name:)` makes a permanent `SecKey` with `kSecAttrTokenIDSecureEnclave`, type elliptic-curve (EC) prime256v1, in the data-protection keychain (`kSecUseDataProtectionKeychain`), in the store's access group.
2. Its access control is `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` with `.privateKeyUsage`: no user presence, usable while locked after the first unlock, never migrated.
3. The name goes in `kSecAttrLabel` and `kSecAttrApplicationTag`, so a lookup by name finds exactly one key.
4. Alternative: a CryptoKit key's `dataRepresentation` in a generic-password item, as the 2026-11-24 measurement used.
   It lost because macOS forms a `SecIdentity` only from a key item and a certificate item, so URLSession and Network.framework could not present it.

### 2. The access group comes from the store's suffix and the running team

1. `IdentityStore(groupSuffix:)` forms `<team>.<suffix>`, with the team from `SecCodeCopySelf` and `kSecCodeInfoTeamIdentifier`.
2. Creating the store fails when the code is unsigned, has no team, or its `keychain-access-groups` entitlement (read with `SecTaskCopyValueForEntitlement`) lacks the group.
   The error contains the group.
3. Alternative: the caller passes the whole group.
   It lost to package rule 3: the team would then sit in the caller's source.

### 3. The leaf is a certificate item and the chain is one item

1. `store(chain:for:)` checks that the leaf's public key equals the identity's key.
2. The leaf is the only `kSecClassCertificate` item, labelled with the identity's name.
   That is all macOS needs to form a `SecIdentity` with the key.
3. The whole chain, leaf first, is one generic-password item of the data-protection keychain in the same group.
   - Its service is `<group suffix>.chain`, and its account is the identity's name.
   - Its value is a PEM bundle: the PEM block of each certificate, leaf first, one after another.
   - The key, the leaf item and the chain item are all usable after the first unlock, on this device only.
   - No intermediate is a certificate item, so two identities that share an intermediate never collide.
4. A store replaces the previous leaf and chain in these steps:
   - It adds the new leaf.
     An item with identical bytes counts as present.
   - It writes the chain item, updating it or adding it.
   - It reads the `SecIdentity` back.
     When macOS forms none, it deletes the new leaf, puts the old chain back and fails.
   - It deletes the old leaf item of that name, so a reader never finds none.
5. `identity(named:)` returns a `ClientIdentity`, or nil when the group has no key of that name.
   - The identity has a name, a public key, a chain and a `SecIdentity`.
   - The chain comes from the chain item, parsed with `swift-certificates`.
   - macOS forms the `SecIdentity` from the key and the leaf.
   - Before a chain is stored, the chain is empty and the `SecIdentity` is nil.
   - `sign(_:)` returns an X9.62 signature over SHA-256.
   - The identity exposes no `SecKey`.
6. `remove(name:)` deletes the key, the leaf item and the chain item.

### 4. The signing request comes from `swift-certificates`

1. `signingRequest(for:subject:)` builds a signing request in the Public-Key Cryptography Standards (PKCS) 10 format, signed by the identity's key through `Certificate.PrivateKey(SecKey)`.
   It returns the request in Distinguished Encoding Rules (DER) and PEM.
2. The subject is a `DistinguishedName` the caller gives; the package adds no extension the caller did not ask for.

### 5. One closed error type

`KeychainIdentityError` has one case per state a caller acts on: `notSigned`, `missingEntitlement(group)`, `notFound(name)`, `alreadyExists(name)`, `keyMismatch`, `lockedSinceBoot` (`errSecInteractionNotAllowed` before the first unlock), and `keychain(OSStatus)` for the rest.

### 6. The SwiftNIO adapter signs off the event loop

1. `KeychainIdentityNIOSSL` provides `KeychainIdentityPrivateKey: NIOSSLCustomPrivateKey` with the one algorithm `.ecdsaSecp256R1Sha256`.
2. `sign` hands the data to a serial dispatch queue of the key, signs with `SecKeyCreateSignature` and `.ecdsaSignatureMessageX962SHA256`, and completes the promise on the channel's event loop.
3. `TLSConfiguration.clientConfiguration(presenting:)` sets the chain as `NIOSSLCertificate`s and the key as `.customPrivateKey`.
4. Alternative: sign on the event loop.
   It lost because a 5 ms signature would stall every other connection of that loop.

### 7. Tests split by what a hosted runner has

1. CI tests run with a software P-256 key behind the same internal `SigningKey` protocol the Secure Enclave key implements.
   They cover:
   - the signing request's shape and signature
   - the chain check
   - the error mapping
   - a full TLS 1.3 handshake in-process against a SwiftNIO server that requires a client certificate
2. `Probe/` is an XcodeGen project with two small apps and a shared group.
   One creates an identity; the other, started by launchd, signs 200 times and reports the latency.
   It runs by hand on a locked Mac that has a development profile.
   Its result goes in tasks.md.

### 8. The repository turns on CI and the Swift pieces

The repository takes `ci`, `swift_tasks`, `swift_settings`, `swift_release`, `swift_format` and `swift_docs` (targets `KeychainIdentity`, `KeychainIdentityNIOSSL`) through `template:on`, with the first package.

## Risks / Trade-offs

1. [The `SecKey` path is not the measured CryptoKit path.] → The probe measures it before the first release.
2. [A store of a leaf that macOS cannot pair with the key yields no `SecIdentity`.] → `store` reads the identity back, undoes its writes and fails when it is missing.
3. [`.macOS(.v27)` needs tools 6.4.] → CI's pinned Xcode 27.2 builds it; a failure there names the platform.
