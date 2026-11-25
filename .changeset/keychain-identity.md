---
"swift-daemon-services": patch
verctl:group: added
---

Add the `KeychainIdentity` product.
It keeps TLS client identities in the Secure Enclave, in a team keychain group.

Add the `KeychainIdentityNIOSSL` product.
It presents such an identity in a SwiftNIO TLS handshake.
