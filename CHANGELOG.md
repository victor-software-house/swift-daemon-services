# Changelog

## swift-daemon-services 0.0.2

### Added

- `IdentityStore.names()` lists the names of the identities in the store's group, sorted ([`4d51574`](https://github.com/victor-software-house/swift-daemon-services/commit/4d51574cbd7bf9f21f187e5f6a9133c2a9d2fdc0)).

## swift-daemon-services 0.0.1

### Added

- Add the `KeychainIdentity` product.
  It keeps TLS client identities in the Secure Enclave, in a team keychain group ([`05ad612`](https://github.com/victor-software-house/swift-daemon-services/commit/05ad6121656d32a0401b2e79cec83c91a03e4cba)).

  Add the `KeychainIdentityNIOSSL` product.
  It presents such an identity in a SwiftNIO TLS handshake.

