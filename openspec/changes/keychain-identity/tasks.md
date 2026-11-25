# Tasks

## 1. Repository

- [ ] 1.1 Add `Package.swift` with the products `KeychainIdentity` and `KeychainIdentityNIOSSL`, their test targets, `.macOS(.v27)`, and the dependencies `swift-certificates` and `swift-nio-ssl` at their newest releases.
  Verify: CI's `swift:build` passes.
- [ ] 1.2 Turn on `ci`, `swift_tasks`, `swift_settings`, `swift_release`, `swift_format` and `swift_docs` with `template:on`, `swift_doc_targets` naming both products.
  Verify: `mise tasks deps check` lists the Swift tasks and `check:repo`.

## 2. KeychainIdentity

- [ ] 2.1 `IdentityStore`, the group from the team, and `KeychainIdentityError`.
  Verify: a test of an unsigned process gets `notSigned`.
- [ ] 2.2 `create`, `identity(named:)`, `remove` and the internal `SigningKey` protocol, with the Secure Enclave and software keys.
  Verify: CI unit tests with the software key pass.
- [ ] 2.3 `signingRequest(for:subject:)` and `store(chain:for:)` with the leaf check and the replace order.
  Verify: tests of the request's signature, a wrong leaf and a renewal pass.

## 3. KeychainIdentityNIOSSL

- [ ] 3.1 `KeychainIdentityPrivateKey` and `clientConfiguration(presenting:)`.
  Verify: the in-process mutual TLS test passes in CI.
- [ ] 3.2 Signing on the key's queue.
  Verify: the slow-signature test passes.

## 4. Probe

- [ ] 4.1 `Probe/` with two apps and a shared group, built with XcodeGen.
  Verify: on a locked Mac, the second app signs 200 times with the first app's identity.
  Median, p95 and max go in a dated note.

## 5. Release

- [ ] 5.1 A changeset fragment, the Version PR, and the 0.0.1 tag.
  Verify: the tag `v0.0.1` exists and `swift:api` passes on main.
