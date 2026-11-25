# Tasks

## 1. Repository

- [x] 1.1 Add `Package.swift` with the products `KeychainIdentity` and `KeychainIdentityNIOSSL`, their test targets, `.macOS(.v27)`, and the dependencies `swift-certificates` and `swift-nio-ssl` at their newest releases.
  Verify: CI's `swift:build` passes.
  - 2026-11-25 (UTC): `swift:build` passed on the hosted macOS runner, in [run 45623036475][run-3] of [PR 3][pr-3].
    The pins are swift-certificates 1.21.2, swift-nio-ssl 2.37.7, swift-nio 2.105.2 and swift-asn1 1.7.5.
- [x] 1.2 Turn on `ci`, `swift_tasks`, `swift_settings`, `swift_release`, `swift_format` and `swift_docs` with `template:on`, `swift_doc_targets` naming both products.
  Verify: `mise tasks deps check` lists the Swift tasks and `check:repo`.
  - 2026-11-25 (UTC): `mise tasks deps check` lists the Swift tasks and `check:repo`, run locally after `template:on`.
    The same tasks passed in [run 45623036475][run-3].

## 2. KeychainIdentity

- [x] 2.1 `IdentityStore`, the group from the team, and `KeychainIdentityError`.
  Verify: a test of an unsigned process gets `notSigned`.
  - 2026-11-25 (UTC): the test of an unsigned process gets `notSigned`, and it passed in [run 45623036475][run-3].
    The tests of the group and entitlement logic passed too.
    Not proven: a signed process with the entitlement.
- [x] 2.2 `create`, `identity(named:)`, `remove` and the internal `SigningKey` protocol, with the Secure Enclave and software keys.
  Verify: CI unit tests with the software key pass.
  - 2026-11-25 (UTC): the unit tests passed in [run 45623036475][run-3], with the software key and a software `SecKey`.
    Not proven: creating, reading and removing a keychain identity with a Secure Enclave key.
    That needs a signed app.
- [x] 2.3 `signingRequest(for:subject:)` and `store(chain:for:)` with the leaf check and the replace order.
  Verify: tests of the request's signature, a wrong leaf and a renewal pass.
  - 2026-11-25 (UTC): the tests of the request's signature, a wrong leaf and a renewal passed in [run 45623036475][run-3].
    The renewal runs against a fake item store.
    Not proven: the keychain writes and the `SecIdentity` read-back.

## 3. KeychainIdentityNIOSSL

- [x] 3.1 `KeychainIdentityPrivateKey` and `clientConfiguration(presenting:)`.
  Verify: the in-process mutual TLS test passes in CI.
  - 2026-11-25 (UTC): the in-process mutual TLS 1.3 test passed in [run 45623036475][run-3].
    The server read the client leaf as the peer certificate.
- [x] 3.2 Signing on the key's queue.
  Verify: the slow-signature test passes.
  - 2026-11-25 (UTC): the slow-signature test passed in [run 45623036475][run-3].
    A timer on the client's event loop fired at least five times during a 50 ms signature.

## 4. Probe

- [x] 4.1 `Probe/` with two apps and a shared group, built with XcodeGen.
  Verify: on a locked Mac, the second app signs 200 times with the first app's identity.
  Median, p95 and max go in a dated note.
  - 2026-11-25 UTC, probe at [`8f23988`][c8f23988] on an M-series Mac, screen locked, signer started by launchd.
    The maker stored a chain of 2 certificates, and the signing request verified.
    The signer read the chain, macOS formed the `SecIdentity`, and 200 signatures verified.
    Median 4.55 ms, p95 4.63 ms, max 6.54 ms.

## 5. Release

- [x] 5.1 A changeset fragment, the Version PR, and the 0.0.1 tag.
  Verify: the tag `v0.0.1` exists and `swift:api` passes on main.
  - 2026-11-25 UTC, [PR 5][pr-5] merged through the merge queue, and the release run published [v0.0.1][v0.0.1].
    `swift:api` passed in the merge-group run, with no earlier tag to compare against.

[pr-3]: https://github.com/victor-software-house/swift-daemon-services/pull/3
[run-3]: https://github.com/victor-software-house/swift-daemon-services/actions/runs/45623036475

[c8f23988]: https://github.com/victor-software-house/swift-daemon-services/commit/8f23988b5cdd53665f5543fd11558873aec19c59
[pr-5]: https://github.com/victor-software-house/swift-daemon-services/pull/5
[v0.0.1]: https://github.com/victor-software-house/swift-daemon-services/releases/tag/v0.0.1
