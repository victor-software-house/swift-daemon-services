## ADDED Requirements

### Requirement: A store belongs to one team keychain group

`IdentityStore(groupSuffix:)` SHALL form the group `<team>.<suffix>` from the running code's signing team.
It SHALL fail with `notSigned` when the code has no team, and with `missingEntitlement` naming the group when the `keychain-access-groups` entitlement lacks it.

#### Scenario: An unsigned test binary

- **WHEN** an unsigned process creates a store
- **THEN** it fails with `notSigned`

### Requirement: An identity is a Secure Enclave key in the group

`create(name:)` SHALL make a Secure Enclave P-256 key that:

- lives in the data-protection keychain, in the store's group
- is accessible after first unlock on this device only
- needs no user presence

It SHALL fail with `alreadyExists` when the group has an identity of that name.

#### Scenario: Another app of the team signs

- **WHEN** app A creates the identity `client`
- **AND** app B of the same team and group reads it while the Mac is locked after its first unlock
- **THEN** B signs with it, and A's public key verifies B's signature

### Requirement: A signing request for the identity

`signingRequest(for:subject:)` SHALL return a Public-Key Cryptography Standards (PKCS) 10 request in Distinguished Encoding Rules (DER) and PEM that:

- is for the identity's public key
- carries the given subject
- is signed by the identity's key

#### Scenario: The request verifies

- **WHEN** a request is built for an identity
- **THEN** `swift-certificates` parses it, and its signature verifies with the identity's public key

### Requirement: The chain is stored so macOS forms a SecIdentity

`store(chain:for:)` SHALL fail with `keyMismatch` when the leaf's public key is not the identity's.
Otherwise it SHALL store the leaf as a certificate item and the whole chain as one keychain item, replacing the identity's previous ones, and `identity(named:)` SHALL then return the chain and a `SecIdentity`.
It SHALL fail, and leave the previous leaf and chain in place, when macOS forms no `SecIdentity`.

#### Scenario: A wrong leaf

- **WHEN** the leaf of a chain carries another key
- **THEN** `store` fails with `keyMismatch` and the stored chain stays as it was

#### Scenario: A renewed certificate

- **WHEN** a new chain is stored for an identity that has one
- **THEN** `identity(named:)` returns the new chain, and the old leaf item and the old chain are gone

### Requirement: Removal

`remove(name:)` SHALL delete the key, the leaf certificate item and the chain item of that identity, and fail with `notFound` when there is none.

#### Scenario: Remove, then read

- **WHEN** an identity is removed
- **THEN** `identity(named:)` returns nil
