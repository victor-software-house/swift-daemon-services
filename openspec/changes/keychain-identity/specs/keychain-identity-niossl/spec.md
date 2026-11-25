## ADDED Requirements

### Requirement: A SwiftNIO client presents the identity

`TLSConfiguration.clientConfiguration(presenting:)` SHALL set:

- the identity's chain
- a custom private key that signs with the identity's key, offering only `ecdsa_secp256r1_sha256`

#### Scenario: Mutual TLS in process

- **WHEN** a SwiftNIO client with this configuration connects over TLS 1.3 to a local SwiftNIO server
- **AND** the server requires a client certificate from the issuing test authority
- **THEN** the handshake completes
- **AND** the server reads the identity's leaf as the peer certificate

### Requirement: Signing never blocks the event loop

The custom key SHALL sign on its own serial queue and complete the handshake's promise on the channel's event loop.

#### Scenario: A slow signature

- **WHEN** the signature takes 50 ms
- **THEN** a timer on the same event loop still fires on time during the handshake
