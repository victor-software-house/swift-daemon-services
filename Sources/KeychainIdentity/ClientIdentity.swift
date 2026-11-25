import CryptoKit
import Foundation
import Security
import X509

/// A TLS client identity: a Secure Enclave key in a team keychain group, with the certificate chain stored for it.
public struct ClientIdentity: @unchecked Sendable {
    /// The name the identity was created with.
    public let name: String

    /// The certificate chain of the identity, leaf first.
    ///
    /// The chain is empty until `IdentityStore/store(chain:for:)` stores one.
    public let chain: [Certificate]

    /// The identity macOS forms from the key and the leaf certificate, for URLSession and Network.framework.
    ///
    /// It is nil while the chain is empty.
    public let secIdentity: SecIdentity?

    let signingKey: any SigningKey

    /// The public half of the identity's key.
    public var publicKey: P256.Signing.PublicKey {
        signingKey.publicKey
    }

    /// Signs a message with the identity's key.
    ///
    /// - Parameter message: The bytes to sign. The key hashes them with SHA-256.
    /// - Returns: The signature in the X9.62 format that TLS and X.509 use.
    /// - Throws: `KeychainIdentityError/lockedSinceBoot` before the first unlock, or another `KeychainIdentityError`.
    public func sign(_ message: Data) throws -> Data {
        try signingKey.signature(for: message)
    }
}

/// A certificate signing request for an identity, to send to a certificate authority.
public struct SigningRequest: Equatable, Sendable {
    /// The request in Distinguished Encoding Rules.
    public let der: Data

    /// The request in PEM form.
    public let pem: String
}
