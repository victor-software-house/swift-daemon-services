import CryptoKit
import Foundation
import Security
import X509

// A P-256 key that signs messages with ECDSA over SHA-256.
// The Secure Enclave key is the product's implementation; the software key is for tests.
protocol SigningKey: Sendable {
    // The key's public half.
    var publicKey: P256.Signing.PublicKey { get }

    // The signature of the message as X9.62 DER, the form TLS and X.509 carry.
    func signature(for message: Data) throws -> Data

    // The key for swift-certificates, which signs requests and certificates with it.
    func certificatePrivateKey() throws -> Certificate.PrivateKey
}

// A P-256 SecKey, a Secure Enclave key in the product and a software key in tests.
struct SecKeySigningKey: SigningKey, @unchecked Sendable {
    let key: SecKey
    let publicKey: P256.Signing.PublicKey

    init(_ key: SecKey) throws {
        var error: Unmanaged<CFError>?
        guard
            let publicSecKey = SecKeyCopyPublicKey(key),
            let external = SecKeyCopyExternalRepresentation(publicSecKey, &error) as Data?
        else {
            throw KeychainIdentityError.mapped(error, fallback: errSecParam)
        }
        do {
            self.publicKey = try P256.Signing.PublicKey(x963Representation: external)
        } catch {
            throw KeychainIdentityError.keychain(errSecDecode)
        }
        self.key = key
    }

    func signature(for message: Data) throws -> Data {
        var error: Unmanaged<CFError>?
        guard
            let signature = SecKeyCreateSignature(
                key,
                .ecdsaSignatureMessageX962SHA256,
                message as CFData,
                &error
            ) as Data?
        else {
            throw KeychainIdentityError.mapped(error, fallback: errSecInternalComponent)
        }
        return signature
    }

    func certificatePrivateKey() throws -> Certificate.PrivateKey {
        try Certificate.PrivateKey(key)
    }
}

// A CryptoKit P-256 key in memory, used only by tests.
struct SoftwareSigningKey: SigningKey {
    let signer: P256.Signing.PrivateKey

    var publicKey: P256.Signing.PublicKey {
        signer.publicKey
    }

    func signature(for message: Data) throws -> Data {
        try signer.signature(for: message).derRepresentation
    }

    func certificatePrivateKey() throws -> Certificate.PrivateKey {
        Certificate.PrivateKey(signer)
    }
}
