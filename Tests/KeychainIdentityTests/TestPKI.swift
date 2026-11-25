import CryptoKit
import Foundation
import SwiftASN1
import X509

// A test authority.
struct TestAuthority {
    let signer: P256.Signing.PrivateKey
    let name: DistinguishedName
    let certificate: Certificate

    // A self-signed authority, or one with an issuer.
    init(commonName: String, issuer: TestAuthority? = nil) throws {
        let signer = P256.Signing.PrivateKey()
        let name = try DistinguishedName { CommonName(commonName) }
        self.signer = signer
        self.name = name
        self.certificate = try TestPKI.certificate(
            subject: name,
            publicKey: signer.publicKey,
            issuer: issuer?.name ?? name,
            issuerKey: issuer?.signer ?? signer,
            extensions: Certificate.Extensions {
                Critical(BasicConstraints.isCertificateAuthority(maxPathLength: nil))
                Critical(KeyUsage(keyCertSign: true))
            }
        )
    }

    // A certificate for a key.
    func issue(commonName: String, publicKey: P256.Signing.PublicKey) throws -> Certificate {
        try TestPKI.certificate(
            subject: DistinguishedName { CommonName(commonName) },
            publicKey: publicKey,
            issuer: name,
            issuerKey: signer,
            extensions: Certificate.Extensions {
                Critical(KeyUsage(digitalSignature: true))
                try ExtendedKeyUsage([.clientAuth])
            }
        )
    }
}

enum TestPKI {
    static func certificate(
        subject: DistinguishedName,
        publicKey: P256.Signing.PublicKey,
        issuer: DistinguishedName,
        issuerKey: P256.Signing.PrivateKey,
        extensions: Certificate.Extensions
    ) throws -> Certificate {
        let now = Date()
        return try Certificate(
            version: .v3,
            serialNumber: Certificate.SerialNumber(),
            publicKey: Certificate.PublicKey(publicKey),
            notValidBefore: now.addingTimeInterval(-3600),
            notValidAfter: now.addingTimeInterval(3600),
            issuer: issuer,
            subject: subject,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: extensions,
            issuerPrivateKey: Certificate.PrivateKey(issuerKey)
        )
    }

    static func der(_ certificate: Certificate) throws -> [UInt8] {
        var serializer = DER.Serializer()
        try serializer.serialize(certificate)
        return serializer.serializedBytes
    }
}
