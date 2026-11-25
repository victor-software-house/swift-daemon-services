import CryptoKit
import Foundation
import KeychainIdentity
import X509

// Creates the identity "probe" and writes its public key to a file.
// Then it stores a chain for the identity.
// A throwaway authority in memory issues the leaf.
@main
enum ProbeMaker {
    static func main() {
        let log = ProbeLog()
        do {
            try make(log: log)
            exit(0)
        } catch {
            log.write("failed: \(error)")
            exit(1)
        }
    }

    private static func make(log: ProbeLog) throws {
        let path = try probePublicKeyPath()
        let store = try IdentityStore(groupSuffix: ProbeConstants.groupSuffix)
        log.write("group \(store.accessGroup)")
        if try store.identity(named: ProbeConstants.identityName) != nil {
            try store.remove(name: ProbeConstants.identityName)
            log.write("removed the identity of an earlier run")
        }
        let identity = try store.create(name: ProbeConstants.identityName)
        let key = identity.publicKey.x963Representation.base64EncodedString()
        try key.write(toFile: path, atomically: true, encoding: .utf8)
        log.write("created \(ProbeConstants.identityName), public key written to \(path)")

        let subject = try DistinguishedName { CommonName("probe") }
        let request = try store.signingRequest(for: identity, subject: subject)
        let parsed = try CertificateSigningRequest(derEncoded: Array(request.der))
        guard parsed.publicKey.isValidSignature(parsed.signature, for: parsed) else {
            throw ProbeError(description: "the signing request does not verify")
        }
        log.write("the signing request verifies")

        let authorityKey = P256.Signing.PrivateKey()
        let authorityName = try DistinguishedName { CommonName("probe authority") }
        let now = Date()
        let authority = try Certificate(
            version: .v3,
            serialNumber: Certificate.SerialNumber(),
            publicKey: Certificate.PublicKey(authorityKey.publicKey),
            notValidBefore: now.addingTimeInterval(-3600),
            notValidAfter: now.addingTimeInterval(86400),
            issuer: authorityName,
            subject: authorityName,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: Certificate.Extensions {
                Critical(BasicConstraints.isCertificateAuthority(maxPathLength: nil))
                Critical(KeyUsage(keyCertSign: true))
            },
            issuerPrivateKey: Certificate.PrivateKey(authorityKey)
        )
        let leaf = try Certificate(
            version: .v3,
            serialNumber: Certificate.SerialNumber(),
            publicKey: parsed.publicKey,
            notValidBefore: now.addingTimeInterval(-3600),
            notValidAfter: now.addingTimeInterval(86400),
            issuer: authorityName,
            subject: parsed.subject,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: Certificate.Extensions {
                Critical(KeyUsage(digitalSignature: true))
                try ExtendedKeyUsage([.clientAuth])
            },
            issuerPrivateKey: Certificate.PrivateKey(authorityKey)
        )
        try store.store(chain: [leaf, authority], for: identity)
        log.write("stored a chain of 2 certificates")
    }
}
