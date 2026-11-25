import CryptoKit
import Foundation
import Security
import SwiftASN1
import Testing
import X509

@testable import KeychainIdentity

private func makeSoftwareSecKey() throws -> SecKey {
    let attributes: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256,
    ]
    var error: Unmanaged<CFError>?
    guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
        throw KeychainIdentityError.mapped(error, fallback: errSecParam)
    }
    return key
}

private func expectValidSignature(by key: some SigningKey) throws {
    let message = Data("a handshake transcript".utf8)
    let signature = try P256.Signing.ECDSASignature(derRepresentation: key.signature(for: message))
    #expect(key.publicKey.isValidSignature(signature, for: message))
    #expect(!key.publicKey.isValidSignature(signature, for: Data("another message".utf8)))
}

private func expectValidRequest(signedBy key: some SigningKey) throws {
    let subject = try DistinguishedName {
        CommonName("test client")
        OrganizationName("Test Organization")
    }
    let request = try IdentityStore.signingRequest(signedBy: key, subject: subject)

    let parsed = try CertificateSigningRequest(derEncoded: Array(request.der))
    #expect(parsed.subject == subject)
    #expect(parsed.publicKey == Certificate.PublicKey(key.publicKey))
    #expect(parsed.publicKey.isValidSignature(parsed.signature, for: parsed))

    #expect(request.pem.hasPrefix("-----BEGIN CERTIFICATE REQUEST-----"))
    let fromPEM = try CertificateSigningRequest(pemEncoded: request.pem)
    #expect(fromPEM.subject == subject)
    #expect(fromPEM.publicKey == parsed.publicKey)
}

@Test func theSoftwareKeySigns() throws {
    try expectValidSignature(by: SoftwareSigningKey(signer: P256.Signing.PrivateKey()))
}

@Test func theSecKeySigns() throws {
    try expectValidSignature(by: SecKeySigningKey(makeSoftwareSecKey()))
}

@Test func theSoftwareKeySignsARequestThatVerifies() throws {
    try expectValidRequest(signedBy: SoftwareSigningKey(signer: P256.Signing.PrivateKey()))
}

@Test func theSecKeySignsARequestThatVerifies() throws {
    try expectValidRequest(signedBy: SecKeySigningKey(makeSoftwareSecKey()))
}

@Test func anIdentitySignsWithItsKey() throws {
    let key = SoftwareSigningKey(signer: P256.Signing.PrivateKey())
    let identity = ClientIdentity(name: "client", chain: [], secIdentity: nil, signingKey: key)
    let message = Data("hello".utf8)
    let signature = try P256.Signing.ECDSASignature(derRepresentation: identity.sign(message))
    #expect(identity.publicKey.isValidSignature(signature, for: message))
}
