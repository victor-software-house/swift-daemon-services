import Foundation
import Security
import Testing
import X509

@testable import KeychainIdentity

private let expected = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String

@Test func theProtectionIsAfterFirstUnlockOnThisDeviceOnly() {
    #expect(Protection.afterFirstUnlock as String == expected)
}

@Test func theLeafItemIsAccessibleAfterFirstUnlock() throws {
    let authority = try TestAuthority(commonName: "Test CA")
    let certificate = try #require(
        SecCertificateCreateWithData(nil, Data(TestPKI.der(authority.certificate)) as CFData)
    )
    let items = KeychainChainItems(accessGroup: "TEAMID1234.test", service: "test.chain", name: "client")
    let attributes = items.leafAttributes(certificate)
    #expect(attributes[kSecAttrAccessible as String] as? String == expected)
    #expect(attributes[kSecAttrLabel as String] as? String == "client")
    #expect(attributes[kSecAttrAccessGroup as String] as? String == "TEAMID1234.test")
}

@Test func theChainItemIsAccessibleAfterFirstUnlock() {
    let items = KeychainChainItems(accessGroup: "TEAMID1234.test", service: "test.chain", name: "client")
    let attributes = items.chainAttributes(Data("bundle".utf8))
    #expect(attributes[kSecAttrAccessible as String] as? String == expected)
    #expect(attributes[kSecAttrService as String] as? String == "test.chain")
    #expect(attributes[kSecAttrAccount as String] as? String == "client")
    #expect(attributes[kSecAttrAccessGroup as String] as? String == "TEAMID1234.test")
}

@Test func theKeyUsesTheProtectionThroughItsAccessControl() throws {
    let access = try IdentityStore.keyAccessControl()
    let attributes = IdentityStore.keyAttributes(name: "client", accessGroup: "TEAMID1234.test", access: access)
    let privateKey = try #require(attributes[kSecPrivateKeyAttrs as String] as? [String: Any])
    #expect(privateKey[kSecAttrAccessControl as String] != nil)
    #expect(privateKey[kSecAttrAccessible as String] == nil)
    #expect(privateKey[kSecAttrAccessGroup as String] as? String == "TEAMID1234.test")
    #expect(attributes[kSecAttrTokenID as String] as? String == kSecAttrTokenIDSecureEnclave as String)
}

@Test func theChainIsStoredAsPEMBlocksLeafFirst() throws {
    let root = try TestAuthority(commonName: "Test Root")
    let intermediate = try TestAuthority(commonName: "Test Intermediate", issuer: root)
    let leaf = try intermediate.issue(commonName: "client", publicKey: intermediate.signer.publicKey)
    let chain = try [leaf, intermediate.certificate, root.certificate].map { Data(try TestPKI.der($0)) }

    let bundle = ChainBundle.encode(chain)
    let text = String(decoding: bundle, as: UTF8.self)
    #expect(text.hasPrefix("-----BEGIN CERTIFICATE-----\n"))
    #expect(text.hasSuffix("-----END CERTIFICATE-----\n"))
    #expect(text.components(separatedBy: "-----BEGIN CERTIFICATE-----").count == 4)

    #expect(try ChainBundle.decode(bundle) == chain)
    let parsed = try ChainBundle.decode(bundle).map { try Certificate(derEncoded: Array($0)) }
    #expect(parsed == [leaf, intermediate.certificate, root.certificate])
}

@Test func anEmptyChainIsAnEmptyBundle() throws {
    #expect(ChainBundle.encode([]).isEmpty)
    #expect(try ChainBundle.decode(Data()).isEmpty)
}

@Test func aBundleOfAnotherKindOfBlockIsRefused() {
    let text = "-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n"
    #expect(throws: KeychainIdentityError.keychain(errSecDecode)) {
        try ChainBundle.decode(Data(text.utf8))
    }
}

@Test func textThatIsNotPEMIsRefused() {
    #expect(throws: KeychainIdentityError.keychain(errSecDecode)) {
        try ChainBundle.decode(Data("-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n".utf8))
    }
}
