import CryptoKit
import Foundation
import Security
import Testing
import X509

@testable import KeychainIdentity

private func makeIdentity() -> ClientIdentity {
    ClientIdentity(
        name: "client",
        chain: [],
        secIdentity: nil,
        signingKey: SoftwareSigningKey(signer: P256.Signing.PrivateKey())
    )
}

// The stand-in for the keychain: it records each operation, and the certificates are plain names.
private final class FakeItems: ChainItems {
    var stored: [Data]
    var operations: [String] = []
    var formsAnIdentity = true
    var failingAdd: Data?

    init(stored: [String]) {
        self.stored = stored.map { Data($0.utf8) }
    }

    func storedChain() throws -> [Data] {
        stored
    }

    func add(_ der: Data) throws {
        operations.append("add \(String(decoding: der, as: UTF8.self))")
        if der == failingAdd {
            throw KeychainIdentityError.keychain(errSecIO)
        }
        stored.append(der)
    }

    func remove(_ der: Data) throws {
        operations.append("remove \(String(decoding: der, as: UTF8.self))")
        stored.removeAll { $0 == der }
    }

    func formsIdentity(forLeaf der: Data) throws -> Bool {
        operations.append("identity \(String(decoding: der, as: UTF8.self))")
        return formsAnIdentity
    }

    var names: Set<String> {
        Set(stored.map { String(decoding: $0, as: UTF8.self) })
    }
}

private func data(_ names: String...) -> [Data] {
    names.map { Data($0.utf8) }
}

@Test func aLeafOfAnotherKeyIsAMismatch() throws {
    let authority = try TestAuthority(commonName: "Test CA")
    let identity = makeIdentity()
    let other = try authority.issue(commonName: "other", publicKey: P256.Signing.PrivateKey().publicKey)
    let store = IdentityStore(accessGroup: "TEAMID1234.test")
    #expect(throws: KeychainIdentityError.keyMismatch) {
        try store.store(chain: [other, authority.certificate], for: identity)
    }
}

@Test func anEmptyChainIsAMismatch() {
    let store = IdentityStore(accessGroup: "TEAMID1234.test")
    #expect(throws: KeychainIdentityError.keyMismatch) {
        try store.store(chain: [], for: makeIdentity())
    }
}

@Test func theLeafOfTheIdentityMatches() throws {
    let authority = try TestAuthority(commonName: "Test CA")
    let identity = makeIdentity()
    let leaf = try authority.issue(commonName: "client", publicKey: identity.publicKey)
    #expect(Chain.leafMatches([leaf, authority.certificate], publicKey: identity.publicKey))
    #expect(!Chain.leafMatches([authority.certificate, leaf], publicKey: identity.publicKey))
}

@Test func theChainIsOrderedFromTheLeafUp() throws {
    let root = try TestAuthority(commonName: "Test Root")
    let intermediate = try TestAuthority(commonName: "Test Intermediate", issuer: root)
    let identity = makeIdentity()
    let leaf = try intermediate.issue(commonName: "client", publicKey: identity.publicKey)
    let stray = try TestAuthority(commonName: "Stray")
    let ordered = Chain.ordered(
        [root.certificate, stray.certificate, leaf, intermediate.certificate],
        leafKey: identity.publicKey
    )
    #expect(ordered == [leaf, intermediate.certificate, root.certificate])
}

@Test func noLeafGivesNoChain() throws {
    let root = try TestAuthority(commonName: "Test Root")
    #expect(Chain.ordered([root.certificate], leafKey: makeIdentity().publicKey).isEmpty)
}

@Test func aRenewalAddsTheNewLeafAndDeletesTheOldOne() throws {
    let items = FakeItems(stored: ["old leaf", "intermediate"])
    try Chain.replace(in: items, with: data("new leaf", "intermediate"))
    #expect(items.operations == ["add new leaf", "identity new leaf", "remove old leaf"])
    #expect(items.names == ["new leaf", "intermediate"])
}

@Test func theFirstStoreOnlyAdds() throws {
    let items = FakeItems(stored: [])
    try Chain.replace(in: items, with: data("leaf", "intermediate"))
    #expect(items.operations == ["add leaf", "add intermediate", "identity leaf"])
    #expect(items.names == ["leaf", "intermediate"])
}

@Test func noIdentityLeavesTheStoredChainAsItWas() {
    let items = FakeItems(stored: ["old leaf", "intermediate"])
    items.formsAnIdentity = false
    #expect(throws: KeychainIdentityError.keychain(errSecItemNotFound)) {
        try Chain.replace(in: items, with: data("new leaf", "intermediate"))
    }
    #expect(items.names == ["old leaf", "intermediate"])
    #expect(items.operations == ["add new leaf", "identity new leaf", "remove new leaf"])
}

@Test func aFailedAddLeavesTheStoredChainAsItWas() {
    let items = FakeItems(stored: ["old leaf"])
    items.failingAdd = Data("second".utf8)
    #expect(throws: KeychainIdentityError.keychain(errSecIO)) {
        try Chain.replace(in: items, with: data("new leaf", "second"))
    }
    #expect(items.names == ["old leaf"])
}

@Test func anEmptyReplacementIsAMismatch() {
    let items = FakeItems(stored: ["old leaf"])
    #expect(throws: KeychainIdentityError.keyMismatch) {
        try Chain.replace(in: items, with: [])
    }
    #expect(items.names == ["old leaf"])
}

@Test func theChangeKeepsSharedCertificates() {
    let change = Chain.change(stored: data("a", "b"), new: data("c", "b"))
    #expect(change == Chain.Change(toAdd: data("c"), toDelete: data("a")))
}
