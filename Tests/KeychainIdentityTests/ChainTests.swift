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

private func name(_ der: Data) -> String {
    String(decoding: der, as: UTF8.self)
}

private func data(_ names: String...) -> [Data] {
    names.map { Data($0.utf8) }
}

// The stand-in for the keychain: it records each operation, and the certificates are plain names.
private final class FakeItems: ChainItems {
    var leaves: [Data]
    var chain: [Data]?
    var operations: [String] = []
    var formsAnIdentity = true
    var failingChain: [Data]?

    init(leaves: [String], chain: [String]?) {
        self.leaves = leaves.map { Data($0.utf8) }
        self.chain = chain?.map { Data($0.utf8) }
    }

    func leafCertificates() throws -> [Data] {
        leaves
    }

    func addLeaf(_ der: Data) throws -> Bool {
        operations.append("add \(name(der))")
        if leaves.contains(der) {
            return false
        }
        leaves.append(der)
        return true
    }

    func removeLeaf(_ der: Data) throws {
        operations.append("remove \(name(der))")
        leaves.removeAll { $0 == der }
    }

    func storedChain() throws -> [Data]? {
        chain
    }

    func writeChain(_ chain: [Data]) throws {
        operations.append("write \(chain.map(name).joined(separator: ","))")
        if chain == failingChain {
            throw KeychainIdentityError.keychain(errSecIO)
        }
        self.chain = chain
    }

    func removeChain() throws {
        operations.append("remove chain")
        chain = nil
    }

    func formsIdentity(forLeaf der: Data) throws -> Bool {
        operations.append("identity \(name(der))")
        return formsAnIdentity
    }
}

@Test func aLeafOfAnotherKeyIsAMismatch() throws {
    let authority = try TestAuthority(commonName: "Test CA")
    let identity = makeIdentity()
    let other = try authority.issue(commonName: "other", publicKey: P256.Signing.PrivateKey().publicKey)
    let store = IdentityStore(accessGroup: "TEAMID1234.test", groupSuffix: "test")
    #expect(throws: KeychainIdentityError.keyMismatch) {
        try store.store(chain: [other, authority.certificate], for: identity)
    }
}

@Test func anEmptyChainIsAMismatch() {
    let store = IdentityStore(accessGroup: "TEAMID1234.test", groupSuffix: "test")
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

@Test func aRenewalWritesTheNewLeafAndChainThenDeletesTheOldLeaf() throws {
    let items = FakeItems(leaves: ["old leaf"], chain: ["old leaf", "intermediate"])
    try Chain.replace(in: items, with: data("new leaf", "intermediate"))
    #expect(
        items.operations == [
            "add new leaf", "write new leaf,intermediate", "identity new leaf", "remove old leaf",
        ]
    )
    #expect(items.leaves == data("new leaf"))
    #expect(items.chain == data("new leaf", "intermediate"))
}

@Test func theFirstStoreDeletesNothing() throws {
    let items = FakeItems(leaves: [], chain: nil)
    try Chain.replace(in: items, with: data("leaf", "intermediate"))
    #expect(items.operations == ["add leaf", "write leaf,intermediate", "identity leaf"])
    #expect(items.leaves == data("leaf"))
}

@Test func theSameLeafStaysWhenOnlyTheChainChanges() throws {
    let items = FakeItems(leaves: ["leaf"], chain: ["leaf"])
    try Chain.replace(in: items, with: data("leaf", "intermediate"))
    #expect(items.operations == ["add leaf", "write leaf,intermediate", "identity leaf"])
    #expect(items.leaves == data("leaf"))
    #expect(items.chain == data("leaf", "intermediate"))
}

@Test func noIdentityLeavesTheOldLeafAndChainAsTheyWere() {
    let items = FakeItems(leaves: ["old leaf"], chain: ["old leaf", "intermediate"])
    items.formsAnIdentity = false
    #expect(throws: KeychainIdentityError.keychain(errSecItemNotFound)) {
        try Chain.replace(in: items, with: data("new leaf", "intermediate"))
    }
    #expect(items.leaves == data("old leaf"))
    #expect(items.chain == data("old leaf", "intermediate"))
}

@Test func noIdentityOnAFirstStoreLeavesNothing() {
    let items = FakeItems(leaves: [], chain: nil)
    items.formsAnIdentity = false
    #expect(throws: KeychainIdentityError.keychain(errSecItemNotFound)) {
        try Chain.replace(in: items, with: data("leaf"))
    }
    #expect(items.leaves.isEmpty)
    #expect(items.chain == nil)
}

@Test func aFailedChainWriteLeavesTheOldLeafAndChainAsTheyWere() {
    let items = FakeItems(leaves: ["old leaf"], chain: ["old leaf"])
    items.failingChain = data("new leaf", "second")
    #expect(throws: KeychainIdentityError.keychain(errSecIO)) {
        try Chain.replace(in: items, with: data("new leaf", "second"))
    }
    #expect(items.leaves == data("old leaf"))
    #expect(items.chain == data("old leaf"))
}

@Test func anEmptyReplacementIsAMismatch() {
    let items = FakeItems(leaves: ["old leaf"], chain: ["old leaf"])
    #expect(throws: KeychainIdentityError.keyMismatch) {
        try Chain.replace(in: items, with: [])
    }
    #expect(items.leaves == data("old leaf"))
    #expect(items.operations.isEmpty)
}
