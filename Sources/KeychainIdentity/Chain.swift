import CryptoKit
import Foundation
import Security
import SwiftASN1
import X509

extension Certificate {
    // The certificate as encoded bytes.
    func derData() throws -> Data {
        var serializer = DER.Serializer()
        try serializer.serialize(self)
        return Data(serializer.serializedBytes)
    }
}

// The items of one identity besides its key, in the keychain or in a test double.
// A certificate item is the leaf. One more item keeps the whole chain in order.
protocol ChainItems {
    // The encoded bytes of every leaf certificate item of the identity.
    func leafCertificates() throws -> [Data]

    // Adds a leaf certificate item. Returns false when an identical one is already stored.
    func addLeaf(_ der: Data) throws -> Bool

    // Deletes a leaf certificate item.
    func removeLeaf(_ der: Data) throws

    // The stored chain, leaf first, or nil when none is stored.
    func storedChain() throws -> [Data]?

    // Stores the chain, replacing the one stored.
    func writeChain(_ chain: [Data]) throws

    // Deletes the stored chain.
    func removeChain() throws

    // Whether macOS forms an identity from the identity's key and this leaf.
    func formsIdentity(forLeaf der: Data) throws -> Bool
}

enum Chain {
    // Whether the leaf carries the identity's public key.
    static func leafMatches(_ chain: [Certificate], publicKey: P256.Signing.PublicKey) -> Bool {
        guard
            let leaf = chain.first,
            let leafKey = P256.Signing.PublicKey(leaf.publicKey)
        else {
            return false
        }
        return leafKey.x963Representation == publicKey.x963Representation
    }

    // Replaces the stored chain in four steps.
    // It adds the new leaf, writes the chain, and checks that macOS forms an identity.
    // Then it deletes the old leaf, so a reader finds a leaf at every step.
    // When a step fails, it deletes the new leaf and writes the old chain back.
    static func replace(in items: some ChainItems, with newChain: [Data]) throws {
        guard let leaf = newChain.first else {
            throw KeychainIdentityError.keyMismatch
        }
        let oldChain = try items.storedChain()
        let oldLeaves = try items.leafCertificates()
        var addedLeaf = false
        var wroteChain = false
        do {
            addedLeaf = try items.addLeaf(leaf)
            wroteChain = true
            try items.writeChain(newChain)
            guard try items.formsIdentity(forLeaf: leaf) else {
                throw KeychainIdentityError.keychain(errSecItemNotFound)
            }
        } catch {
            if wroteChain {
                if let oldChain {
                    _ = try? items.writeChain(oldChain)
                } else {
                    _ = try? items.removeChain()
                }
            }
            if addedLeaf {
                _ = try? items.removeLeaf(leaf)
            }
            throw error
        }
        for der in oldLeaves where der != leaf {
            try items.removeLeaf(der)
        }
    }
}

// An identity's items in the data-protection keychain.
// The leaf is a certificate item labelled with the identity's name.
// A generic password item of the service and the name keeps the chain.
struct KeychainChainItems: ChainItems {
    let accessGroup: String
    let service: String
    let name: String

    private var leafQuery: [String: Any] {
        [
            kSecClass as String: kSecClassCertificate,
            kSecAttrLabel as String: name,
            kSecAttrAccessGroup as String: accessGroup,
            kSecUseDataProtectionKeychain as String: true,
        ]
    }

    private var chainQuery: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: name,
            kSecAttrAccessGroup as String: accessGroup,
            kSecUseDataProtectionKeychain as String: true,
        ]
    }

    func leafCertificates() throws -> [Data] {
        var query = leafQuery
        query[kSecReturnRef as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitAll
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return []
        }
        guard status == errSecSuccess else {
            throw KeychainIdentityError.mapped(status)
        }
        guard let items = result as? [AnyObject] else {
            throw KeychainIdentityError.keychain(errSecDecode)
        }
        return try items.map { item in
            guard CFGetTypeID(item) == SecCertificateGetTypeID() else {
                throw KeychainIdentityError.keychain(errSecDecode)
            }
            return SecCertificateCopyData(unsafeDowncast(item, to: SecCertificate.self)) as Data
        }
    }

    func addLeaf(_ der: Data) throws -> Bool {
        var attributes = leafQuery
        attributes[kSecValueRef as String] = try Self.certificate(der)
        let status = SecItemAdd(attributes as CFDictionary, nil)
        if status == errSecSuccess {
            return true
        }
        guard status == errSecDuplicateItem, try leafCertificates().contains(der) else {
            throw KeychainIdentityError.mapped(status)
        }
        return false
    }

    func removeLeaf(_ der: Data) throws {
        var query = leafQuery
        query[kSecValueRef as String] = try Self.certificate(der)
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainIdentityError.mapped(status)
        }
    }

    func storedChain() throws -> [Data]? {
        var query = chainQuery
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess else {
            throw KeychainIdentityError.mapped(status)
        }
        guard let data = result as? Data, let chain = try? JSONDecoder().decode([Data].self, from: data) else {
            throw KeychainIdentityError.keychain(errSecDecode)
        }
        return chain
    }

    func writeChain(_ chain: [Data]) throws {
        let data = try JSONEncoder().encode(chain)
        var status = SecItemUpdate(chainQuery as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if status == errSecItemNotFound {
            var attributes = chainQuery
            attributes[kSecValueData as String] = data
            attributes[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            status = SecItemAdd(attributes as CFDictionary, nil)
        }
        guard status == errSecSuccess else {
            throw KeychainIdentityError.mapped(status)
        }
    }

    func removeChain() throws {
        let status = SecItemDelete(chainQuery as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainIdentityError.mapped(status)
        }
    }

    func formsIdentity(forLeaf der: Data) throws -> Bool {
        try secIdentity(forLeaf: der) != nil
    }

    // The identity of the group whose certificate is the given one.
    func secIdentity(forLeaf der: Data) throws -> SecIdentity? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassIdentity,
            kSecAttrAccessGroup as String: accessGroup,
            kSecUseDataProtectionKeychain as String: true,
            kSecReturnRef as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess else {
            throw KeychainIdentityError.mapped(status)
        }
        guard let items = result as? [AnyObject] else {
            throw KeychainIdentityError.keychain(errSecDecode)
        }
        for item in items {
            guard CFGetTypeID(item) == SecIdentityGetTypeID() else {
                throw KeychainIdentityError.keychain(errSecDecode)
            }
            let identity = unsafeDowncast(item, to: SecIdentity.self)
            var certificate: SecCertificate?
            let copyStatus = SecIdentityCopyCertificate(identity, &certificate)
            guard copyStatus == errSecSuccess, let certificate else {
                throw KeychainIdentityError.mapped(copyStatus)
            }
            if SecCertificateCopyData(certificate) as Data == der {
                return identity
            }
        }
        return nil
    }

    private static func certificate(_ der: Data) throws -> SecCertificate {
        guard let certificate = SecCertificateCreateWithData(nil, der as CFData) else {
            throw KeychainIdentityError.keychain(errSecDecode)
        }
        return certificate
    }
}
