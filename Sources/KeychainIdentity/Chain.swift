import CryptoKit
import Foundation
import Security
import SwiftASN1
import X509

extension Certificate {
    // The certificate in DER form.
    func derData() throws -> Data {
        var serializer = DER.Serializer()
        try serializer.serialize(self)
        return Data(serializer.serializedBytes)
    }
}

// The certificate items of one identity, as the keychain or a test double holds them.
protocol ChainItems {
    // The DER of every stored certificate of the identity.
    func storedChain() throws -> [Data]

    // Adds a certificate. A certificate that is already stored is not an error.
    func add(_ der: Data) throws

    // Deletes a certificate.
    func remove(_ der: Data) throws

    // Whether macOS forms an identity from the identity's key and this certificate.
    func formsIdentity(forLeaf der: Data) throws -> Bool
}

enum Chain {
    // What a store changes: the certificates to add and the old ones to delete.
    struct Change: Equatable {
        let toAdd: [Data]
        let toDelete: [Data]
    }

    static func change(stored: [Data], new: [Data]) -> Change {
        let storedSet = Set(stored)
        let newSet = Set(new)
        return Change(
            toAdd: new.filter { !storedSet.contains($0) },
            toDelete: stored.filter { !newSet.contains($0) }
        )
    }

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

    // Replaces the stored chain: adds the new certificates, checks that macOS forms an identity
    // from the new leaf, then deletes the old certificates. A reader finds a chain at every step.
    // When an add fails or no identity forms, the certificates this call added are deleted again.
    static func replace(in items: some ChainItems, with newChain: [Data]) throws {
        guard let leaf = newChain.first else {
            throw KeychainIdentityError.keyMismatch
        }
        let plan = change(stored: try items.storedChain(), new: newChain)
        var added: [Data] = []
        do {
            for der in plan.toAdd {
                try items.add(der)
                added.append(der)
            }
            guard try items.formsIdentity(forLeaf: leaf) else {
                throw KeychainIdentityError.keychain(errSecItemNotFound)
            }
        } catch {
            for der in added {
                _ = try? items.remove(der)
            }
            throw error
        }
        for der in plan.toDelete {
            try items.remove(der)
        }
    }

    // The chain from the leaf up: the certificate that carries the key, then the issuer of each,
    // as far as the stored certificates reach. Certificates that no chain step reaches are left out.
    static func ordered(_ certificates: [Certificate], leafKey: P256.Signing.PublicKey) -> [Certificate] {
        guard let leaf = certificates.first(where: { leafMatches([$0], publicKey: leafKey) }) else {
            return []
        }
        var chain = [leaf]
        var rest = certificates.filter { $0 != leaf }
        while let current = chain.last, current.issuer != current.subject,
            let index = rest.firstIndex(where: { $0.subject == current.issuer })
        {
            chain.append(rest.remove(at: index))
        }
        return chain
    }
}

// The certificate items of an identity in the data-protection keychain, found by the identity's name.
struct KeychainChainItems: ChainItems {
    let accessGroup: String
    let name: String

    private var certificateQuery: [String: Any] {
        [
            kSecClass as String: kSecClassCertificate,
            kSecAttrLabel as String: name,
            kSecAttrAccessGroup as String: accessGroup,
            kSecUseDataProtectionKeychain as String: true,
        ]
    }

    func storedChain() throws -> [Data] {
        var query = certificateQuery
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
        return try Self.certificates(in: result).map { SecCertificateCopyData($0) as Data }
    }

    func add(_ der: Data) throws {
        var attributes = certificateQuery
        attributes[kSecValueRef as String] = try Self.certificate(der)
        let status = SecItemAdd(attributes as CFDictionary, nil)
        guard status == errSecSuccess || status == errSecDuplicateItem else {
            throw KeychainIdentityError.mapped(status)
        }
    }

    func remove(_ der: Data) throws {
        var query = certificateQuery
        query[kSecValueRef as String] = try Self.certificate(der)
        let status = SecItemDelete(query as CFDictionary)
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

    private static func certificates(in result: CFTypeRef?) throws -> [SecCertificate] {
        guard let items = result as? [AnyObject] else {
            throw KeychainIdentityError.keychain(errSecDecode)
        }
        return try items.map { item in
            guard CFGetTypeID(item) == SecCertificateGetTypeID() else {
                throw KeychainIdentityError.keychain(errSecDecode)
            }
            return unsafeDowncast(item, to: SecCertificate.self)
        }
    }
}
