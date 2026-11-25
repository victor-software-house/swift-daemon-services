import CryptoKit
import Foundation
import Security
import SwiftASN1
import X509

/// The identities of one team keychain group.
///
/// The group is the running code's signing team and a suffix, such as `TEAMID.com.example.identity`.
/// Every app of the team whose `keychain-access-groups` entitlement lists the group reaches the same identities.
public struct IdentityStore: Sendable {
    /// The keychain access group of the store.
    public let accessGroup: String

    // The service of the generic password item that keeps an identity's chain.
    private let chainService: String

    /// Opens the store of a group suffix.
    ///
    /// - Parameter groupSuffix: The part of the group after the team identifier.
    /// - Throws: `KeychainIdentityError/notSigned` when the running code has no signing team, and
    ///   `KeychainIdentityError/missingEntitlement(group:)` when its entitlement does not list the group.
    public init(groupSuffix: String) throws {
        self.accessGroup = try RunningCode.accessGroup(
            team: RunningCode.teamIdentifier(),
            suffix: groupSuffix,
            entitled: RunningCode.keychainAccessGroups()
        )
        self.chainService = "\(groupSuffix).chain"
    }

    // A store of a group that has not been checked against the running code.
    init(accessGroup: String, groupSuffix: String) {
        self.accessGroup = accessGroup
        self.chainService = "\(groupSuffix).chain"
    }

    /// Creates an identity: a Secure Enclave P-256 key in the group.
    ///
    /// The key needs no user presence and is usable while the Mac is locked after its first unlock.
    /// It never leaves this Mac.
    ///
    /// - Parameter name: The name of the identity, unique in the group.
    /// - Returns: The identity, with no chain yet.
    /// - Throws: `KeychainIdentityError/alreadyExists(name:)` when the group has an identity of that name,
    ///   or another `KeychainIdentityError`.
    public func create(name: String) throws -> ClientIdentity {
        if try readKey(named: name) != nil {
            throw KeychainIdentityError.alreadyExists(name: name)
        }
        var error: Unmanaged<CFError>?
        guard
            let access = SecAccessControlCreateWithFlags(
                nil,
                kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                .privateKeyUsage,
                &error
            )
        else {
            throw KeychainIdentityError.mapped(error, fallback: errSecParam)
        }
        let privateKeyAttributes: [String: Any] = [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: Data(name.utf8),
            kSecAttrLabel as String: name,
            kSecAttrAccessControl as String: access,
            kSecAttrAccessGroup as String: accessGroup,
        ]
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecUseDataProtectionKeychain as String: true,
            kSecPrivateKeyAttrs as String: privateKeyAttributes,
        ]
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            let mapped = KeychainIdentityError.mapped(error, fallback: errSecInternalComponent)
            throw mapped == .keychain(errSecDuplicateItem) ? KeychainIdentityError.alreadyExists(name: name) : mapped
        }
        return ClientIdentity(
            name: name,
            chain: [],
            secIdentity: nil,
            signingKey: try SecKeySigningKey(key)
        )
    }

    /// Reads an identity.
    ///
    /// - Parameter name: The name the identity was created with.
    /// - Returns: The identity with its stored chain and the `SecIdentity` macOS forms from it,
    ///   or nil when the group has no key of that name.
    /// - Throws: `KeychainIdentityError/lockedSinceBoot` before the first unlock,
    ///   or another `KeychainIdentityError`.
    public func identity(named name: String) throws -> ClientIdentity? {
        guard let key = try readKey(named: name) else {
            return nil
        }
        let signingKey = try SecKeySigningKey(key)
        let items = chainItems(named: name)
        let chain = try items.storedChain()?.map { try Certificate(derEncoded: Array($0)) } ?? []
        guard chain.isEmpty || Chain.leafMatches(chain, publicKey: signingKey.publicKey) else {
            throw KeychainIdentityError.keyMismatch
        }
        let secIdentity = try chain.first.flatMap { try items.secIdentity(forLeaf: $0.derData()) }
        return ClientIdentity(name: name, chain: chain, secIdentity: secIdentity, signingKey: signingKey)
    }

    /// Removes an identity: its key, its leaf certificate and its stored chain.
    ///
    /// - Parameter name: The name of the identity.
    /// - Throws: `KeychainIdentityError/notFound(name:)` when there is nothing to remove,
    ///   or another `KeychainIdentityError`.
    public func remove(name: String) throws {
        let keyStatus = SecItemDelete(keyQuery(named: name) as CFDictionary)
        let leafQuery: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecAttrLabel as String: name,
            kSecAttrAccessGroup as String: accessGroup,
            kSecUseDataProtectionKeychain as String: true,
        ]
        let chainQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: chainService,
            kSecAttrAccount as String: name,
            kSecAttrAccessGroup as String: accessGroup,
            kSecUseDataProtectionKeychain as String: true,
        ]
        let statuses = [
            keyStatus,
            SecItemDelete(leafQuery as CFDictionary),
            SecItemDelete(chainQuery as CFDictionary),
        ]
        for status in statuses where status != errSecSuccess && status != errSecItemNotFound {
            throw KeychainIdentityError.mapped(status)
        }
        if statuses.allSatisfy({ $0 == errSecItemNotFound }) {
            throw KeychainIdentityError.notFound(name: name)
        }
    }

    /// Builds a PKCS 10 certificate signing request for an identity, signed by its key.
    ///
    /// The request carries the subject and no attribute the caller did not give.
    ///
    /// - Parameters:
    ///   - identity: The identity whose public key the request is for.
    ///   - subject: The subject of the future certificate.
    /// - Returns: The request in DER and PEM form.
    /// - Throws: `KeychainIdentityError`, or the error of swift-certificates when it cannot build the request.
    public func signingRequest(for identity: ClientIdentity, subject: DistinguishedName) throws -> SigningRequest {
        try Self.signingRequest(signedBy: identity.signingKey, subject: subject)
    }

    /// Stores the certificate chain of an identity, replacing the one it had.
    ///
    /// The leaf is a certificate item that macOS pairs with the key, and the whole chain is one keychain item.
    /// The new leaf and chain are written first and the old leaf deleted after, so a reader always finds a leaf.
    /// The call fails, and puts the old chain back, when macOS forms no `SecIdentity` from the key and the new leaf.
    ///
    /// - Parameters:
    ///   - chain: The certificates, leaf first.
    ///   - identity: The identity the chain belongs to.
    /// - Throws: `KeychainIdentityError/keyMismatch` when the leaf does not carry the identity's public key,
    ///   in which case the stored chain stays as it was, or another `KeychainIdentityError`.
    public func store(chain: [Certificate], for identity: ClientIdentity) throws {
        guard Chain.leafMatches(chain, publicKey: identity.publicKey) else {
            throw KeychainIdentityError.keyMismatch
        }
        try Chain.replace(in: chainItems(named: identity.name), with: chain.map { try $0.derData() })
    }

    static func signingRequest(signedBy key: any SigningKey, subject: DistinguishedName) throws -> SigningRequest {
        let request = try CertificateSigningRequest(
            version: .v1,
            subject: subject,
            privateKey: key.certificatePrivateKey(),
            attributes: CertificateSigningRequest.Attributes()
        )
        var serializer = DER.Serializer()
        try serializer.serialize(request)
        return SigningRequest(
            der: Data(serializer.serializedBytes),
            pem: try request.serializeAsPEM().pemString
        )
    }

    private func chainItems(named name: String) -> KeychainChainItems {
        KeychainChainItems(accessGroup: accessGroup, service: chainService, name: name)
    }

    private func keyQuery(named name: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrApplicationTag as String: Data(name.utf8),
            kSecAttrAccessGroup as String: accessGroup,
            kSecUseDataProtectionKeychain as String: true,
        ]
    }

    private func readKey(named name: String) throws -> SecKey? {
        var query = keyQuery(named: name)
        query[kSecReturnRef as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess else {
            throw KeychainIdentityError.mapped(status)
        }
        guard let result, CFGetTypeID(result) == SecKeyGetTypeID() else {
            throw KeychainIdentityError.keychain(errSecDecode)
        }
        return unsafeDowncast(result, to: SecKey.self)
    }
}
