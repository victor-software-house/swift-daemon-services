import Dispatch
import Foundation
import KeychainIdentity
import NIOCore
import NIOSSL
import Security
import SwiftASN1
import X509

/// A TLS private key that signs with the key of a `ClientIdentity`.
///
/// The key offers only `ecdsa_secp256r1_sha256`. It signs on a serial queue of its own and completes
/// the handshake's promise on the channel's event loop, so a slow signature never stalls other connections.
public final class KeychainIdentityPrivateKey: NIOSSLCustomPrivateKey, Hashable, Sendable {
    private let identity: ClientIdentity
    private let queue = DispatchQueue(label: "KeychainIdentityPrivateKey")

    /// Makes a TLS key that signs with the key of an identity.
    ///
    /// - Parameter identity: The identity whose key signs the handshake.
    public init(identity: ClientIdentity) {
        self.identity = identity
    }

    /// The one signature algorithm the key offers: ECDSA over P-256 with SHA-256.
    public var signatureAlgorithms: [SignatureAlgorithm] {
        [.ecdsaSecp256R1Sha256]
    }

    /// Signs handshake data on the key's queue.
    ///
    /// - Parameters:
    ///   - channel: The channel that handshakes.
    ///   - algorithm: The signature algorithm the handshake chose.
    ///   - data: The data to sign. The key hashes it with SHA-256.
    /// - Returns: A future with the DER signature, completed on the channel's event loop.
    public func sign(
        channel: any Channel,
        algorithm: SignatureAlgorithm,
        data: ByteBuffer
    ) -> EventLoopFuture<ByteBuffer> {
        let eventLoop = channel.eventLoop
        guard algorithm == .ecdsaSecp256R1Sha256 else {
            return eventLoop.makeFailedFuture(KeychainIdentityError.keychain(errSecParam))
        }
        let promise = eventLoop.makePromise(of: ByteBuffer.self)
        let message = Data(data.readableBytesView)
        let identity = identity
        queue.async {
            let result = Result { try ByteBuffer(bytes: identity.sign(message)) }
            eventLoop.execute {
                promise.completeWith(result)
            }
        }
        return promise.futureResult
    }

    /// Fails: an ECDSA key never decrypts.
    ///
    /// - Parameters:
    ///   - channel: The channel that handshakes.
    ///   - data: The data to decrypt.
    /// - Returns: A failed future.
    public func decrypt(channel: any Channel, data: ByteBuffer) -> EventLoopFuture<ByteBuffer> {
        channel.eventLoop.makeFailedFuture(KeychainIdentityError.keychain(errSecParam))
    }

    /// Whether both are the same key object.
    ///
    /// - Parameters:
    ///   - lhs: The first key.
    ///   - rhs: The second key.
    /// - Returns: True when the two are one object.
    public static func == (lhs: KeychainIdentityPrivateKey, rhs: KeychainIdentityPrivateKey) -> Bool {
        lhs === rhs
    }

    /// Hashes the key object's identity.
    ///
    /// - Parameter hasher: The hasher to feed.
    public func hash(into hasher: inout Hasher) {
        hasher.combine(ObjectIdentifier(self))
    }
}

extension TLSConfiguration {
    /// A client configuration that presents an identity's certificate chain and signs with its key.
    ///
    /// - Parameter identity: The identity to present. Its chain must hold at least its leaf.
    /// - Returns: A client configuration; the caller sets trust roots and anything else it needs.
    /// - Throws: `KeychainIdentityError.notFound(name:)` when the identity has no chain stored,
    ///   or the error of NIOSSL when it cannot read a certificate.
    public static func clientConfiguration(presenting identity: ClientIdentity) throws -> TLSConfiguration {
        guard !identity.chain.isEmpty else {
            throw KeychainIdentityError.notFound(name: identity.name)
        }
        var configuration = TLSConfiguration.makeClientConfiguration()
        configuration.certificateChain = try identity.chain.map { certificate in
            var serializer = DER.Serializer()
            try serializer.serialize(certificate)
            return .certificate(try NIOSSLCertificate(bytes: serializer.serializedBytes, format: .der))
        }
        configuration.privateKey = .privateKey(
            NIOSSLPrivateKey(customPrivateKey: KeychainIdentityPrivateKey(identity: identity))
        )
        return configuration
    }
}
