import CryptoKit
import Foundation
import KeychainIdentityNIOSSL
import NIOCore
import NIOPosix
import NIOSSL
import NIOTLS
import Testing
import X509

@testable import KeychainIdentity

// What one side read when its handshake completed.
struct HandshakeResult: Sendable {
    // The certificate of the peer, as encoded bytes.
    let peerCertificate: [UInt8]?
    let isTLS13: Bool
}

// Reports the result of a TLS handshake to a promise.
final class HandshakeProbe: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer

    private let promise: EventLoopPromise<HandshakeResult>

    init(promise: EventLoopPromise<HandshakeResult>) {
        self.promise = promise
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if let event = event as? TLSUserEvent, case .handshakeCompleted = event {
            do {
                let operations = context.pipeline.syncOperations
                let peer = try operations.nioSSL_peerCertificate()
                promise.succeed(
                    HandshakeResult(
                        peerCertificate: try peer?.toDERBytes(),
                        isTLS13: try operations.nioSSL_tlsVersion() == .tlsv13
                    )
                )
            } catch {
                promise.fail(error)
            }
        }
        context.fireUserInboundEventTriggered(event)
    }

    func errorCaught(context: ChannelHandlerContext, error: any Error) {
        promise.fail(error)
        context.close(promise: nil)
    }
}

// A client identity whose leaf a test authority issued, over a software key.
func makeClientIdentity(
    authority: TestAuthority,
    signingKey: some SigningKey
) throws -> ClientIdentity {
    let leaf = try authority.issue(
        commonName: "test client",
        publicKey: signingKey.publicKey,
        extensions: Certificate.Extensions {
            Critical(KeyUsage(digitalSignature: true))
            try ExtendedKeyUsage([.clientAuth])
        }
    )
    return ClientIdentity(name: "test client", chain: [leaf], secIdentity: nil, signingKey: signingKey)
}

// Runs a TLS 1.3 handshake of a client that presents the identity against a local server that requires
// a client certificate from the authority. Returns what the server and the client read.
func mutualHandshake(
    presenting identity: ClientIdentity,
    authority: TestAuthority,
    serverGroup: any EventLoopGroup,
    clientLoop: any EventLoop
) async throws -> (server: HandshakeResult, client: HandshakeResult) {
    let serverKey = P256.Signing.PrivateKey()
    let serverCertificate = try authority.issue(
        commonName: "localhost",
        publicKey: serverKey.publicKey,
        extensions: Certificate.Extensions {
            Critical(KeyUsage(digitalSignature: true))
            try ExtendedKeyUsage([.serverAuth])
            SubjectAlternativeNames([.dnsName("localhost")])
        }
    )
    let authorityCertificate = try NIOSSLCertificate(bytes: TestPKI.der(authority.certificate), format: .der)

    var serverConfiguration = TLSConfiguration.makeServerConfigurationWithMTLS(
        certificateChain: [.certificate(try NIOSSLCertificate(bytes: TestPKI.der(serverCertificate), format: .der))],
        privateKey: .privateKey(try NIOSSLPrivateKey(bytes: Array(serverKey.pemRepresentation.utf8), format: .pem)),
        trustRoots: .certificates([authorityCertificate])
    )
    serverConfiguration.minimumTLSVersion = .tlsv13
    let serverContext = try NIOSSLContext(configuration: serverConfiguration)

    var clientConfiguration = try TLSConfiguration.clientConfiguration(presenting: identity)
    clientConfiguration.trustRoots = .certificates([authorityCertificate])
    clientConfiguration.minimumTLSVersion = .tlsv13
    let clientContext = try NIOSSLContext(configuration: clientConfiguration)

    let serverResult = serverGroup.next().makePromise(of: HandshakeResult.self)
    let clientResult = clientLoop.makePromise(of: HandshakeResult.self)

    let server = try await ServerBootstrap(group: serverGroup)
        .childChannelInitializer { channel in
            channel.eventLoop.makeCompletedFuture {
                let operations = channel.pipeline.syncOperations
                try operations.addHandler(NIOSSLServerHandler(context: serverContext))
                try operations.addHandler(HandshakeProbe(promise: serverResult))
            }
        }
        .bind(host: "127.0.0.1", port: 0)
        .get()
    let port = try #require(server.localAddress?.port)

    let client = try await ClientBootstrap(group: clientLoop)
        .channelInitializer { channel in
            channel.eventLoop.makeCompletedFuture {
                let operations = channel.pipeline.syncOperations
                try operations.addHandler(NIOSSLClientHandler(context: clientContext, serverHostname: "localhost"))
                try operations.addHandler(HandshakeProbe(promise: clientResult))
            }
        }
        .connect(host: "127.0.0.1", port: port)
        .get()

    let results = try await (serverResult.futureResult.get(), clientResult.futureResult.get())
    try await client.close()
    try await server.close()
    return (results.0, results.1)
}
