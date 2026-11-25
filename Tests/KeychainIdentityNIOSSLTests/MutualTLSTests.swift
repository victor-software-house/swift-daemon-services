import CryptoKit
import Foundation
import NIOConcurrencyHelpers
import NIOCore
import NIOPosix
import NIOSSL
import Testing
import X509

@testable import KeychainIdentity

// A software key that takes a fixed time to sign and notes when it started and finished.
private struct SlowSigningKey: SigningKey {
    let base: SoftwareSigningKey
    let duration: TimeInterval
    let started: NIOLockedValueBox<UInt64>
    let finished: NIOLockedValueBox<UInt64>

    var publicKey: P256.Signing.PublicKey {
        base.publicKey
    }

    func signature(for message: Data) throws -> Data {
        started.withLockedValue { $0 = DispatchTime.now().uptimeNanoseconds }
        Thread.sleep(forTimeInterval: duration)
        let signature = try base.signature(for: message)
        finished.withLockedValue { $0 = DispatchTime.now().uptimeNanoseconds }
        return signature
    }

    func certificatePrivateKey() throws -> Certificate.PrivateKey {
        try base.certificatePrivateKey()
    }
}

@Test(.timeLimit(.minutes(1)))
func theServerReadsTheClientLeafInATLS13Handshake() async throws {
    let authority = try TestAuthority(commonName: "Test CA")
    let identity = try makeClientIdentity(
        authority: authority,
        signingKey: SoftwareSigningKey(signer: P256.Signing.PrivateKey())
    )
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 2)
    let result = try await mutualHandshake(
        presenting: identity,
        authority: authority,
        serverGroup: group,
        clientLoop: group.next()
    )
    try await group.shutdownGracefully()

    let leaf = try TestPKI.der(#require(identity.chain.first))
    #expect(result.server.peerCertificate == leaf)
    #expect(result.server.isTLS13)
    #expect(result.client.isTLS13)
}

@Test(.timeLimit(.minutes(1)))
func aSlowSignatureDoesNotStallTheEventLoop() async throws {
    let authority = try TestAuthority(commonName: "Test CA")
    let started = NIOLockedValueBox<UInt64>(0)
    let finished = NIOLockedValueBox<UInt64>(0)
    let key = SlowSigningKey(
        base: SoftwareSigningKey(signer: P256.Signing.PrivateKey()),
        duration: 0.05,
        started: started,
        finished: finished
    )
    let identity = try makeClientIdentity(authority: authority, signingKey: key)
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 2)
    let clientLoop = group.next()

    // A task that repeats on the client's event loop for as long as the handshake runs.
    let ticks = NIOLockedValueBox<[UInt64]>([])
    let timer = clientLoop.scheduleRepeatedTask(initialDelay: .milliseconds(2), delay: .milliseconds(2)) { _ in
        ticks.withLockedValue { $0.append(DispatchTime.now().uptimeNanoseconds) }
    }
    _ = try await mutualHandshake(
        presenting: identity,
        authority: authority,
        serverGroup: group,
        clientLoop: clientLoop
    )
    timer.cancel()
    try await group.shutdownGracefully()

    let start = started.withLockedValue { $0 }
    let end = finished.withLockedValue { $0 }
    #expect(start > 0 && end > start)
    // While the key signed for 50 ms, the loop ran its task many times.
    let during = ticks.withLockedValue { $0.filter { $0 > start && $0 < end }.count }
    #expect(during >= 5)
}
