import CryptoKit
import Foundation
import KeychainIdentity

// Reads the identity "probe" and signs 200 messages with it.
// It checks each signature with the public key that the other app wrote.
// It logs the median, the 95th percentile and the maximum time in milliseconds.
@main
enum ProbeSigner {
    static let signatures = 200

    static func main() {
        let log = ProbeLog()
        do {
            let store = try IdentityStore(groupSuffix: ProbeConstants.groupSuffix)
            guard let identity = try store.identity(named: ProbeConstants.identityName) else {
                throw ProbeError(description: "no identity named \(ProbeConstants.identityName)")
            }
            let encoded = try String(contentsOfFile: probePublicKeyPath(), encoding: .utf8)
            guard let keyData = Data(base64Encoded: encoded.trimmingCharacters(in: .whitespacesAndNewlines)) else {
                throw ProbeError(description: "the public key file is not base64")
            }
            let publicKey = try P256.Signing.PublicKey(x963Representation: keyData)
            log.write(
                "public key of the other app matches the identity: \(publicKey.x963Representation == identity.publicKey.x963Representation)"
            )

            var milliseconds: [Double] = []
            let clock = ContinuousClock()
            for index in 0..<signatures {
                let message = Data("probe message \(index)".utf8)
                let start = clock.now
                let signature = try identity.sign(message)
                let elapsed = start.duration(to: clock.now)
                guard
                    try publicKey.isValidSignature(
                        P256.Signing.ECDSASignature(derRepresentation: signature), for: message)
                else {
                    throw ProbeError(description: "signature \(index) does not verify")
                }
                let parts = elapsed.components
                milliseconds.append(Double(parts.seconds) * 1000 + Double(parts.attoseconds) / 1e15)
            }
            milliseconds.sort()
            let middle = milliseconds.count / 2
            let median = (milliseconds[middle - 1] + milliseconds[middle]) / 2
            let p95 = milliseconds[Int((0.95 * Double(milliseconds.count)).rounded(.up)) - 1]
            let maximum = milliseconds[milliseconds.count - 1]
            log.write(
                "signed \(signatures) messages, all verified: median \(median) ms, p95 \(p95) ms, max \(maximum) ms")
            exit(0)
        } catch {
            log.write("failed: \(error)")
            exit(1)
        }
    }
}
