import Foundation
import KeychainIdentity

// Creates the identity "probe" in the probe's keychain group and writes its public key to a file.
@main
enum ProbeMaker {
    static func main() {
        let log = ProbeLog()
        do {
            let path = try probePublicKeyPath()
            let store = try IdentityStore(groupSuffix: ProbeConstants.groupSuffix)
            log.write("group \(store.accessGroup)")
            if try store.identity(named: ProbeConstants.identityName) != nil {
                try store.remove(name: ProbeConstants.identityName)
                log.write("removed the identity of an earlier run")
            }
            let identity = try store.create(name: ProbeConstants.identityName)
            let key = identity.publicKey.x963Representation.base64EncodedString()
            try key.write(toFile: path, atomically: true, encoding: .utf8)
            log.write("created \(ProbeConstants.identityName), public key written to \(path)")
            exit(0)
        } catch {
            log.write("failed: \(error)")
            exit(1)
        }
    }
}
