import Foundation

// The group suffix and identity name both apps use.
enum ProbeConstants {
    static let groupSuffix = "com.victor-software-house.swift-daemon-services.probe"
    static let identityName = "probe"
}

// A failure of the probe that is not a KeychainIdentityError.
struct ProbeError: Error, CustomStringConvertible {
    let description: String
}

// Appends lines to the file that the PROBE_LOG environment variable names.
struct ProbeLog {
    private let handle: FileHandle?

    init() {
        guard let path = ProcessInfo.processInfo.environment["PROBE_LOG"] else {
            handle = nil
            return
        }
        if !FileManager.default.fileExists(atPath: path) {
            FileManager.default.createFile(atPath: path, contents: nil)
        }
        handle = FileHandle(forWritingAtPath: path)
        _ = try? handle?.seekToEnd()
    }

    func write(_ line: String) {
        try? handle?.write(contentsOf: Data("\(Date()) \(line)\n".utf8))
    }
}

// The file that the PROBE_PUBLIC_KEY environment variable names.
func probePublicKeyPath() throws -> String {
    guard let path = ProcessInfo.processInfo.environment["PROBE_PUBLIC_KEY"] else {
        throw ProbeError(description: "PROBE_PUBLIC_KEY names no file")
    }
    return path
}
