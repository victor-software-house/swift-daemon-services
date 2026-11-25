import Foundation

// The group suffix and identity name that both apps use.
enum ProbeConstants {
    static let groupSuffix = "com.victor-software-house.swift-daemon-services.probe"
    static let identityName = "probe"
}

// A failure of the probe.
struct ProbeError: Error, CustomStringConvertible {
    let description: String
}

// Appends lines to the file that PROBE_LOG names.
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

// The file that PROBE_PUBLIC_KEY names.
func probePublicKeyPath() throws -> String {
    guard let path = ProcessInfo.processInfo.environment["PROBE_PUBLIC_KEY"] else {
        throw ProbeError(description: "PROBE_PUBLIC_KEY names no file")
    }
    return path
}
