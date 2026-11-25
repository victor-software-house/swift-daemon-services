import Foundation
import Security

// What the running code's signature says: its team and the keychain groups it may use.
enum RunningCode {
    // The signing team of the running code, or nil when it has none.
    // Unsigned code, ad hoc code and Apple platform code carry no team.
    static func teamIdentifier() throws -> String? {
        var code: SecCode?
        var status = SecCodeCopySelf([], &code)
        guard status == errSecSuccess, let code else {
            throw KeychainIdentityError.mapped(status)
        }
        var staticCode: SecStaticCode?
        status = SecCodeCopyStaticCode(code, [], &staticCode)
        guard status == errSecSuccess, let staticCode else {
            throw KeychainIdentityError.mapped(status)
        }
        var information: CFDictionary?
        status = SecCodeCopySigningInformation(
            staticCode,
            SecCSFlags(rawValue: kSecCSSigningInformation),
            &information
        )
        if status == errSecCSUnsigned {
            return nil
        }
        guard status == errSecSuccess else {
            throw KeychainIdentityError.mapped(status)
        }
        let values = information as? [String: Any]
        return values?[kSecCodeInfoTeamIdentifier as String] as? String
    }

    // The `keychain-access-groups` entitlement of the running code, empty when it has none.
    static func keychainAccessGroups() -> [String] {
        guard let task = SecTaskCreateFromSelf(nil) else {
            return []
        }
        var error: Unmanaged<CFError>?
        let value = SecTaskCopyValueForEntitlement(task, "keychain-access-groups" as CFString, &error)
        error?.release()
        return value as? [String] ?? []
    }

    // The group of a team and a suffix, when the code is signed by the team and its entitlement lists the group.
    static func accessGroup(team: String?, suffix: String, entitled: [String]) throws -> String {
        guard let team, !team.isEmpty else {
            throw KeychainIdentityError.notSigned
        }
        let group = "\(team).\(suffix)"
        guard entitled.contains(group) else {
            throw KeychainIdentityError.missingEntitlement(group: group)
        }
        return group
    }
}
