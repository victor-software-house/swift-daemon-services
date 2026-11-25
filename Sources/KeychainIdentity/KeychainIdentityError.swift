import Foundation
import Security

/// A state of a keychain identity that a caller acts on.
///
/// Every failure of `IdentityStore` that comes from the keychain, the signing team or the
/// entitlements is one of these cases.
public enum KeychainIdentityError: Error, Equatable, Sendable {
    /// The running code has no signing team, so it has no team keychain group.
    case notSigned
    /// The code's `keychain-access-groups` entitlement does not list the group.
    case missingEntitlement(group: String)
    /// The keychain holds no identity with this name.
    case notFound(name: String)
    /// The group already holds an identity with this name.
    case alreadyExists(name: String)
    /// The leaf certificate does not carry the identity's public key.
    case keyMismatch
    /// The Mac has not been unlocked since it started, so the keychain refuses access.
    case lockedSinceBoot
    /// Any other Security framework status.
    case keychain(OSStatus)
}

extension KeychainIdentityError {
    // The error for a Security framework status.
    static func mapped(_ status: OSStatus) -> KeychainIdentityError {
        if status == errSecInteractionNotAllowed {
            return .lockedSinceBoot
        }
        return .keychain(status)
    }

    // The error for the CFError that a Security call returned, or for the fallback status when it returned none.
    static func mapped(_ error: Unmanaged<CFError>?, fallback: OSStatus) -> KeychainIdentityError {
        guard let error else {
            return mapped(fallback)
        }
        let code = CFErrorGetCode(error.takeRetainedValue())
        return mapped(OSStatus(truncatingIfNeeded: code))
    }
}
