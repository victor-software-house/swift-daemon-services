import Security
import Testing

@testable import KeychainIdentity

@Test func anUnsignedProcessHasNoTeamGroup() {
    #expect(throws: KeychainIdentityError.notSigned) {
        try IdentityStore(groupSuffix: "com.example.identity")
    }
}

@Test func aSignedTeamWithTheEntitlementGetsItsGroup() throws {
    let group = try RunningCode.accessGroup(
        team: "TEAMID1234",
        suffix: "com.example.identity",
        entitled: ["TEAMID1234.com.example.identity", "TEAMID1234.other"]
    )
    #expect(group == "TEAMID1234.com.example.identity")
}

@Test(arguments: [nil, ""] as [String?])
func aMissingTeamIsNotSigned(team: String?) {
    #expect(throws: KeychainIdentityError.notSigned) {
        try RunningCode.accessGroup(team: team, suffix: "x", entitled: ["x"])
    }
}

@Test func aMissingEntitlementNamesTheGroup() {
    #expect(throws: KeychainIdentityError.missingEntitlement(group: "TEAMID1234.com.example.identity")) {
        try RunningCode.accessGroup(
            team: "TEAMID1234",
            suffix: "com.example.identity",
            entitled: ["TEAMID1234.other"]
        )
    }
}

@Test func theInteractionNotAllowedStatusIsLockedSinceBoot() {
    #expect(KeychainIdentityError.mapped(errSecInteractionNotAllowed) == .lockedSinceBoot)
}

@Test func anotherStatusKeepsItsCode() {
    #expect(KeychainIdentityError.mapped(errSecItemNotFound) == .keychain(errSecItemNotFound))
}
