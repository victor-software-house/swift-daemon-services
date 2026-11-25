import Foundation
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

private func tagged(_ name: String) -> [String: Any] {
    [kSecAttrApplicationTag as String: Data(name.utf8)]
}

@Test func theNamesAreSortedWithoutDuplicates() {
    let attributes = ["b", "c", "a", "b"].map(tagged)
    #expect(IdentityStore.names(fromAttributes: attributes) == ["a", "b", "c"])
}

@Test func anItemWithoutATagHasNoName() {
    let attributes = [tagged("a"), [kSecAttrLabel as String: "b"], [kSecAttrApplicationTag as String: "c"]]
    #expect(IdentityStore.names(fromAttributes: attributes) == ["a"])
}

@Test func aTagThatIsNotTextHasNoName() {
    let attributes = [tagged("a"), [kSecAttrApplicationTag as String: Data([0xFF, 0xFE])]]
    #expect(IdentityStore.names(fromAttributes: attributes) == ["a"])
}

@Test func noItemsHaveNoNames() {
    #expect(IdentityStore.names(fromAttributes: []).isEmpty)
}
