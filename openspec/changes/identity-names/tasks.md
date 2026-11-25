# Tasks

## 1. KeychainIdentity

- [ ] 1.1 `IdentityStore.names()`, and the internal `names(fromAttributes:)` that decodes, deduplicates and sorts the key tags.
  Verify: CI unit tests of `names(fromAttributes:)` pass, with unsorted tags, a duplicate, an item with no tag, and an empty list.
  Not provable in CI: the keychain query, since hosted runners are unsigned.

## 2. Release

- [ ] 2.1 A patch changeset fragment, the Version PR, and the next patch tag.
  Verify: the tag exists and `swift:api` passes on main.
