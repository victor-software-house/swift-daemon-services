# Proposal

## Why

1. A caller that keeps several identities in one team keychain group cannot ask which exist.
   It must remember each name, or call `identity(named:)` with a guess.
2. A mirror client certificate renews every identity of a Mac.
   It needs the list of names to do that, without a second record that can drift from the keychain.

## What Changes

1. `IdentityStore` gets `names()`, which returns the names of the identity keys in its group, sorted.

## Capabilities

### Modified Capabilities

- `keychain-identity`: list the identities of a store.

## Impact

1. Public API: one method is added to `IdentityStore`, so the release is a patch while the package is below 1.0.
2. No new dependency, and no change to a stored item.
