## ADDED Requirements

### Requirement: The store lists its identities

`names()` SHALL return the names of every identity key in the store's group, sorted, and an empty list when there is none.

#### Scenario: Two identities and a removed one

- **WHEN** the group has the identities `b` and `a`
- **THEN** `names()` returns `["a", "b"]`
- **AND WHEN** `a` is removed
- **THEN** `names()` returns `["b"]`
