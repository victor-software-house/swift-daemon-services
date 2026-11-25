# swift-daemon-services: design

A Swift package for the background parts of a macOS app signed with a Developer ID: login agents, launch daemons, helpers and system extensions.
It gives each part one implementation of what every such app needs: registration and approval, updates, local connections, configuration, CloudKit state, keychain identities and logging.
Status: draft. It becomes the first OpenSpec change once the repository takes the shared template.

## 1. Rules every module follows

1. It works on any Mac on the supported macOS, as a person installs it: no device management profile, no System Integrity Protection change, no pre-granted privacy access (operator, 2026-11-24).
2. Every approval macOS may require is a state the package detects and reports, with the one System Settings pane that grants it.
   It asks at most once per install, and an update never asks again.
   A device management profile may grant the same approval ahead of time; the package then sees the granted state and asks nothing.
3. No resident process when idle: a part starts when launchd delivers a message, a connection or a scheduled time, and exits when idle.
4. No measurable cost on a hot path: no polling, and every speed claim backed by a release-build measurement.
5. Settings are typed values read from files or preferences, never constants in code.
6. The signing team is read from the running code's own signature, never written in source.
7. Every check that guards a boundary fails closed.
8. Apple's frameworks first.
   The core products depend on nothing else; a product that needs SwiftNIO or swift-nio-ssl is a separate product.
9. macOS 27 and Swift 6.4 language mode with strict concurrency, built with the newest Xcode.

## 2. Install and update model

1. Install: a notarized, stapled package that a Homebrew cask installs.
   The app lands root-owned in `/Applications`, where macOS requires a system extension's app to be.
2. Registration: the app carries its launchd property lists in `Contents/Library/LaunchAgents` and `LaunchDaemons` with `BundleProgram`, and registers them with `SMAppService`.
3. Update: each app runs the `DaemonUpdater` library in its own on-demand root daemon (operator, 2026-11-24).
   The cask sets `auto_updates true`, so `brew upgrade` leaves the app to the updater.
4. An update replaces the bundle in place and keeps the team, bundle identifiers and job labels, so macOS keeps every approval it granted.

## 3. Products

Each product is a library target; the first release ships 3.1 and 3.2, which a signed TLS client needs.

### 3.1 KeychainIdentity

1. Data-protection keychain items in an access group read from the app's entitlements.
2. Secure Enclave P-256 keys, created with `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` and `.privateKeyUsage`, and restored from their handle.
3. TLS client identities: a Secure Enclave key, a certificate signing request for it, and the certificate chain stored beside it.
   An identity lives in a keychain group two apps of one team share, so one app manages it and another signs with it.
4. Measured on 2026-11-24: an app started by launchd signed with a key another app of the team created, through a shared group, on a locked Mac, at 4.63 ms median per signature.
   Both apps were development-signed bundles; a Developer ID bundle with a Developer ID provisioning profile is still to be measured.

### 3.2 KeychainIdentityNIOSSL

Adapts a KeychainIdentity to swift-nio-ssl's `NIOSSLCustomPrivateKey`, so a SwiftNIO client signs its TLS handshake with the Secure Enclave key.

### 3.3 DaemonRegistration

1. One type per kind of part: login agent, launch daemon, the app as a login item, and a system extension.
2. Status as a closed enum, from `SMAppService.Status` and the system extension request's callbacks, each with the action it needs, such as `SMAppService.openSystemSettingsLoginItems()` for `requiresApproval`.
3. launchd job control with a bounded retry and a typed error, for the moments `SMAppService` does not cover, such as restarting a job after an update.
4. `launch_activate_socket` as a typed call that returns a named socket's descriptors.

### 3.4 DaemonUpdater

1. Runs inside an app's own root daemon, started by launchd on a schedule or a check request, and exits when done.
2. Reads the newest release, downloads with a size limit, unpacks into a root-owned staging folder, and seals it.
3. Requires a notarized bundle with the app's identifier and the updater's own team, and a version equal to the release tag.
4. Swaps the bundle with `renamex_np` and restarts the app's jobs.
5. Settings come from managed preferences, then machine preferences, then defaults, so an administrator can turn updates off or space them out.

### 3.5 LocalConnection

1. XPC listeners and sessions through the Swift XPC API with an `XPCPeerRequirement`: the same team and the peer's signing identifier, never the team alone.
2. Peer code identity from an audit token, cached per token.
3. A separate product, `LocalConnectionNIO`, serves a Unix socket for a data path: socket file mode 0600 in a 0700 folder, the peer's uid and code identity read once per connection, and length-prefixed frames with a maximum length.

### 3.6 ConfigWatch

1. A kqueue watch on a file and its folder that re-arms when an editor or a deploy tool replaces the file, with a short debounce.
2. Typed load and validation, with every error naming the entry at fault.
3. Managed and machine preference precedence for administrator settings, with a Darwin notification on change.

### 3.7 CloudState

1. A private CloudKit database zone per app, with a database subscription and push delivery.
2. Conditional saves, and a lease record that expires on its own, so one Mac does a shared job at a time.
3. Account change handling, and a clear state when the person is not signed in to iCloud.

### 3.8 Logging

1. A logger per category under the app's subsystem, with a level read from configuration.
2. A status value each part reports, for a status command and a menu.

## 4. Not in the package

1. Packaging, notarization and CI, which the repository's templates and shared workflows own.
2. Any app's own logic.
3. User interface beyond opening the right System Settings pane.

## 5. Repository

1. Public, AGPL-3.0, rendered from the shared `swift-package` template with every Swift library piece on.
2. CI on GitHub-hosted macOS 27 runners with the pinned Xcode.
   Secure Enclave, keychain group and CloudKit tests need a signed bundle on a real Mac, so they run in a separate suite by hand.
3. Releases through verctl tags, from version 0.0.0; the first release is 0.0.1.
