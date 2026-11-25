# swift-daemon-services

A Swift package for the background parts of a macOS app signed with a Developer ID: login agents, launch daemons, helpers and system extensions.

It gives each part one tested implementation of what every such app needs:
registration and approval, self-updates, local connections, configuration that reloads on change, CloudKit state, keychain and Secure Enclave identities, and logging.

Status: design.
No release yet; the first release will contain the keychain identity products.

## Requirements

- macOS 27 or later.
- Swift 6.4 and the newest Xcode.
- An app signed with a Developer ID, installed in `/Applications`.

The package assumes nothing beyond a standard Mac.
It needs no device management profile and no change to System Integrity Protection.
Where macOS asks a person to approve something, the package reports which approval is missing and opens the System Settings pane that grants it.

## License

[GNU Affero General Public License v3.0 or later](LICENSE).
