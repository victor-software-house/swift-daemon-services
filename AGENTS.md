# swift-daemon-services

A public Swift package for the background parts of macOS apps.
This file is the contributor contract.

## Rules

1. The repository is public.
   Keep these out of every tracked file, commit message, branch name and pull request:
   - a local path
   - a machine name
   - a private repository name
   - an internal URL
   - a credential
   - a personal detail
2. The package works on any Mac on the supported macOS as a person installs it.
   Never assume a device management profile, a System Integrity Protection change or pre-granted privacy access.
3. Each approval that macOS may require is a detected state.
   It comes with the System Settings pane that grants it.
   A person sees it at most once per install.
4. A background part runs only while it has work.
   Launchd starts it on a message, a connection or a schedule.
   It exits when it is idle.
5. Core products depend only on Apple's frameworks.
   A product that needs another package is a separate product.
6. The signing team is read from the running code's signature, never written in source.
7. Every change goes through a pull request, and the pull request's CI verifies it.
8. Commits follow Conventional Commits.
