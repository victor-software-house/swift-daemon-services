# Probe

Two small apps measure one app that signs with a Secure Enclave key another app created.
Both belong to one team and one keychain access group.
The Mac is locked after its first unlock.

CI never builds this folder.
A hosted runner has no Secure Enclave and no signed keychain group.
Run the probe by hand.
Use a Mac with a development profile.

## Apps

1. `ProbeMaker` removes the identity `probe` if an earlier run left one.
   It creates the identity again and writes its public key to the file that `PROBE_PUBLIC_KEY` names.
   It builds a signing request and issues a leaf from a throwaway authority that it makes in memory.
   It stores the chain, so that macOS forms a `SecIdentity`.
2. `ProbeSigner` reads `probe`.
   It logs the length of the chain and whether a `SecIdentity` is present.
   Then it signs 200 messages with the key.
   It checks every signature with the public key the other app wrote.
   It logs the median, the 95th percentile and the maximum time of one signature, in milliseconds.
3. Both apps write progress to the file that `PROBE_LOG` names.

## Build

1. Install XcodeGen.
   Then set your Apple developer team and an App Store Connect API key as shell variables:

   ```sh
   export DEVELOPMENT_TEAM=<team identifier>
   export ASC_KEY_PATH=<path of the AuthKey_<id>.p8 file>
   export ASC_KEY_ID=<key id>
   export ASC_ISSUER_ID=<issuer id>
   ```

2. Generate the project and build both apps:

   ```sh
   cd Probe
   xcodegen generate
   xcodebuild -project Probe.xcodeproj -scheme ProbeMaker -configuration Release \
     -derivedDataPath build -allowProvisioningUpdates \
     -authenticationKeyPath "$ASC_KEY_PATH" -authenticationKeyID "$ASC_KEY_ID" \
     -authenticationKeyIssuerID "$ASC_ISSUER_ID" DEVELOPMENT_TEAM="$DEVELOPMENT_TEAM"
   xcodebuild -project Probe.xcodeproj -scheme ProbeSigner -configuration Release \
     -derivedDataPath build -allowProvisioningUpdates \
     -authenticationKeyPath "$ASC_KEY_PATH" -authenticationKeyID "$ASC_KEY_ID" \
     -authenticationKeyIssuerID "$ASC_ISSUER_ID" DEVELOPMENT_TEAM="$DEVELOPMENT_TEAM"
   ```

   The apps are `build/Build/Products/Release/ProbeMaker.app` and `ProbeSigner.app`.
   No file names the team.
   The code reads it from its own signature at run time.

## Run

1. Make a folder for the run, and copy both apps into it.

2. Write two LaunchAgent property lists in `~/Library/LaunchAgents`, one for each app.
   Give each list these keys:
   - `Label` is `com.victor-software-house.swift-daemon-services.probe.maker` or `.signer`.
   - `ProgramArguments` is the executable `Contents/MacOS/ProbeMaker` or `ProbeSigner` of the copied app.
   - `RunAtLoad` is false.
   - `EnvironmentVariables` sets `PROBE_LOG` to a log file, and `PROBE_PUBLIC_KEY` to one key file for both apps.

3. Start the maker once.
   Lock the Mac, and start the signer from another machine over SSH:

   ```sh
   launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/<maker plist>
   launchctl kickstart gui/$(id -u)/com.victor-software-house.swift-daemon-services.probe.maker
   launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/<signer plist>
   launchctl kickstart gui/$(id -u)/com.victor-software-house.swift-daemon-services.probe.signer
   ```

4. Read the log of the signer.
   The line that starts with `chain length` shows the chain and the `SecIdentity`.
   The line that starts with `signed 200 messages, all verified` shows the timing.
   Add both, with the date, to the note of task 4.1 in `openspec/changes/keychain-identity/tasks.md`.
