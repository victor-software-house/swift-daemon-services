# Probe

Two small apps that measure one app signing with a Secure Enclave key that another app of the same team created, while the Mac is locked after its first unlock.
CI never builds this folder: a hosted runner has no Secure Enclave and no signed keychain group.
Run it by hand on a Mac with a development profile.

## What each app does

1. `ProbeMaker` removes the identity `probe` if an earlier run left one, creates it, and writes its public key to the file named by `PROBE_PUBLIC_KEY`.
2. `ProbeSigner` reads `probe`, signs 200 messages with it, and checks every signature with the public key the other app wrote.
   It logs the median, the 95th percentile and the maximum time of one signature, in milliseconds.
3. Both write progress to the file named by `PROBE_LOG`.

## Build

1. Install XcodeGen, and set your Apple developer team and the App Store Connect API key as shell variables:

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
   The team is read from the apps' signature at run time, and no file names it.

## Run

1. Make a folder for the run, and copy both apps into it.
2. Write two LaunchAgent property lists in `~/Library/LaunchAgents`, one per app.
   Each sets the label `com.victor-software-house.swift-daemon-services.probe.maker` or `.signer`,
   `ProgramArguments` with the app's `Contents/MacOS/ProbeMaker` or `ProbeSigner` executable, `RunAtLoad` false,
   and `EnvironmentVariables` that set `PROBE_LOG` to a log file and `PROBE_PUBLIC_KEY` to the same key file in both.
3. Start the maker once, then lock the Mac, and start the signer from another machine over SSH:

   ```sh
   launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/<maker plist>
   launchctl kickstart gui/$(id -u)/com.victor-software-house.swift-daemon-services.probe.maker
   launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/<signer plist>
   launchctl kickstart gui/$(id -u)/com.victor-software-house.swift-daemon-services.probe.signer
   ```

4. Read the signer's log.
   A line that starts with `signed 200 messages, all verified` carries the result.
   Add it, with the date, to the task 4.1 note in `openspec/changes/keychain-identity/tasks.md`.
