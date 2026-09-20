# Case: EasyControl MDM on X96Q-class Android TV box

Status: active reverse-engineering case. This file intentionally contains no live credentials, private-key material, device serials, or Wi-Fi identifiers.

## Correlated facts

- The installed package is `com.easycontrol.mdm` under `/system/priv-app/MDM/MDM.apk`.
- Runtime evidence reports the package as Android Device Owner for user 0 and running as UID 1000.
- `EcmService` is observed running persistently.
- The package registers boot/direct-boot receivers, Firebase messaging and a proprietary push receiver.
- Static analysis identified task names including application install/uninstall, reboot, factory reset, screenshot, log capture, file deletion, location and lock/passcode operations.
- Static call tracing identified concrete paths from selected task handlers to privileged Android APIs such as DevicePolicyManager, PackageInstaller, shell `screencap`, and filesystem deletion.

## Important uncertainty boundary

The presence of a remote command implementation and the agent's live Device Owner authority does **not** establish that a specific command was issued against the examined device. Runtime command execution must be demonstrated independently through logs, traces or other direct evidence.

## Sanitized security leads under review

- TLS hostname verification behavior in the proprietary push stack;
- keystore material bundled in the client;
- reusable transport credentials embedded in the APK;
- remote path handling in file deletion;
- signer validation before remote APK installation;
- exported component authorization;
- sensitive push/task data in logs.
