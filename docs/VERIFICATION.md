# Verification log

## 2026-09-20 — bootstrap

Local verification of the initial analyzer:

```text
pytest -q
4 passed
```

The analyzer was also run against the owner-supplied EasyControl APK:

```text
size: 24801867 bytes
sha256: 97b5b3479f58e6ba25bea74c15674f2ac5e07b48be807ec734d7ed16370aa575
zip_integrity: ok
entry_count: 1062
dex: 3
keystore: 13
native-library: 4
xml: 583
native_abis: arm64-v8a, armeabi-v7a, x86, x86_64
```

High-value string scanning identified command-name hits for application install/uninstall, reboot, factory reset, screenshot, log capture, location, lock/unlock, remote-care and related control-plane behavior.

No discovered credential values, private-key contents, device serial numbers, Wi-Fi identifiers or raw forensic dumps are committed to this repository.
