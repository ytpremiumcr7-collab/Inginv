# Inginv

Evidence-first Android reverse-engineering workbench for APK/static and device-runtime correlation.

Inginv is designed for authorized analysis of devices and software you own or are permitted to inspect. It separates **capability in code** from **behavior observed at runtime**, keeps raw evidence out of Git by default, and redacts common credential patterns before reports are exported.

## Current focus

The first case is a privileged Android MDM observed on an X96Q-class device. The repository is intentionally structured as a reusable reverse-engineering toolkit rather than a one-off dump.

## What works now

```bash
python -m inginv apk-summary /path/to/app.apk
python -m inginv apk-summary /path/to/app.apk --json report.json
python -m inginv apk-strings /path/to/app.apk --json strings.json
```

The analyzer currently performs:

- SHA-256 and archive integrity verification;
- complete ZIP entry inventory and type classification;
- DEX / native ABI / certificate / keystore surface inventory;
- suspicious path traversal checks;
- printable-string extraction from APK members;
- URL, endpoint, command-keyword and credential-pattern discovery;
- deterministic redaction of likely secrets before export.

## Evidence discipline

Every finding should be classified as one of:

- `STATIC_CONFIRMED` — directly present in APK code/resources;
- `RUNTIME_CONFIRMED` — directly observed on the device;
- `CORRELATED` — static and runtime evidence independently agree;
- `INFERRED` — technically plausible but not directly observed;
- `UNVERIFIED` — insufficient evidence.

See [`docs/EVIDENCE_MODEL.md`](docs/EVIDENCE_MODEL.md).

## Security rules

Do not commit APKs, device dumps, serial numbers, Wi-Fi identifiers, private keys, tokens, passwords, or unredacted forensic exports. The public repository is for tooling, sanitized evidence summaries, and reproducible methodology.

See [`SECURITY.md`](SECURITY.md).
