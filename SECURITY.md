# Security policy

## Scope

Inginv is for authorized reverse engineering and defensive security research.

## Never publish

- private keys or keystore contents;
- passwords, tokens, API keys or session secrets;
- device serial numbers or stable user identifiers;
- Wi-Fi SSIDs/BSSIDs or unrelated user data;
- unredacted raw device dumps;
- credentials discovered in third-party software.

If a report contains a secret, record only its **presence, location, type, cryptographic fingerprint when appropriate, and remediation impact**. Do not reproduce the secret value.

## Reporting a vulnerability

Do not open a public issue containing a live credential or exploit-ready secret. Use a private disclosure channel with the affected vendor instead.
