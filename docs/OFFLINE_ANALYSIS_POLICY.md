# Offline analysis policy

Inginv is an **offline reverse-engineering workbench**.

Analysis of third-party software and device evidence must not contact the software vendor, control plane, broker, telemetry service, CDN, DNS endpoint, Firebase project, or any other external provider discovered in an artifact.

## Hard rules

- Treat domains, IPs, URLs, MQTT/WebSocket endpoints, Firebase configuration and credentials as inert evidence strings only.
- Do not resolve discovered hosts for analysis purposes.
- Do not issue HTTP(S), WebSocket, MQTT or other protocol requests to discovered infrastructure.
- Do not authenticate with discovered credentials, tokens, certificates or keys.
- Do not execute an analyzed APK in an environment where it can phone home as part of analysis.
- Do not upload APKs, raw device dumps, private keys, credentials, stable device identifiers, Wi-Fi identifiers or provider responses to the public repository.
- Network-behavior tests use `example.invalid`, in-memory fixtures, or an explicitly local simulator only.

## Allowed network use

Repository hosting and CI may contact infrastructure required to operate GitHub and install Inginv's own declared build/test dependencies. That allowance does **not** authorize calls to infrastructure discovered in analyzed artifacts.

## Enforcement

Inginv uses three complementary controls:

1. `offline-guard` statically rejects direct network transports/resolvers and common network subprocess clients from production Python source.
2. CI runs that guard independently of the unit tests.
3. The pytest suite has an autouse fail-closed fixture that blocks DNS resolution and socket connections while tests execute.

These controls are guardrails, not a proof against every dynamically constructed operation. Code review remains mandatory for changes involving subprocesses, plugins, native executables, dynamic imports or execution facilities.
