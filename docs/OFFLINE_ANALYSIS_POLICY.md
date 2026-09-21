# Offline analysis policy

Inginv is an **offline reverse-engineering workbench**. Analysis of third-party software and device evidence must not contact the software vendor, control plane, broker, telemetry service, CDN, DNS endpoint, Firebase project, or any other external provider discovered in the artifact.

## Hard rules

- Treat domains, IPs, URLs, MQTT/WebSocket endpoints, Firebase configuration and credentials as inert evidence strings only.
- Do not resolve discovered hosts for analysis purposes.
- Do not issue HTTP(S), WebSocket, MQTT or other protocol requests to discovered infrastructure.
- Do not authenticate with discovered credentials, tokens, certificates or keys.
- Do not execute an APK in an environment where it can phone home as part of analysis.
- Do not upload APKs, raw device dumps, private keys, credentials, stable device identifiers, Wi-Fi identifiers or provider responses to the public repository.
- Network-behavior tests use `example.invalid`, local fixtures or an explicitly local simulated server only.

## Allowed network use

Repository hosting and CI may contact the infrastructure required to operate GitHub and install the project's own declared build/test dependencies. This does **not** authorize calls to infrastructure discovered in analyzed artifacts.

## Enforcement

The test suite statically rejects direct network-client/resolver imports and common network subprocess tools from Inginv production source. This is a guardrail, not a proof against every possible dynamically constructed network operation; code review remains mandatory for changes that touch subprocesses, plugins or execution facilities.
