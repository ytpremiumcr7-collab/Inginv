# Threat model

## Assets

- device-owner authority;
- package installation state;
- device files and logs;
- screenshots and other exported artifacts;
- remote-command channel credentials and trust anchors;
- forensic evidence collected by the analyst.

## Trust boundaries

1. remote control plane ↔ device agent;
2. push transport ↔ task dispatcher;
3. task payload ↔ privileged controller;
4. downloaded artifact ↔ package installer;
5. device filesystem ↔ upload/reporting worker;
6. raw evidence ↔ public/sanitized repository.

## High-impact failure classes

- weak or bypassed TLS identity validation;
- client-shipped server private-key material;
- hard-coded reusable credentials;
- remote file operations without path confinement;
- package installation without an application-specific signer allowlist;
- exported privileged components without caller authorization;
- sensitive payloads/tokens written to logs;
- remote task replay or missing freshness/idempotency checks;
- command dispatch that can reach shell execution with attacker-controlled input.

## Non-goals

This project does not attempt unauthorized server access, credential reuse, broker authentication, remote command injection, or exploitation of third-party infrastructure.
