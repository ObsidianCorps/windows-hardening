# Security

Report vulnerabilities privately through the repository's GitHub private vulnerability reporting facility when available, or contact the maintainers through the organization's published security contact. Do not post credentials, recovery keys or private diagnostic reports in public issues.

## Development status

Version 2 is an unreleased development candidate. Production qualification requires the client VM/recovery matrix and publisher-signed release verification described in docs/RELEASE-VALIDATION.md. No release or signature is implied by a development bundle or a passing regression suite.

## Trust and recovery

Review proposed changes before running elevated Apply. Use the complete trusted release bundle; catalog data can request impactful Windows configuration even though it contains no executable script blocks.

Journals cover provider-specific original state and selective rollback, not a full operating system backup. App removal needs reinstallation. Firmware locks created by earlier versions are not removed by registry restoration. App Control enforcement requires separately tested recovery procedures.

Local administrators and SYSTEM can access or modify local evidence. Restrictive ACLs do not make a compromised host trustworthy. Share only redacted reports, and review exports before publication.

The tool never collects disk-encryption recovery keys or logging private keys. Diagnostic event messages and private reports can contain sensitive application paths or command content.


