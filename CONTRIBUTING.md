# Contributing

## Rule changes

Add or update data in catalog/rules.json. Keep IDs stable and assign a single owner to each physical target. Include exact evidence semantics, desired value/type, supported builds/editions, domain, severity, profile eligibility, reversibility, restart need, impact, source and review date. Do not add executable catalog script blocks.

Prefer runtime evidence for runtime claims. Missing registry values are not automatically secure; DefaultSecure needs an authoritative documented default. Legacy, deprecated or unverified controls remain inventory-only until their behavior is qualified. Do not label privacy or preference changes as security compliance.

Providers belong in src/Providers.ps1. Every mutation needs an original-state read, safe apply/restore behavior, post-change verification and meaningful failure propagation. If exact rollback is unavailable, mark the action irreversible and exclude it from automatic profiles.

## Tests

Run tests/Run-Tests.ps1 with Windows PowerShell 5.1 and PowerShell 7. The suite requires no downloaded dependencies and mocks system mutations. Add behavioral regression coverage for failures, stale state, repeat runs, interruptions and restore conflicts.

tests/Windows-Integration.ps1 is restricted to disposable CI runners or explicitly designated disposable VMs and mutates only a GUID-scoped HKCU fixture.

Complete the client VM matrix in docs/RELEASE-VALIDATION.md before production qualification. Server CI alone does not validate Windows client hardening, reset, gaming, App Control or organization-managed behavior.

## Style and review

Use Windows PowerShell 5.1-compatible syntax and UTF-8 with BOM for PowerShell files. Preserve strict mode compatibility. Keep diagnostics local, bound expensive collection and redact free-form/private evidence from sharing exports. Keep secrets and signing private keys out of source control.

PR descriptions should explain resulting behavior, compatibility impact, recovery and validation. Publish source/rule diffs and known limitations. Do not claim CIS certification or production readiness from a settings count or unit-test result.


