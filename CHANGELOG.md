# Changelog

## 2.0.0 - unreleased candidate

### Behavior changes
- Default CLI invocation audits. Applying settings requires -Action Apply.
- Distribution is a complete bundle with a versioned catalog and provider modules.
- Privacy and preference items no longer inflate a single security percentage.
- ASR starts in Audit and preserves stronger existing modes.
- Application/service/task removal, update deferral, LSA changes and other compatibility-sensitive rules require explicit selection.
- App removal affects the current user and preserves provisioning; removed app payloads are not backed up.

### Correctness and recovery
- One Delivery Optimization setting replaces contradictory category values.
- LSA configuration no longer requests a new firmware lock by default.
- NetBIOS P-node is labeled accurately; actual per-adapter disabling is a separate optional rule.
- Legacy/unverified policy mechanisms are marked Unsupported rather than applied.
- Registry value absence and type are preserved; nonregistry configuration uses provider-specific state.
- Changes require write-ahead journaling, are verified, and report failures through exit codes.
- Selective restore preserves later user changes and records conflicts.

### Features
- Profiles, explanations, expiry-based exceptions and compatibility hints.
- JSON/HTML reports, sharing redaction, snapshot and catalog comparisons.
- TCP/UDP process/service inventory and active firewall evidence.
- Symptom-based diagnostics and runtime security/recovery observations.
- Optional limited-user read-only monitor.
- App Control audit creation/deployment, evidence review, reviewed enforcement candidate and removal workflow.
- Public-certificate Protected Event Logging configuration and dependency checks.
- Offline automated regression tests, Windows CI, release signing and manifest verification tooling.

### Qualification
- Production release requires the client VM matrix, recovery/reset exercises, full provider qualification and code-signing evidence described in docs/RELEASE-VALIDATION.md.
- No signed production release is created merely by merging this change.

