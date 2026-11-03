# Architecture and threat model

Harden-Windows.ps1 validates CLI intent and orchestrates a data-only catalog. WindowsHardening.psm1 plans work and provides a common execution/restore engine. Providers.ps1 implements allowlisted Windows operations; Inspection.ps1 reads network and diagnostic evidence; Reports.ps1 compares and exports; Automation.ps1 manages only this user's monitor; AppControl.ps1 implements a separate advanced lifecycle.

## Catalog

Rule IDs are stable. A physical target has one owner. Rules carry domain, severity, desired value, type, build/edition applicability, profile eligibility, reversibility, restart requirement, explanation, impact, source and review date. Legacy or unverified controls are disabled. A reference and review date are not claims of benchmark certification or client VM testing.

Catalog JSON contains no executable script blocks. A malicious catalog can still request harmful allowlisted configuration, so trust the release publisher and review catalog diffs. Changing a rule's target requires migration planning because restore deliberately validates targets against the installed trusted catalog.

## State and execution

Provider state preserves Known, Exists, Value, Type and provider-specific Extra. Unknown reads are not treated as secure defaults. Null/default security applies only to explicitly documented registry rules.

The engine reads the original state, persists Prepared, invokes the provider, re-reads state and persists a result. Settings are never changed when the write-ahead journal cannot be saved. Native exit codes are checked. Journal replacement is atomic on supported local filesystems and retains the previous checkpoint. Files are UTF-8 with BOM. Exclusive file locking serializes this tool's mutation operations; it cannot lock out Windows, management agents or other administrators.

Restore reverses journal order, validates the local computer/user and catalog target, and compares current state with recorded before/after states. It refuses to overwrite intervening changes. Configuration changes are not one OS-wide atomic transaction: an interruption can leave partial state, documented for investigation. Before/after races with external management cannot be eliminated.

## Output security

State/report directories remove inherited ACL entries and grant access to the current user, SYSTEM and Administrators. Failure to apply ACLs is fatal for writes. Reparse-point paths are refused for privileged state output. Keep directories on a local NTFS volume, outside shared or synchronized folders. Elevated alternate-user sessions use that account's HKCU; the tool does not impersonate an unelevated desktop user.

Reports escape dynamic HTML, disable active/remote content through CSP and have no external dependencies. Redaction uses a strict field allowlist and drops free-form messages and raw state. Local journals are not cryptographically authenticated evidence against administrators. Signing protects release provenance, not an already compromised host.

## Scope

No external port scans, telemetry uploads, secret collection, antivirus bypasses, automatic remote script execution, app provisioning removal, boot edits or firmware-lock creation are part of ordinary Apply.

Protected Event Logging stores only a public certificate. Device encryption observations never collect recovery passwords. Firewall evidence does not establish external reachability. Build compatibility does not establish servicing entitlement. App Control enforcement is explicitly separate and requires human compatibility review.

