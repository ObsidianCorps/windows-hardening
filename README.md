# Windows Hardening Tool v2

Audit Windows, understand the trade-offs, preview changes, apply selected rules, and verify the result.

**Development candidate: client VM qualification and production code signing are required before a production release.** See [release validation](docs/RELEASE-VALIDATION.md). Automated tests do not certify Windows reset/recovery compatibility.

## What changed

- A versioned catalog of 171 security, privacy, preference and recovery checks.
- Everyday, Gaming, Developer and ManagedWorkstation profiles, with explicit optional selections.
- Write-ahead change journals, verification, selective rollback, conflict detection and mutation locking.
- Separate counts for security, privacy and preferences; runtime observations are distinguished from configured policy.
- Private JSON/HTML reports, redacted sharing exports, machine-state diffs and catalog recommendation diffs.
- TCP listeners, UDP endpoints, process/service ownership and active firewall evidence.
- Symptom-based diagnostics, WinRE evidence and bounded Defender/Code Integrity event collection.
- Optional read-only monitoring, exceptions with expiry, and software compatibility hints.
- An advanced App Control audit/review/enforcement lifecycle.
- Signed-release tooling and checksum verification. Development bundles are explicitly unsigned.

Version 2 replaces the single-file distribution. Keep **Harden-Windows.ps1**, **src/** and **catalog/** together. No runtime third-party PowerShell modules are downloaded.

## Start with an audit

Use 64-bit Windows PowerShell 5.1 on Windows 10 22H2 or Windows 11. Features vary by build, edition, management policy and hardware. The App Control lifecycle requires Windows 11 22H2 or newer. Windows Server is not an application target.

Some observations require elevation. Restricted access is reported as Unknown. Windows 10 servicing depends on edition/channel and ESU entitlement: a compatible build does not prove it is receiving security updates.

~~~powershell
.\Harden-Windows.ps1
.\Harden-Windows.ps1 -Action Audit -ReportPath "$env:LOCALAPPDATA\WindowsHardening\reports"
.\Harden-Windows.ps1 -Interactive
~~~

Audit and Plan read configuration. Report files are written only when requested. No scan result is a guarantee that a device is secure.

## Preview and apply

~~~powershell
.\Harden-Windows.ps1 -Action Plan -Profile Gaming

# Preview without modifying settings or writing reports:
.\Harden-Windows.ps1 -Action Apply -RuleId security.enablelua -WhatIf

# Elevated PowerShell; inspect the per-rule confirmation:
.\Harden-Windows.ps1 -Action Apply -RuleId security.enablelua

# Optional settings must be selected explicitly:
.\Harden-Windows.ps1 -Action Plan -Categories Privacy -IncludeOptional
.\Harden-Windows.ps1 -Action Apply -RuleId security.runasppl

# ASR defaults to Audit. Test applications before explicitly selecting Block:
.\Harden-Windows.ps1 -Action Apply -Categories Defender -ASRMode Audit
~~~

Profiles select a conservative starting set; they do not certify compatibility. Gaming avoids app/service removal; Developer leaves the maximum UAC prompt preference unselected. ManagedWorkstation still requires explicit authorization to modify a managed device. Privacy, app removal, service/task disabling, LSA changes, update deferral and driver exclusion are optional.

ASR rules already in Block or Warn are preserved when the target is Audit. LSA RunAsPPL=1 is preserved rather than downgraded; new optional LSA changes use value 2 on supported Windows 11 builds, without requesting a UEFI lock. Existing firmware locks require Microsoft's separate recovery procedure.

Use -AllowManaged only after reviewing organizational policy. The tool does not bypass Group Policy, MDM or Defender tamper protection. Management detection is conservative and can require manual review.

Legacy -Silent -All no longer implicitly mutates Windows. Use an explicit -Action Apply. -All additionally requires -IncludeOptional; selecting individual rules is recommended. -Confirm:$false is available for reviewed automation.

## Reports and differences

~~~powershell
# Keep this private JSON snapshot as your accepted baseline:
.\Harden-Windows.ps1 -Action Audit -ReportPath "$env:LOCALAPPDATA\WindowsHardening\baseline"

# Later, use the exact JSON filename printed by the first command:
.\Harden-Windows.ps1 -Action Audit -BaselinePath .\baseline.json -ReportPath .\reports

.\Harden-Windows.ps1 -Action Compare -BaselinePath .\before.json -ComparePath .\after.json
.\Harden-Windows.ps1 -Action CompareCatalog -BaselinePath .\old-rules.json -ComparePath .\catalog\rules.json

# Strict sharing export removes raw values, device/user IDs, addresses, processes and free-form logs:
.\Harden-Windows.ps1 -Action Audit -ReportPath .\share -Redact
~~~

Keep private snapshots for comparisons. Redacted exports cannot be restored or used as monitor baselines. HTML is standalone, escapes dynamic content, and uses no remote assets. An observed difference is not automatically attributed to this tool.

## Ports and troubleshooting

~~~powershell
.\Harden-Windows.ps1 -Action Network
.\Harden-Windows.ps1 -Action Doctor -Symptom Recovery -JournalPath .\run-ID.json
.\Harden-Windows.ps1 -Action Doctor -Symptom Camera -JournalPath .\run-ID.json
~~~

Network inventory distinguishes loopback, all-interface and individual interface bindings. Firewall rules are evidence, not a complete reachability verdict. A bound UDP endpoint does not necessarily represent a server. Internet exposure requires testing from an appropriate external observation point.

Doctor reads relevant events and log locations. It does not reset Windows, repair the component store, disable protections, or claim that a related change caused a failure.

## Restore

~~~powershell
.\Harden-Windows.ps1 -Action Restore -JournalPath .\run-ID.json -RuleId security.enablelua
~~~

Use the journal path printed after Apply. Original registry absence and types, service settings, task enablement, ASR preferences, firewall profile values and adapter NetBIOS settings are recorded. Rollback checks for intervening changes; conflicts require review. A restart may still be necessary.

Removed apps require Microsoft Store reinstallation. Provisioned apps are preserved. Feature payloads are not deliberately removed. Interrupted changes without reliable after-state require manual review. The adjacent .previous checkpoint may help investigation after an interrupted journal replacement.

Journals are local recovery records protected by filesystem ACLs. They are not tamper-proof evidence against a local administrator, and they are not a disk image or system backup. Version 1 .reg exports cannot provide full rollback.

## Monitoring and exceptions

~~~powershell
.\Harden-Windows.ps1 -Action RegisterMonitor -BaselinePath .\accepted-baseline.json
.\Harden-Windows.ps1 -Action RemoveMonitor

.\Harden-Windows.ps1 -Action Audit -ExceptionsPath .\my-exceptions.json
~~~

Copy [the exception example](catalog/exceptions.example.json), set a reason and an optional UTC expiry. Monitoring runs daily and at logon as the current user with a limited token. It writes private reports and never applies settings. It can detect changes after updates at the next scan; it is not a real-time Windows Update event subscriber. Retain or remove monitor reports according to your storage policy.

## Advanced features

See [App Control and protected logging](docs/ADVANCED.md), [architecture](docs/ARCHITECTURE.md), [release validation](docs/RELEASE-VALIDATION.md) and [the changelog](CHANGELOG.md).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Requested operation completed; inspect Unknown/Unsupported results in audits |
| 1 | Invalid input, environment error, or fatal persistence failure |
| 2 | Apply/restore failed, conflicted, needed manual recovery, or selected evidence was unavailable |
| 3 | Read-only Monitor found differences from its accepted baseline |

## Verify a release

Obtain the publisher's certificate thumbprint through an independently trusted channel. Run the verifier from a trusted checkout or verified distribution before running the tool:

~~~powershell
.\tools\Verify-Release.ps1 -Directory .\windows-hardening-2.0.0 -ExpectedSignerThumbprint YOUR_TRUSTED_THUMBPRINT
~~~

Checksums detect corruption; the signed manifest authenticates the publisher when its signature and expected certificate are verified. There is no automatic download-and-execute updater. Catalog changes are compared locally before adoption.

## License

[MIT](LICENSE).


