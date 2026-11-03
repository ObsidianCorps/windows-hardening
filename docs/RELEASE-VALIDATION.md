# Release qualification

Status: development candidate. Automated regression tests are necessary but do not certify client behavior or recovery compatibility.

## Automated checks

Run Windows PowerShell 5.1 tests without third-party modules:

~~~powershell
.\tests\Run-Tests.ps1 -ResultPath .\test-results.json
~~~

CI runs the offline regression suite on Windows Server 2022/2025 with Windows PowerShell and PowerShell 7. Server runners validate engine compatibility; Windows Server is not a supported hardening target. Windows integration tests touch only a uniquely named disposable HKCU test key.

Restricted development environments may deny CIM, registry writes, ACL changes or code-signing APIs. Treat denied checks as untested rather than success. Do not relax production ACL requirements merely to make sandbox tests pass.

## Client VM matrix - required before production sign-off

Maintain separate evidence for Windows 10 22H2 with supported servicing, and supported Windows 11 builds/editions. Include Pro/Home and an organization-managed scenario where applicable; unsupported features must be reported honestly.

For each qualified client build record the exact OS edition/build/patch level, tool/catalog hashes, VM snapshot ID, operator/date and artifacts for:

1. Audit and Plan with standard and elevated users. Confirm no configuration changes.
2. Each profile, optional registry/service/task/Defender/firewall/feature/adapter operation, and post-reboot observations.
3. Repeat Apply without unintended further changes; selective Restore and full reversible Restore.
4. Originally absent registry values, non-default types, automatic/delayed/manual services and disabled/running tasks.
5. Defender tamper protection, passive/third-party antivirus, GPO/MDM overrides, access denial, missing components and pending restarts.
6. Interrupted writes/mutations, disk-full behavior, concurrent invocation and externally changed state.
7. Gaming, developer tooling, camera/microphone, network shares, VPN, printing, backup software and organization administration.
8. WinRE boot, local Reset this PC, cloud reset where available, and repair installation after representative optional changes. Preserve diagnostics and restore the VM snapshot between destructive recovery tests.
9. ASR Audit-to-Block application checks and App Control audit/review/enforcement/removal/recovery on a separate disposable VM.
10. Protected Event Logging encryption/decryption, certificate expiry handling and report redaction.

Record pass/fail/unavailable per feature. Preserve unresolved issues in release notes. Do not call a build production-qualified while required checks are pending.

## Build and sign

An unsigned test package:

~~~powershell
.\tools\Build-Release.ps1 -OutputDirectory .\dist-development -Development
.\tools\Verify-Release.ps1 -Directory .\dist-development\windows-hardening-2.0.0 -AllowUnsignedDevelopment
~~~

A production package requires a trusted code-signing certificate and timestamp service:

~~~powershell
.\tools\Build-Release.ps1 -OutputDirectory .\dist-release -SigningThumbprint YOUR_CERTIFICATE_THUMBPRINT -TimestampServer YOUR_TIMESTAMP_SERVICE
~~~

The build signs PowerShell files, hashes bundle contents and signs the manifest. Production verification requires a valid signature and the independently trusted publisher thumbprint. Do not commit signing keys, automatically export them or create a self-signed certificate and describe it as public publisher trust.

Release approval must include the completed VM evidence, passing CI, reviewed rule diffs, a versioned changelog, successful signed-bundle verification, and published signer identity/checksums.

