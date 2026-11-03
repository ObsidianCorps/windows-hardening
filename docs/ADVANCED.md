# Advanced workflows

## App Control

This is a separate, explicit lifecycle. General Apply never deploys App Control policies.

Use a disposable Windows 11 client VM first. A restrictive policy can prevent applications and administration scripts from running; audit mode can also change script-host behavior. The tool only manages independent, removable unsigned base policies; it does not deploy signed/firmware-locked policies or automatically change other products' policies.

~~~powershell
.\Harden-Windows.ps1 -Action AppControl -AppControlOperation New
# Inspect the generated XML and retain its path.
.\Harden-Windows.ps1 -Action AppControl -AppControlOperation Audit -PolicyPath .\audit.xml
# Exercise applications for at least seven days, including backup and recovery tools.
.\Harden-Windows.ps1 -Action AppControl -AppControlOperation Review -PolicyPath .\audit.xml
# Inspect audit events, including script/MSI events, and resolve compatibility issues.
.\Harden-Windows.ps1 -Action AppControl -AppControlOperation EnforceCandidate -PolicyPath .\audit.xml -ReviewPath .\review.json -CompatibilityReviewed
# Inspect the generated candidate before explicitly deploying it.
.\Harden-Windows.ps1 -Action AppControl -AppControlOperation Enforce -PolicyPath .\candidate.xml -CompatibilityReviewed
.\Harden-Windows.ps1 -Action AppControl -AppControlOperation Remove -PolicyPath .\candidate.xml
~~~

The review binds to the exact audit policy hash and local deployment record. Seven days alone is not a compatibility certification. Events can be truncated or unavailable. Modifying the audit policy requires a new review lifecycle. Policy deployment/removal requests may require restart and independent verification with CiTool and event logs.

Prepare recovery media and Microsoft's documented App Control recovery procedure before enforcement. The tool does not promise that it can run under every enforced policy.

References: [rule options](https://learn.microsoft.com/windows/security/threat-protection/windows-defender-application-control/select-types-of-rules-to-create), [audit events](https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/deployment/audit-appcontrol-policies), [CiTool](https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/operations/citool-commands).

## Protected Event Logging

Supply a valid public certificate with Document Encryption EKU and key/data encipherment usage. Keep the private key off the logging device, and test decryption on a separate collector. The tool neither generates nor collects private keys.

~~~powershell
.\Harden-Windows.ps1 -Action Plan -EncryptionCertificatePath .\collector-public.cer -RuleId security.enablescriptblocklogging
.\Harden-Windows.ps1 -Action Apply -EncryptionCertificatePath .\collector-public.cer -RuleId security.enablescriptblocklogging
~~~

Certificate configuration precedes Protected Event Logging, which precedes script logging. Existing logging is observed without attempting to disable it. PowerShell module logging also requires a separately reviewed ModuleNames configuration; its switch alone does not enable coverage of every module.

[Microsoft Protected Event Logging guidance](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_logging?view=powershell-5.1).

