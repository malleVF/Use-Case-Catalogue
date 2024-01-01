---
title: "Malicious PowerShell Commandlets - PoshModule"
status: "test"
created: "2023/01/20"
last_modified: "2023/04/17"
tags: [execution, discovery, t1482, t1087, t1087_001, t1087_002, t1069_001, t1069_002, t1069, t1059_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Malicious PowerShell Commandlets - PoshModule

### Description

Detects Commandlet names from well-known PowerShell exploitation frameworks

```yml
title: Malicious PowerShell Commandlets - PoshModule
id: 7d0d0329-0ef1-4e84-a9f5-49500f9d7c6c
related:
    - id: 89819aa4-bbd6-46bc-88ec-c7f7fe30efa6
      type: similar
    - id: 02030f2f-6199-49ec-b258-ea71b07e03dc
      type: similar
status: test
description: Detects Commandlet names from well-known PowerShell exploitation frameworks
references:
    - https://adsecurity.org/?p=2921
    - https://github.com/S3cur3Th1sSh1t/PowerSharpPack/tree/master/PowerSharpBinaries
    - https://github.com/BC-SECURITY/Invoke-ZeroLogon/blob/111d17c7fec486d9bb23387e2e828b09a26075e4/Invoke-ZeroLogon.ps1
    - https://github.com/xorrior/RandomPS-Scripts/blob/848c919bfce4e2d67b626cbcf4404341cfe3d3b6/Get-DXWebcamVideo.ps1
    - https://github.com/rvrsh3ll/Misc-Powershell-Scripts/blob/6f23bb41f9675d7e2d32bacccff75e931ae00554/OfficeMemScraper.ps1
    - https://github.com/dafthack/DomainPasswordSpray/blob/b13d64a5834694aa73fd2aea9911a83027c465a7/DomainPasswordSpray.ps1
    - https://unit42.paloaltonetworks.com/threat-assessment-black-basta-ransomware/ # Invoke-TotalExec
    - https://research.nccgroup.com/2022/06/06/shining-the-light-on-black-basta/ # Invoke-TotalExec
    - https://github.com/calebstewart/CVE-2021-1675 # Invoke-Nightmare
    - https://github.com/BloodHoundAD/BloodHound/blob/0927441f67161cc6dc08a53c63ceb8e333f55874/Collectors/AzureHound.ps1
    - https://bloodhound.readthedocs.io/en/latest/data-collection/azurehound.html
    - https://github.com/HarmJ0y/DAMP
    - https://github.com/samratashok/nishang
    - https://github.com/DarkCoderSc/PowerRunAsSystem/
    - https://github.com/besimorhino/powercat
    - https://github.com/Kevin-Robertson/Powermad
    - https://github.com/adrecon/ADRecon
    - https://github.com/adrecon/AzureADRecon
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/01/20
modified: 2023/04/17
tags:
    - attack.execution
    - attack.discovery
    - attack.t1482
    - attack.t1087
    - attack.t1087.001
    - attack.t1087.002
    - attack.t1069.001
    - attack.t1069.002
    - attack.t1069
    - attack.t1059.001
logsource:
    product: windows
    category: ps_module
    definition: 0ad03ef1-f21b-4a79-8ce8-e6900c54b65b
detection:
    selection:
        Payload|contains:
            # Note: Please ensure alphabetical order when adding new entries
            - 'Add-Exfiltration'
            - 'Add-Persistence'
            - 'Add-RegBackdoor'
            - 'Add-RemoteRegBackdoor'
            - 'Add-ScrnSaveBackdoor'
            - 'Check-VM'
            - 'ConvertTo-Rc4ByteStream'
            - 'Decrypt-Hash'
            - 'Disable-ADIDNSNode'
            - 'Disable-MachineAccount'
            - 'Do-Exfiltration'
            - 'Enable-ADIDNSNode'
            - 'Enable-MachineAccount'
            - 'Enabled-DuplicateToken'
            - 'Exploit-Jboss'
            - 'Export-ADR' # # ADRecon related cmdlets
            - 'Export-ADRCSV' # # ADRecon related cmdlets
            - 'Export-ADRExcel' # # ADRecon related cmdlets
            - 'Export-ADRHTML' # # ADRecon related cmdlets
            - 'Export-ADRJSON' # # ADRecon related cmdlets
            - 'Export-ADRXML' # # ADRecon related cmdlets
            - 'Find-Fruit'
            - 'Find-GPOLocation'
            - 'Find-TrustedDocuments'
            - 'Get-ADIDNS' # Covers: Get-ADIDNSNodeAttribute, Get-ADIDNSNodeOwner, Get-ADIDNSNodeTombstoned, Get-ADIDNSPermission, Get-ADIDNSZone
            - 'Get-ApplicationHost'
            - 'Get-ChromeDump'
            - 'Get-ClipboardContents'
            - 'Get-FoxDump'
            - 'Get-GPPPassword'
            - 'Get-IndexedItem'
            - 'Get-KerberosAESKey'
            - 'Get-Keystrokes'
            - 'Get-LSASecret'
            - 'Get-MachineAccountAttribute'
            - 'Get-MachineAccountCreator'
            - 'Get-PassHashes'
            - 'Get-RegAlwaysInstallElevated'
            - 'Get-RegAutoLogon'
            - 'Get-RemoteBootKey'
            - 'Get-RemoteCachedCredential'
            - 'Get-RemoteLocalAccountHash'
            - 'Get-RemoteLSAKey'
            - 'Get-RemoteMachineAccountHash'
            - 'Get-RemoteNLKMKey'
            - 'Get-RickAstley'
            - 'Get-Screenshot'
            - 'Get-SecurityPackages'
            - 'Get-ServiceFilePermission'
            - 'Get-ServicePermission'
            - 'Get-ServiceUnquoted'
            - 'Get-SiteListPassword'
            - 'Get-System'
            - 'Get-TimedScreenshot'
            - 'Get-UnattendedInstallFile'
            - 'Get-Unconstrained'
            - 'Get-USBKeystrokes'
            - 'Get-VaultCredential'
            - 'Get-VulnAutoRun'
            - 'Get-VulnSchTask'
            - 'Grant-ADIDNSPermission'
            - 'Gupt-Backdoor'
            - 'HTTP-Login'
            - 'Install-ServiceBinary'
            - 'Install-SSP'
            - 'Invoke-ACLScanner'
            - 'Invoke-ADRecon' # # ADRecon related cmdlets
            - 'Invoke-ADSBackdoor'
            - 'Invoke-AgentSmith'
            - 'Invoke-AllChecks'
            - 'Invoke-ARPScan'
            - 'Invoke-AzureHound'
            - 'Invoke-BackdoorLNK'
            - 'Invoke-BadPotato'
            - 'Invoke-BetterSafetyKatz'
            - 'Invoke-BypassUAC'
            - 'Invoke-Carbuncle'
            - 'Invoke-Certify'
            - 'Invoke-ConPtyShell'
            - 'Invoke-CredentialInjection'
            - 'Invoke-DAFT'
            - 'Invoke-DCSync'
            - 'Invoke-DinvokeKatz'
            - 'Invoke-DllInjection'
            - 'Invoke-DNSUpdate'
            - 'Invoke-DomainPasswordSpray'
            - 'Invoke-DowngradeAccount'
            - 'Invoke-EgressCheck'
            - 'Invoke-Eyewitness'
            - 'Invoke-FakeLogonScreen'
            - 'Invoke-Farmer'
            - 'Invoke-Get-RBCD-Threaded'
            - 'Invoke-Gopher'
            - 'Invoke-Grouper' # Also Covers Invoke-GrouperX
            - 'Invoke-HandleKatz'
            - 'Invoke-ImpersonatedProcess'
            - 'Invoke-ImpersonateSystem'
            - 'Invoke-InteractiveSystemPowerShell'
            - 'Invoke-Internalmonologue'
            - 'Invoke-Inveigh'
            - 'Invoke-InveighRelay'
            - 'Invoke-KrbRelay'
            - 'Invoke-LdapSignCheck'
            - 'Invoke-Lockless'
            - 'Invoke-MalSCCM'
            - 'Invoke-Mimikatz'
            - 'Invoke-Mimikittenz'
            - 'Invoke-MITM6'
            - 'Invoke-NanoDump'
            - 'Invoke-NetRipper'
            - 'Invoke-Nightmare'
            - 'Invoke-NinjaCopy'
            - 'Invoke-OfficeScrape'
            - 'Invoke-OxidResolver'
            - 'Invoke-P0wnedshell'
            - 'Invoke-Paranoia'
            - 'Invoke-PortScan'
            - 'Invoke-PoshRatHttp' # Also Covers Invoke-PoshRatHttps
            - 'Invoke-PostExfil'
            - 'Invoke-PowerDump'
            - 'Invoke-PowerShellTCP'
            - 'Invoke-PowerShellWMI'
            - 'Invoke-PPLDump'
            - 'Invoke-PsExec'
            - 'Invoke-PSInject'
            - 'Invoke-PsUaCme'
            - 'Invoke-ReflectivePEInjection'
            - 'Invoke-ReverseDNSLookup'
            - 'Invoke-Rubeus'
            - 'Invoke-RunAs'
            - 'Invoke-SafetyKatz'
            - 'Invoke-SauronEye'
            - 'Invoke-SCShell'
            - 'Invoke-Seatbelt'
            - 'Invoke-ServiceAbuse'
            - 'Invoke-ShadowSpray'
            - 'Invoke-Sharp' # Covers all "Invoke-Sharp" variants
            - 'Invoke-Shellcode'
            - 'Invoke-SMBScanner'
            - 'Invoke-Snaffler'
            - 'Invoke-Spoolsample'
            - 'Invoke-SpraySinglePassword'
            - 'Invoke-SSHCommand'
            - 'Invoke-StandIn'
            - 'Invoke-StickyNotesExtract'
            - 'Invoke-SystemCommand'
            - 'Invoke-Tasksbackdoor'
            - 'Invoke-Tater'
            - 'Invoke-Thunderfox'
            - 'Invoke-ThunderStruck'
            - 'Invoke-TokenManipulation'
            - 'Invoke-Tokenvator'
            - 'Invoke-TotalExec'
            - 'Invoke-UrbanBishop'
            - 'Invoke-UserHunter'
            - 'Invoke-VoiceTroll'
            - 'Invoke-Whisker'
            - 'Invoke-WinEnum'
            - 'Invoke-winPEAS'
            - 'Invoke-WireTap'
            - 'Invoke-WmiCommand'
            - 'Invoke-WMIExec'
            - 'Invoke-WScriptBypassUAC'
            - 'Invoke-Zerologon'
            - 'MailRaider'
            - 'New-ADIDNSNode'
            - 'New-DNSRecordArray'
            - 'New-HoneyHash'
            - 'New-InMemoryModule'
            - 'New-MachineAccount'
            - 'New-SOASerialNumberArray'
            - 'Out-Minidump'
            - 'Port-Scan'
            - 'PowerBreach'
            - 'powercat '
            - 'PowerUp'
            - 'PowerView'
            - 'Remove-ADIDNSNode'
            - 'Remove-MachineAccount'
            - 'Remove-Update'
            - 'Rename-ADIDNSNode'
            - 'Revoke-ADIDNSPermission'
            - 'Set-ADIDNSNode' # Covers: Set-ADIDNSNodeAttribute, Set-ADIDNSNodeOwner
            - 'Set-MacAttribute'
            - 'Set-MachineAccountAttribute'
            - 'Set-Wallpaper'
            - 'Show-TargetScreen'
            - 'Start-CaptureServer'
            - 'Start-WebcamRecorder'
            - 'VolumeShadowCopyTools'
    condition: selection
falsepositives:
    - Unknown
level: high

```