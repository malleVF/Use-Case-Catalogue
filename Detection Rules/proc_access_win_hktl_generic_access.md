---
title: "HackTool - Generic Process Access"
status: "experimental"
created: "2023/11/27"
last_modified: ""
tags: [credential_access, t1003_001, s0002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## HackTool - Generic Process Access

### Description

Detects process access requests from hacktool processes based on their default image name

```yml
title: HackTool - Generic Process Access
id: d0d2f720-d14f-448d-8242-51ff396a334e
status: experimental
description: Detects process access requests from hacktool processes based on their default image name
references:
    - https://jsecurity101.medium.com/bypassing-access-mask-auditing-strategies-480fb641c158
    - https://www.splunk.com/en_us/blog/security/you-bet-your-lsass-hunting-lsass-access.html
author: Nasreddine Bencherchali (Nextron Systems), Swachchhanda Shrawan Poudel
date: 2023/11/27
tags:
    - attack.credential_access
    - attack.t1003.001
    - attack.s0002
logsource:
    category: process_access
    product: windows
detection:
    selection:
        - SourceImage|endswith:
              - '\Akagi.exe'
              - '\Akagi64.exe'
              - '\atexec_windows.exe'
              - '\Certify.exe'
              - '\Certipy.exe'
              - '\CoercedPotato.exe'
              - '\crackmapexec.exe'
              - '\CreateMiniDump.exe'
              - '\dcomexec_windows.exe'
              - '\dpapi_windows.exe'
              - '\findDelegation_windows.exe'
              - '\GetADUsers_windows.exe'
              - '\GetNPUsers_windows.exe'
              - '\getPac_windows.exe'
              - '\getST_windows.exe'
              - '\getTGT_windows.exe'
              - '\GetUserSPNs_windows.exe'
              - '\gmer.exe'
              - '\hashcat.exe'
              - '\htran.exe'
              - '\ifmap_windows.exe'
              - '\impersonate.exe'
              - '\Inveigh.exe'
              - '\LocalPotato.exe'
              - '\mimikatz_windows.exe'
              - '\mimikatz.exe'
              - '\netview_windows.exe'
              - '\nmapAnswerMachine_windows.exe'
              - '\opdump_windows.exe'
              - '\PasswordDump.exe'
              - '\Potato.exe'
              - '\PowerTool.exe'
              - '\PowerTool64.exe'
              - '\psexec_windows.exe'
              - '\PurpleSharp.exe'
              - '\pypykatz.exe'
              - '\QuarksPwDump.exe'
              - '\rdp_check_windows.exe'
              - '\Rubeus.exe'
              - '\SafetyKatz.exe'
              - '\sambaPipe_windows.exe'
              - '\SelectMyParent.exe'
              - '\SharpChisel.exe'
              - '\SharPersist.exe'
              - '\SharpEvtMute.exe'
              - '\SharpImpersonation.exe'
              - '\SharpLDAPmonitor.exe'
              - '\SharpLdapWhoami.exe'
              - '\SharpUp.exe'
              - '\SharpView.exe'
              - '\smbclient_windows.exe'
              - '\smbserver_windows.exe'
              - '\sniff_windows.exe'
              - '\sniffer_windows.exe'
              - '\split_windows.exe'
              - '\SpoolSample.exe'
              - '\Stracciatella.exe'
              - '\SysmonEOP.exe'
              - '\temp\rot.exe'
              - '\ticketer_windows.exe'
              - '\TruffleSnout.exe'
              - '\winPEASany_ofs.exe'
              - '\winPEASany.exe'
              - '\winPEASx64_ofs.exe'
              - '\winPEASx64.exe'
              - '\winPEASx86_ofs.exe'
              - '\winPEASx86.exe'
              - '\xordump.exe'
        - SourceImage|contains:
              - '\goldenPac'
              - '\just_dce_'
              - '\karmaSMB'
              - '\kintercept'
              - '\LocalPotato'
              - '\ntlmrelayx'
              - '\rpcdump'
              - '\samrdump'
              - '\secretsdump'
              - '\smbexec'
              - '\smbrelayx'
              - '\wmiexec'
              - '\wmipersist'
              - 'HotPotato'
              - 'Juicy Potato'
              - 'JuicyPotato'
              - 'PetitPotam'
              - 'RottenPotato'
    condition: selection
falsepositives:
    - Unlikely
level: high

```