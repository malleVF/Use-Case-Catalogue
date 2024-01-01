---
title: "PSScriptPolicyTest Creation By Uncommon Process"
status: "experimental"
created: "2023/06/01"
last_modified: "2023/12/11"
tags: [defense_evasion, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## PSScriptPolicyTest Creation By Uncommon Process

### Description

Detects the creation of the "PSScriptPolicyTest" PowerShell script by an uncommon process. This file is usually generated by Microsoft Powershell to test against Applocker.

```yml
title: PSScriptPolicyTest Creation By Uncommon Process
id: 1027d292-dd87-4a1a-8701-2abe04d7783c
status: experimental
description: Detects the creation of the "PSScriptPolicyTest" PowerShell script by an uncommon process. This file is usually generated by Microsoft Powershell to test against Applocker.
references:
    - https://www.paloaltonetworks.com/blog/security-operations/stopping-powershell-without-powershell/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/06/01
modified: 2023/12/11
tags:
    - attack.defense_evasion
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|contains: '__PSScriptPolicyTest_'
    filter_main_generic:
        Image|endswith:
            - ':\Program Files\PowerShell\7-preview\pwsh.exe'
            - ':\Program Files\PowerShell\7\pwsh.exe'
            - ':\Windows\System32\dsac.exe'
            - ':\Windows\System32\sdiagnhost.exe'
            - ':\Windows\System32\ServerManager.exe'
            - ':\Windows\System32\WindowsPowerShell\v1.0\powershell_ise.exe'
            - ':\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
            - ':\Windows\System32\wsmprovhost.exe'
            - ':\Windows\SysWOW64\sdiagnhost.exe'
            - ':\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell_ise.exe'
            - ':\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
level: medium

```