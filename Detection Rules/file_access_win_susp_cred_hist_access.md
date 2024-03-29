---
title: "Access To Windows Credential History File By Uncommon Application"
status: "experimental"
created: "2022/10/17"
last_modified: "2023/12/18"
tags: [credential_access, t1555_004, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Access To Windows Credential History File By Uncommon Application

### Description

Detects file access requests to the Windows Credential History File by an uncommon application.
This can be a sign of credential stealing. Example case would be usage of mimikatz "dpapi::credhist" function


```yml
title: Access To Windows Credential History File By Uncommon Application
id: 7a2a22ea-a203-4cd3-9abf-20eb1c5c6cd2
status: experimental
description: |
    Detects file access requests to the Windows Credential History File by an uncommon application.
    This can be a sign of credential stealing. Example case would be usage of mimikatz "dpapi::credhist" function
references:
    - https://tools.thehacker.recipes/mimikatz/modules/dpapi/credhist
    - https://www.passcape.com/windows_password_recovery_dpapi_credhist
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/10/17
modified: 2023/12/18
tags:
    - attack.credential_access
    - attack.t1555.004
logsource:
    category: file_access
    product: windows
    definition: 'Requirements: Microsoft-Windows-Kernel-File ETW provider'
detection:
    selection:
        FileName|endswith: '\Microsoft\Protect\CREDHIST'
    filter_main_system_folders:
        Image|contains:
            - ':\Program Files\'
            - ':\Program Files (x86)\'
            - ':\Windows\system32\'
            - ':\Windows\SysWOW64\'
    filter_main_explorer:
        Image|endswith: ':\Windows\explorer.exe'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
# Increase level after false positives filters are good enough
level: medium

```
