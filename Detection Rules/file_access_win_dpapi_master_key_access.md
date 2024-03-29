---
title: "Access To Windows DPAPI Master Keys By Uncommon Application"
status: "experimental"
created: "2022/10/17"
last_modified: "2023/12/18"
tags: [credential_access, t1555_004, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Access To Windows DPAPI Master Keys By Uncommon Application

### Description

Detects file access requests to the the Windows Data Protection API Master keys by an uncommon application.
This can be a sign of credential stealing. Example case would be usage of mimikatz "dpapi::masterkey" function


```yml
title: Access To Windows DPAPI Master Keys By Uncommon Application
id: 46612ae6-86be-4802-bc07-39b59feb1309
status: experimental
description: |
    Detects file access requests to the the Windows Data Protection API Master keys by an uncommon application.
    This can be a sign of credential stealing. Example case would be usage of mimikatz "dpapi::masterkey" function
references:
    - http://blog.harmj0y.net/redteaming/operational-guidance-for-offensive-user-dpapi-abuse/
    - https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/dpapi-extracting-passwords
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
        FileName|contains:
            - '\Microsoft\Protect\S-1-5-18\' # For System32
            - '\Microsoft\Protect\S-1-5-21-' # For Users
    filter_system_folders:
        Image|contains:
            - ':\Program Files\'
            - ':\Program Files (x86)\'
            - ':\Windows\system32\'
            - ':\Windows\SysWOW64\'
    condition: selection and not 1 of filter_*
falsepositives:
    - Unknown
# Increase level after false positives filters are good enough
level: medium

```
