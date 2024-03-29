---
title: "Credential Manager Access By Uncommon Application"
status: "experimental"
created: "2022/10/11"
last_modified: "2023/12/18"
tags: [t1003, credential_access, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Credential Manager Access By Uncommon Application

### Description

Detects suspicious processes based on name and location that access the windows credential manager and vault.
Which can be a sign of credential stealing. Example case would be usage of mimikatz "dpapi::cred" function


```yml
title: Credential Manager Access By Uncommon Application
id: 407aecb1-e762-4acf-8c7b-d087bcff3bb6
status: experimental
description: |
    Detects suspicious processes based on name and location that access the windows credential manager and vault.
    Which can be a sign of credential stealing. Example case would be usage of mimikatz "dpapi::cred" function
references:
    - https://hunter2.gitbook.io/darthsidious/privilege-escalation/mimikatz
    - https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/10/11
modified: 2023/12/18
tags:
    - attack.t1003
    - attack.credential_access
logsource:
    category: file_access
    product: windows
    definition: 'Requirements: Microsoft-Windows-Kernel-File ETW provider'
detection:
    selection:
        FileName|contains:
            - '\AppData\Local\Microsoft\Credentials\'
            - '\AppData\Roaming\Microsoft\Credentials\'
            - '\AppData\Local\Microsoft\Vault\'
            - '\ProgramData\Microsoft\Vault\'
    filter_system_folders:
        Image|contains:
            - ':\Program Files\'
            - ':\Program Files (x86)\'
            - ':\Windows\system32\'
            - ':\Windows\SysWOW64\'
    condition: selection and not 1 of filter_*
falsepositives:
    - Legitimate software installed by the users for example in the "AppData" directory may access these files (for any reason).
# Increase level after false positives filters are good enough
level: medium

```
