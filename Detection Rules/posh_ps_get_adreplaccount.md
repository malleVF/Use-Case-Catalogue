---
title: "Suspicious Get-ADReplAccount"
status: "test"
created: "2022/02/06"
last_modified: ""
tags: [credential_access, t1003_006, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Suspicious Get-ADReplAccount

### Description

The DSInternals PowerShell Module exposes several internal features of Active Directory and Azure Active Directory.
These include FIDO2 and NGC key auditing, offline ntds.dit file manipulation, password auditing, DC recovery from IFM backups and password hash calculation.


```yml
title: Suspicious Get-ADReplAccount
id: 060c3ef1-fd0a-4091-bf46-e7d625f60b73
status: test
description: |
    The DSInternals PowerShell Module exposes several internal features of Active Directory and Azure Active Directory.
    These include FIDO2 and NGC key auditing, offline ntds.dit file manipulation, password auditing, DC recovery from IFM backups and password hash calculation.
references:
    - https://www.powershellgallery.com/packages/DSInternals
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1003.006/T1003.006.md#atomic-test-2---run-dsinternals-get-adreplaccount
author: frack113
date: 2022/02/06
tags:
    - attack.credential_access
    - attack.t1003.006
logsource:
    product: windows
    category: ps_script
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    selection:
        ScriptBlockText|contains|all:
            - Get-ADReplAccount
            - '-All '
            - '-Server '
    condition: selection
falsepositives:
    - Legitimate PowerShell scripts
level: medium

```