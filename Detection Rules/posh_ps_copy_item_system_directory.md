---
title: "Powershell Install a DLL in System Directory"
status: "test"
created: "2021/12/27"
last_modified: "2022/10/20"
tags: [credential_access, t1556_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Powershell Install a DLL in System Directory

### Description

Uses PowerShell to install/copy a a file into a system directory such as "System32" or "SysWOW64"

```yml
title: Powershell Install a DLL in System Directory
id: 63bf8794-9917-45bc-88dd-e1b5abc0ecfd
status: test
description: Uses PowerShell to install/copy a a file into a system directory such as "System32" or "SysWOW64"
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1556.002/T1556.002.md#atomic-test-1---install-and-register-password-filter-dll
author: frack113, Nasreddine Bencherchali
date: 2021/12/27
modified: 2022/10/20
tags:
    - attack.credential_access
    - attack.t1556.002
logsource:
    product: windows
    category: ps_script
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    selection_copy:
        ScriptBlockText|contains|all:
            - 'Copy-Item '
            - '-Destination '
    selection_paths:
        ScriptBlockText|contains:
            - '\Windows\System32'
            - '\Windows\SysWOW64'
    condition: all of selection*
falsepositives:
    - Unknown
level: high

```
