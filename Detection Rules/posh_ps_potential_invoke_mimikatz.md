---
title: "Potential Invoke-Mimikatz PowerShell Script"
status: "test"
created: "2022/09/28"
last_modified: ""
tags: [credential_access, t1003, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Potential Invoke-Mimikatz PowerShell Script

### Description

Detects Invoke-Mimikatz PowerShell script and alike. Mimikatz is a credential dumper capable of obtaining plaintext Windows account logins and passwords.

```yml
title: Potential Invoke-Mimikatz PowerShell Script
id: 189e3b02-82b2-4b90-9662-411eb64486d4
status: test
description: Detects Invoke-Mimikatz PowerShell script and alike. Mimikatz is a credential dumper capable of obtaining plaintext Windows account logins and passwords.
references:
    - https://www.elastic.co/guide/en/security/current/potential-invoke-mimikatz-powershell-script.html#potential-invoke-mimikatz-powershell-script
author: Tim Rauch
date: 2022/09/28
tags:
    - attack.credential_access
    - attack.t1003
logsource:
    category: ps_script
    product: windows
detection:
    selection_1:
        ScriptBlockText|contains|all:
            - 'DumpCreds'
            - 'DumpCerts'
    selection_2:
        ScriptBlockText|contains: 'sekurlsa::logonpasswords'
    selection_3:
        ScriptBlockText|contains|all:
            - 'crypto::certificates'
            - 'CERT_SYSTEM_STORE_LOCAL_MACHINE'
    condition: 1 of selection*
falsepositives:
    - Mimikatz can be useful for testing the security of networks
level: high

```
