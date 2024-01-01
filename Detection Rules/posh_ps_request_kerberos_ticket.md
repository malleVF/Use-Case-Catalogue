---
title: "Request A Single Ticket via PowerShell"
status: "test"
created: "2021/12/28"
last_modified: ""
tags: [credential_access, t1558_003, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Request A Single Ticket via PowerShell

### Description

utilize native PowerShell Identity modules to query the domain to extract the Service Principal Names for a single computer.
This behavior is typically used during a kerberos or silver ticket attack.
A successful execution will output the SPNs for the endpoint in question.


```yml
title: Request A Single Ticket via PowerShell
id: a861d835-af37-4930-bcd6-5b178bfb54df
status: test
description: |
    utilize native PowerShell Identity modules to query the domain to extract the Service Principal Names for a single computer.
    This behavior is typically used during a kerberos or silver ticket attack.
    A successful execution will output the SPNs for the endpoint in question.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1558.003/T1558.003.md#atomic-test-4---request-a-single-ticket-via-powershell
author: frack113
date: 2021/12/28
tags:
    - attack.credential_access
    - attack.t1558.003
logsource:
    product: windows
    category: ps_script
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    selection:
        ScriptBlockText|contains: System.IdentityModel.Tokens.KerberosRequestorSecurityToken
    condition: selection
falsepositives:
    - Unknown
level: high

```