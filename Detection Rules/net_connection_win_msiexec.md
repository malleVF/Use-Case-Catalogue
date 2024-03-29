---
title: "Msiexec Initiated Connection"
status: "test"
created: "2022/01/16"
last_modified: ""
tags: [defense_evasion, t1218_007, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Msiexec Initiated Connection

### Description

Adversaries may abuse msiexec.exe to proxy execution of malicious payloads.
Msiexec.exe is the command-line utility for the Windows Installer and is thus commonly associated with executing installation packages (.msi)


```yml
title: Msiexec Initiated Connection
id: 8e5e38e4-5350-4c0b-895a-e872ce0dd54f
status: test
description: |
    Adversaries may abuse msiexec.exe to proxy execution of malicious payloads.
    Msiexec.exe is the command-line utility for the Windows Installer and is thus commonly associated with executing installation packages (.msi)
references:
    - https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/msiexec
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1218.007/T1218.007.md
author: frack113
date: 2022/01/16
tags:
    - attack.defense_evasion
    - attack.t1218.007
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        Initiated: 'true'
        Image|endswith: '\msiexec.exe'
    condition: selection
falsepositives:
    - Legitimate msiexec over networks
level: medium

```
