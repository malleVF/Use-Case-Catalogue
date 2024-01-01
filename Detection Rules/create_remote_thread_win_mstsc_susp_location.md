---
title: "Remote Thread Creation In Mstsc.Exe From Suspicious Location"
status: "experimental"
created: "2023/07/28"
last_modified: ""
tags: [credential_access, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Remote Thread Creation In Mstsc.Exe From Suspicious Location

### Description

Detects remote thread creation in the "mstsc.exe" process by a process located in a potentially suspicious location.
This technique is often used by attackers in order to hook some APIs used by DLLs loaded by "mstsc.exe" during RDP authentications in order to steal credentials.


```yml
title: Remote Thread Creation In Mstsc.Exe From Suspicious Location
id: c0aac16a-b1e7-4330-bab0-3c27bb4987c7
status: experimental
description: |
    Detects remote thread creation in the "mstsc.exe" process by a process located in a potentially suspicious location.
    This technique is often used by attackers in order to hook some APIs used by DLLs loaded by "mstsc.exe" during RDP authentications in order to steal credentials.
references:
    - https://github.com/S12cybersecurity/RDPCredentialStealer/blob/1b8947cdd065a06c1b62e80967d3c7af895fcfed/APIHookInjectorBin/APIHookInjectorBin/Inject.h#L25
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/07/28
tags:
    - attack.credential_access
logsource:
    product: windows
    category: create_remote_thread
detection:
    selection:
        TargetImage|endswith: '\mstsc.exe'
        SourceImage|contains:
            - ':\Users\Public\'
            - ':\Windows\PerfLogs\'
            - ':\Windows\Tasks\'
            - ':\Temp\'
            - ':\Windows\Temp\'
            - ':\AppData\Local\Temp\'
    condition: selection
falsepositives:
    - Unknown
level: high

```