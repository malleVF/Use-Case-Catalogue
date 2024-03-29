---
title: "Unsigned Binary Loaded From Suspicious Location"
status: "test"
created: "2022/08/03"
last_modified: "2022/09/28"
tags: [defense_evasion, t1574_002, detection_rule]
logsrc_product: "windows"
logsrc_service: "security-mitigations"
level: "high"
---

## Unsigned Binary Loaded From Suspicious Location

### Description

Detects Code Integrity (CI) engine blocking processes from loading unsigned DLLs residing in suspicious locations

```yml
title: Unsigned Binary Loaded From Suspicious Location
id: 8289bf8c-4aca-4f5a-9db3-dc3d7afe5c10
status: test
description: Detects Code Integrity (CI) engine blocking processes from loading unsigned DLLs residing in suspicious locations
references:
    - https://github.com/nasbench/EVTX-ETW-Resources/blob/45fd5be71a51aa518b1b36d4e1f36af498084e27/ETWEventsList/CSV/Windows11/21H2/W11_21H2_Pro_20220719_22000.795/Providers/Microsoft-Windows-Security-Mitigations.csv
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/08/03
modified: 2022/09/28
tags:
    - attack.defense_evasion
    - attack.t1574.002
logsource:
    product: windows
    service: security-mitigations
detection:
    selection:
        EventID:
            - 11
            - 12
        ImageName|contains:
            - '\Users\Public\'
            - '\PerfLogs\'
            - '\Desktop\'
            - '\Downloads\'
            - '\AppData\Local\Temp\'
            - 'C:\Windows\TEMP\'
    condition: selection
falsepositives:
    - Unknown
level: high

```
