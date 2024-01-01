---
title: "Sysmon Crash"
status: "test"
created: "2022/04/26"
last_modified: ""
tags: [defense_evasion, t1562, detection_rule]
logsrc_product: "windows"
logsrc_service: "system"
level: "high"
---

## Sysmon Crash

### Description

Detects application popup reporting a failure of the Sysmon service

```yml
title: Sysmon Crash
id: 4d7f1827-1637-4def-8d8a-fd254f9454df
status: test
description: Detects application popup reporting a failure of the Sysmon service
author: Tim Shelton
date: 2022/04/26
tags:
    - attack.defense_evasion
    - attack.t1562
logsource:
    product: windows
    service: system
detection:
    selection:
        Provider_Name: 'Application Popup'
        EventID: 26
        Caption: 'sysmon64.exe - Application Error'
    condition: selection
falsepositives:
    - Unknown
level: high

```
