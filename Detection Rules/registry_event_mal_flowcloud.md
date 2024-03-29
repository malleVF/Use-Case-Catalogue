---
title: "FlowCloud Malware"
status: "test"
created: "2020/06/09"
last_modified: "2022/10/09"
tags: [persistence, t1112, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "critical"
---

## FlowCloud Malware

### Description

Detects FlowCloud malware from threat group TA410.

```yml
title: FlowCloud Malware
id: 5118765f-6657-4ddb-a487-d7bd673abbf1
status: test
description: Detects FlowCloud malware from threat group TA410.
references:
    - https://www.proofpoint.com/us/blog/threat-insight/ta410-group-behind-lookback-attacks-against-us-utilities-sector-returns-new
author: NVISO
date: 2020/06/09
modified: 2022/10/09
tags:
    - attack.persistence
    - attack.t1112
logsource:
    product: windows
    category: registry_event
detection:
    selection:
        - TargetObject:
              - 'HKLM\HARDWARE\{804423C2-F490-4ac3-BFA5-13DEDE63A71A}'
              - 'HKLM\HARDWARE\{A5124AF5-DF23-49bf-B0ED-A18ED3DEA027}'
              - 'HKLM\HARDWARE\{2DB80286-1784-48b5-A751-B6ED1F490303}'
        - TargetObject|startswith: 'HKLM\SYSTEM\Setup\PrintResponsor\'
    condition: selection
falsepositives:
    - Unknown
level: critical

```
