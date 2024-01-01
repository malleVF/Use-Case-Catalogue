---
title: "Silenttrinity Stager Msbuild Activity"
status: "test"
created: "2020/10/11"
last_modified: "2022/10/05"
tags: [execution, t1127_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Silenttrinity Stager Msbuild Activity

### Description

Detects a possible remote connections to Silenttrinity c2

```yml
title: Silenttrinity Stager Msbuild Activity
id: 50e54b8d-ad73-43f8-96a1-5191685b17a4
status: test
description: Detects a possible remote connections to Silenttrinity c2
references:
    - https://www.blackhillsinfosec.com/my-first-joyride-with-silenttrinity/
author: Kiran kumar s, oscd.community
date: 2020/10/11
modified: 2022/10/05
tags:
    - attack.execution
    - attack.t1127.001
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        Image|endswith: '\msbuild.exe'
    filter:
        DestinationPort:
            - 80
            - 443
        Initiated: 'true'
    condition: selection and filter
falsepositives:
    - Unknown
level: high

```
