---
title: "QuarksPwDump Clearing Access History"
status: "test"
created: "2017/05/15"
last_modified: "2022/04/14"
tags: [credential_access, t1003_002, detection_rule]
logsrc_product: "windows"
logsrc_service: "system"
level: "critical"
---

## QuarksPwDump Clearing Access History

### Description

Detects QuarksPwDump clearing access history in hive

```yml
title: QuarksPwDump Clearing Access History
id: 39f919f3-980b-4e6f-a975-8af7e507ef2b
status: test
description: Detects QuarksPwDump clearing access history in hive
author: Florian Roth (Nextron Systems)
date: 2017/05/15
modified: 2022/04/14
tags:
    - attack.credential_access
    - attack.t1003.002
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 16
        Provider_Name: Microsoft-Windows-Kernel-General
        HiveName|contains: '\AppData\Local\Temp\SAM'
        HiveName|endswith: '.dmp'
    condition: selection
falsepositives:
    - Unknown
level: critical

```
