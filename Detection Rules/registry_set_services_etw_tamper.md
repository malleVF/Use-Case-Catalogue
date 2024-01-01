---
title: "ETW Logging Disabled For SCM"
status: "experimental"
created: "2022/12/09"
last_modified: "2023/08/17"
tags: [defense_evasion, t1112, t1562, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "low"
---

## ETW Logging Disabled For SCM

### Description

Detects changes to the "TracingDisabled" key in order to disable ETW logging for services.exe (SCM)

```yml
title: ETW Logging Disabled For SCM
id: 4f281b83-0200-4b34-bf35-d24687ea57c2
status: experimental
description: Detects changes to the "TracingDisabled" key in order to disable ETW logging for services.exe (SCM)
references:
    - http://redplait.blogspot.com/2020/07/whats-wrong-with-etw.html
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/12/09
modified: 2023/08/17
tags:
    - attack.defense_evasion
    - attack.t1112
    - attack.t1562
logsource:
    product: windows
    category: registry_set
detection:
    selection:
        TargetObject|endswith: 'Software\Microsoft\Windows NT\CurrentVersion\Tracing\SCM\Regular\TracingDisabled'
        Details: 'DWORD (0x00000001)' # Funny (sad) enough, this value is by default 1.
    condition: selection
falsepositives:
    - Unknown
level: low

```