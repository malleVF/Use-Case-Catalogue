---
title: "COM Hijack via Sdclt"
status: "test"
created: "2020/09/27"
last_modified: "2023/09/28"
tags: [privilege_escalation, t1546, t1548, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## COM Hijack via Sdclt

### Description

Detects changes to 'HKCU\Software\Classes\Folder\shell\open\command\DelegateExecute'

```yml
title: COM Hijack via Sdclt
id: 07743f65-7ec9-404a-a519-913db7118a8d
status: test
description: Detects changes to 'HKCU\Software\Classes\Folder\shell\open\command\DelegateExecute'
references:
    - http://blog.sevagas.com/?Yet-another-sdclt-UAC-bypass
    - https://www.exploit-db.com/exploits/47696
author: Omkar Gudhate
date: 2020/09/27
modified: 2023/09/28
tags:
    - attack.privilege_escalation
    - attack.t1546
    - attack.t1548
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains: '\Software\Classes\Folder\shell\open\command\DelegateExecute'
    condition: selection
falsepositives:
    - Unknown
level: high

```
