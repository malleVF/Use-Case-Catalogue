---
title: "Potential Persistence Via Netsh Helper DLL"
status: "test"
created: "2019/10/25"
last_modified: "2023/11/28"
tags: [privilege_escalation, persistence, t1546_007, s0108, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Potential Persistence Via Netsh Helper DLL

### Description

Detects the execution of netsh with "add helper" flag in order to add a custom helper DLL. This technique can be abused to add a malicious helper DLL that can be used as a persistence proxy that gets called when netsh.exe is executed.


```yml
title: Potential Persistence Via Netsh Helper DLL
id: 56321594-9087-49d9-bf10-524fe8479452
related:
    - id: c90362e0-2df3-4e61-94fe-b37615814cb1
      type: similar
    - id: e7b18879-676e-4a0e-ae18-27039185a8e7
      type: similar
status: test
description: |
    Detects the execution of netsh with "add helper" flag in order to add a custom helper DLL. This technique can be abused to add a malicious helper DLL that can be used as a persistence proxy that gets called when netsh.exe is executed.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1546.007/T1546.007.md
    - https://github.com/outflanknl/NetshHelperBeacon
    - https://web.archive.org/web/20160928212230/https://www.adaptforward.com/2016/09/using-netshell-to-execute-evil-dlls-and-persist-on-a-host/
author: Victor Sergeev, oscd.community
date: 2019/10/25
modified: 2023/11/28
tags:
    - attack.privilege_escalation
    - attack.persistence
    - attack.t1546.007
    - attack.s0108
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - OriginalFileName: 'netsh.exe'
        - Image|endswith: '\netsh.exe'
    selection_cli:
        CommandLine|contains|all:
            - 'add'
            - 'helper'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium

```
