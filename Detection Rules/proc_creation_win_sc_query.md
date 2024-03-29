---
title: "SC.EXE Query Execution"
status: "test"
created: "2021/12/06"
last_modified: "2022/11/10"
tags: [discovery, t1007, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "low"
---

## SC.EXE Query Execution

### Description

Detects execution of "sc.exe" to query information about registered services on the system

```yml
title: SC.EXE Query Execution
id: 57712d7a-679c-4a41-a913-87e7175ae429
status: test
description: Detects execution of "sc.exe" to query information about registered services on the system
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1007/T1007.md#atomic-test-1---system-service-discovery
author: frack113
date: 2021/12/06
modified: 2022/11/10
tags:
    - attack.discovery
    - attack.t1007
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        Image|endswith: '\sc.exe'
        OriginalFileName|endswith: 'sc.exe'
    selection_cli:
        CommandLine|contains: ' query'
    condition: all of selection_*
falsepositives:
    - Legitimate query of a service by an administrator to get more information such as the state or PID
    - Keybase process "kbfsdokan.exe" query the dokan1 service with the following commandline "sc query dokan1"
level: low

```
