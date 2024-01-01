---
title: "Suspicious Scheduled Task Write to System32 Tasks"
status: "test"
created: "2021/11/16"
last_modified: "2022/01/12"
tags: [persistence, execution, t1053, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Suspicious Scheduled Task Write to System32 Tasks

### Description

Detects the creation of tasks from processes executed from suspicious locations

```yml
title: Suspicious Scheduled Task Write to System32 Tasks
id: 80e1f67a-4596-4351-98f5-a9c3efabac95
status: test
description: Detects the creation of tasks from processes executed from suspicious locations
references:
    - Internal Research
author: Florian Roth (Nextron Systems)
date: 2021/11/16
modified: 2022/01/12
tags:
    - attack.persistence
    - attack.execution
    - attack.t1053
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|contains: '\Windows\System32\Tasks'
        Image|contains:
            - '\AppData\'
            - 'C:\PerfLogs'
            - '\Windows\System32\config\systemprofile'
    condition: selection
falsepositives:
    - Unknown
level: high

```
