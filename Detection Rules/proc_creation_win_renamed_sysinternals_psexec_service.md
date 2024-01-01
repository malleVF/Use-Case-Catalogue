---
title: "Renamed PsExec Service Execution"
status: "test"
created: "2022/07/21"
last_modified: ""
tags: [execution, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Renamed PsExec Service Execution

### Description

Detects suspicious launch of a renamed version of the PSEXESVC service with, which is not often used by legitimate administrators

```yml
title: Renamed PsExec Service Execution
id: 51ae86a2-e2e1-4097-ad85-c46cb6851de4
status: test
description: Detects suspicious launch of a renamed version of the PSEXESVC service with, which is not often used by legitimate administrators
references:
    - https://docs.microsoft.com/en-us/sysinternals/downloads/psexec
    - https://www.youtube.com/watch?v=ro2QuZTIMBM
author: Florian Roth (Nextron Systems)
date: 2022/07/21
tags:
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        OriginalFileName: 'psexesvc.exe'
    filter:
        Image: 'C:\Windows\PSEXESVC.exe'
    condition: selection and not filter
falsepositives:
    - Legitimate administrative tasks
level: high

```
