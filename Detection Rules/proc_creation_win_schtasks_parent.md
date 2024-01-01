---
title: "Suspicious Add Scheduled Task Parent"
status: "test"
created: "2022/02/23"
last_modified: "2022/06/02"
tags: [execution, t1053_005, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Suspicious Add Scheduled Task Parent

### Description

Detects suspicious scheduled task creations from a parent stored in a temporary folder

```yml
title: Suspicious Add Scheduled Task Parent
id: 9494479d-d994-40bf-a8b1-eea890237021
status: test
description: Detects suspicious scheduled task creations from a parent stored in a temporary folder
references:
    - https://app.any.run/tasks/649e7b46-9bec-4d05-98a5-dfa9a13eaae5/
author: Florian Roth (Nextron Systems)
date: 2022/02/23
modified: 2022/06/02
tags:
    - attack.execution
    - attack.t1053.005
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains: '/Create '
        ParentImage|contains:
            - '\AppData\Local\'
            - '\AppData\Roaming\'
            - '\Temporary Internet'
            - '\Users\Public\'
    filter:
        CommandLine|contains:
            - 'update_task.xml'
            - 'unattended.ini'
    condition: selection and not 1 of filter*
falsepositives:
    - Software installers that run from temporary folders and also install scheduled tasks
level: medium

```