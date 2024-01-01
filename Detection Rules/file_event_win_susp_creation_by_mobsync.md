---
title: "Created Files by Microsoft Sync Center"
status: "test"
created: "2022/04/28"
last_modified: "2022/06/02"
tags: [t1055, t1218, execution, defense_evasion, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Created Files by Microsoft Sync Center

### Description

This rule detects suspicious files created by Microsoft Sync Center (mobsync)

```yml
title: Created Files by Microsoft Sync Center
id: 409f8a98-4496-4aaa-818a-c931c0a8b832
status: test
description: This rule detects suspicious files created by Microsoft Sync Center (mobsync)
references:
    - https://redcanary.com/blog/intelligence-insights-november-2021/
author: elhoim
date: 2022/04/28
modified: 2022/06/02
tags:
    - attack.t1055
    - attack.t1218
    - attack.execution
    - attack.defense_evasion
logsource:
    product: windows
    category: file_event
detection:
    selection_mobsync:
        Image|endswith: '\mobsync.exe'
    filter_created_file:
        TargetFilename|endswith:
            - '.dll'
            - '.exe'
    condition: selection_mobsync and filter_created_file
falsepositives:
    - Unknown
level: medium

```
