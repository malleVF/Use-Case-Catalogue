---
title: "Bypass UAC Using SilentCleanup Task"
status: "test"
created: "2022/01/06"
last_modified: "2023/08/17"
tags: [privilege_escalation, defense_evasion, t1548_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Bypass UAC Using SilentCleanup Task

### Description

There is an auto-elevated task called SilentCleanup located in %windir%\system32\cleanmgr.exe This can be abused to elevate any file with Administrator privileges without prompting UAC

```yml
title: Bypass UAC Using SilentCleanup Task
id: 724ea201-6514-4f38-9739-e5973c34f49a
status: test
description: There is an auto-elevated task called SilentCleanup located in %windir%\system32\cleanmgr.exe This can be abused to elevate any file with Administrator privileges without prompting UAC
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1548.002/T1548.002.md#atomic-test-9---bypass-uac-using-silentcleanup-task
    - https://www.reddit.com/r/hacking/comments/ajtrws/bypassing_highest_uac_level_windows_810/
author: frack113
date: 2022/01/06
modified: 2023/08/17
tags:
    - attack.privilege_escalation
    - attack.defense_evasion
    - attack.t1548.002
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|endswith: '\Environment\windir'
        Details|contains: '&REM'
    condition: selection
falsepositives:
    - Unknown
level: high

```
