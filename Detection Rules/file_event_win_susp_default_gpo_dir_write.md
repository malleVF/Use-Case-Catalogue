---
title: "Suspicious Files in Default GPO Folder"
status: "test"
created: "2022/04/28"
last_modified: ""
tags: [t1036_005, defense_evasion, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Suspicious Files in Default GPO Folder

### Description

Detects the creation of copy of suspicious files (EXE/DLL) to the default GPO storage folder

```yml
title: Suspicious Files in Default GPO Folder
id: 5f87308a-0a5b-4623-ae15-d8fa1809bc60
status: test
description: Detects the creation of copy of suspicious files (EXE/DLL) to the default GPO storage folder
references:
    - https://redcanary.com/blog/intelligence-insights-november-2021/
author: elhoim
date: 2022/04/28
tags:
    - attack.t1036.005
    - attack.defense_evasion
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|contains: '\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\'
        TargetFilename|endswith:
            - '.dll'
            - '.exe'
    condition: selection
falsepositives:
    - Unknown
level: medium

```