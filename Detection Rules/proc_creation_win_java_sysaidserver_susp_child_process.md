---
title: "Suspicious SysAidServer Child"
status: "test"
created: "2022/08/26"
last_modified: ""
tags: [lateral_movement, t1210, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Suspicious SysAidServer Child

### Description

Detects suspicious child processes of SysAidServer (as seen in MERCURY threat actor intrusions)

```yml
title: Suspicious SysAidServer Child
id: 60bfeac3-0d35-4302-8efb-1dd16f715bc6
status: test
description: Detects suspicious child processes of SysAidServer (as seen in MERCURY threat actor intrusions)
references:
    - https://www.microsoft.com/security/blog/2022/08/25/mercury-leveraging-log4j-2-vulnerabilities-in-unpatched-systems-to-target-israeli-organizations/
author: Florian Roth (Nextron Systems)
date: 2022/08/26
tags:
    - attack.lateral_movement
    - attack.t1210
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith:
            - '\java.exe'
            - '\javaw.exe'
        ParentCommandLine|contains: 'SysAidServer'
    condition: selection
falsepositives:
    - Unknown
level: medium

```
