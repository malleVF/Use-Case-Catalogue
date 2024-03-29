---
title: "Startup Items"
status: "test"
created: "2020/10/14"
last_modified: "2022/07/11"
tags: [persistence, privilege_escalation, t1037_005, detection_rule]
logsrc_product: "macos"
logsrc_service: ""
level: "low"
---

## Startup Items

### Description

Detects creation of startup item plist files that automatically get executed at boot initialization to establish persistence.

```yml
title: Startup Items
id: dfe8b941-4e54-4242-b674-6b613d521962
status: test
description: Detects creation of startup item plist files that automatically get executed at boot initialization to establish persistence.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1037.005/T1037.005.md
author: Alejandro Ortuno, oscd.community
date: 2020/10/14
modified: 2022/07/11
tags:
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1037.005
logsource:
    category: file_event
    product: macos
detection:
    selection:
        - TargetFilename|contains: '/Library/StartupItems/'
        - TargetFilename|endswith: '.plist'
    condition: selection
falsepositives:
    - Legitimate administration activities
level: low

```
