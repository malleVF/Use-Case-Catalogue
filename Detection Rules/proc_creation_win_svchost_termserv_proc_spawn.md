---
title: "Terminal Service Process Spawn"
status: "test"
created: "2019/05/22"
last_modified: "2023/01/25"
tags: [initial_access, t1190, lateral_movement, t1210, car_2013-07-002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Terminal Service Process Spawn

### Description

Detects a process spawned by the terminal service server process (this could be an indicator for an exploitation of CVE-2019-0708)

```yml
title: Terminal Service Process Spawn
id: 1012f107-b8f1-4271-af30-5aed2de89b39
status: test
description: Detects a process spawned by the terminal service server process (this could be an indicator for an exploitation of CVE-2019-0708)
references:
    - https://securingtomorrow.mcafee.com/other-blogs/mcafee-labs/rdp-stands-for-really-do-patch-understanding-the-wormable-rdp-vulnerability-cve-2019-0708/
author: Florian Roth (Nextron Systems)
date: 2019/05/22
modified: 2023/01/25
tags:
    - attack.initial_access
    - attack.t1190
    - attack.lateral_movement
    - attack.t1210
    - car.2013-07-002
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        ParentCommandLine|contains|all:
            - '\svchost.exe'
            - 'termsvcs'
    filter_img:
        Image|endswith:
            - '\rdpclip.exe'
            - ':\Windows\System32\csrss.exe'
            - ':\Windows\System32\wininit.exe'
            - ':\Windows\System32\winlogon.exe'
    filter_null:
        Image: null
    condition: selection and not 1 of filter_*
falsepositives:
    - Unknown
level: high

```
