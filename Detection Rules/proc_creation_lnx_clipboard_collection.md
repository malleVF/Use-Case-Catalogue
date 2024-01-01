---
title: "Clipboard Collection with Xclip Tool"
status: "test"
created: "2021/10/15"
last_modified: "2022/09/15"
tags: [collection, t1115, detection_rule]
logsrc_product: "linux"
logsrc_service: ""
level: "low"
---

## Clipboard Collection with Xclip Tool

### Description

Detects attempts to collect data stored in the clipboard from users with the usage of xclip tool. Xclip has to be installed.
Highly recommended using rule on servers, due to high usage of clipboard utilities on user workstations.


```yml
title: Clipboard Collection with Xclip Tool
id: ec127035-a636-4b9a-8555-0efd4e59f316
status: test
description: |
    Detects attempts to collect data stored in the clipboard from users with the usage of xclip tool. Xclip has to be installed.
    Highly recommended using rule on servers, due to high usage of clipboard utilities on user workstations.
references:
    - https://www.packetlabs.net/posts/clipboard-data-security/
author: Pawel Mazur, Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research), MSTIC
date: 2021/10/15
modified: 2022/09/15
tags:
    - attack.collection
    - attack.t1115
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|contains: 'xclip'
        CommandLine|contains|all:
            - '-sel'
            - 'clip'
            - '-o'
    condition: selection
falsepositives:
    - Legitimate usage of xclip tools.
level: low

```