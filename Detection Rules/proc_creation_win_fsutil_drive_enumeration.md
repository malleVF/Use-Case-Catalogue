---
title: "Fsutil Drive Enumeration"
status: "test"
created: "2022/03/29"
last_modified: "2022/07/14"
tags: [discovery, t1120, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "low"
---

## Fsutil Drive Enumeration

### Description

Attackers may leverage fsutil to enumerated connected drives.

```yml
title: Fsutil Drive Enumeration
id: 63de06b9-a385-40b5-8b32-73f2b9ef84b6
status: test
description: Attackers may leverage fsutil to enumerated connected drives.
references:
    - Turla has used fsutil fsinfo drives to list connected drives.
    - https://github.com/elastic/detection-rules/blob/414d32027632a49fb239abb8fbbb55d3fa8dd861/rules/windows/discovery_peripheral_device.toml
author: Christopher Peacock '@securepeacock', SCYTHE '@scythe_io'
date: 2022/03/29
modified: 2022/07/14
tags:
    - attack.discovery
    - attack.t1120
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\fsutil.exe'
        - OriginalFileName: 'fsutil.exe'
    selection_cli:
        CommandLine|contains: 'drives'
    condition: all of selection_*
falsepositives:
    - Certain software or administrative tasks may trigger false positives.
level: low

```