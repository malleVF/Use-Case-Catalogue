---
title: "Screen Capture with Import Tool"
status: "test"
created: "2021/09/21"
last_modified: "2022/10/09"
tags: [collection, t1113, detection_rule]
logsrc_product: "linux"
logsrc_service: "auditd"
level: "low"
---

## Screen Capture with Import Tool

### Description

Detects adversary creating screen capture of a desktop with Import Tool.
Highly recommended using rule on servers, due to high usage of screenshot utilities on user workstations.
ImageMagick must be installed.


```yml
title: Screen Capture with Import Tool
id: dbe4b9c5-c254-4258-9688-d6af0b7967fd
status: test
description: |
  Detects adversary creating screen capture of a desktop with Import Tool.
  Highly recommended using rule on servers, due to high usage of screenshot utilities on user workstations.
  ImageMagick must be installed.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1113/T1113.md
    - https://linux.die.net/man/1/import
    - https://imagemagick.org/
author: 'Pawel Mazur'
date: 2021/09/21
modified: 2022/10/09
tags:
    - attack.collection
    - attack.t1113
logsource:
    product: linux
    service: auditd
detection:
    import:
        type: EXECVE
        a0: import
    import_window_root:
        a1: '-window'
        a2: 'root'
        a3|endswith:
            - '.png'
            - '.jpg'
            - '.jpeg'
    import_no_window_root:
        a1|endswith:
            - '.png'
            - '.jpg'
            - '.jpeg'
    condition: import and (import_window_root or import_no_window_root)
falsepositives:
    - Legitimate use of screenshot utility
level: low

```
