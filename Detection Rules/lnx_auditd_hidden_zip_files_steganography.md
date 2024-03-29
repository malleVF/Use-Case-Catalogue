---
title: "Steganography Hide Zip Information in Picture File"
status: "test"
created: "2021/09/09"
last_modified: "2022/10/09"
tags: [defense_evasion, t1027_003, detection_rule]
logsrc_product: "linux"
logsrc_service: "auditd"
level: "low"
---

## Steganography Hide Zip Information in Picture File

### Description

Detects appending of zip file to image

```yml
title: Steganography Hide Zip Information in Picture File
id: 45810b50-7edc-42ca-813b-bdac02fb946b
status: test
description: Detects appending of zip file to image
references:
    - https://zerotoroot.me/steganography-hiding-a-zip-in-a-jpeg-file/
author: 'Pawel Mazur'
date: 2021/09/09
modified: 2022/10/09
tags:
    - attack.defense_evasion
    - attack.t1027.003
logsource:
    product: linux
    service: auditd
detection:
    commands:
        type: EXECVE
        a0: cat
    a1:
        a1|endswith:
            - '.jpg'
            - '.png'
    a2:
        a2|endswith: '.zip'
    condition: commands and a1 and a2
falsepositives:
    - Unknown
level: low

```
