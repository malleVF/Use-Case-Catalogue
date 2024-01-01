---
title: "Steganography Extract Files with Steghide"
status: "test"
created: "2021/09/11"
last_modified: "2022/10/09"
tags: [defense_evasion, t1027_003, detection_rule]
logsrc_product: "linux"
logsrc_service: "auditd"
level: "low"
---

## Steganography Extract Files with Steghide

### Description

Detects extraction of files with usage of steghide binary, the adversaries may use this technique to prevent the detection of hidden information.

```yml
title: Steganography Extract Files with Steghide
id: a5a827d9-1bbe-4952-9293-c59d897eb41b
status: test
description: Detects extraction of files with usage of steghide binary, the adversaries may use this technique to prevent the detection of hidden information.
references:
    - https://vitux.com/how-to-hide-confidential-files-in-images-on-debian-using-steganography/
author: 'Pawel Mazur'
date: 2021/09/11
modified: 2022/10/09
tags:
    - attack.defense_evasion
    - attack.t1027.003
logsource:
    product: linux
    service: auditd
detection:
    selection:
        type: EXECVE
        a0: steghide
        a1: extract
        a2: '-sf'
        a3|endswith:
            - '.jpg'
            - '.png'
    condition: selection
falsepositives:
    - Unknown
level: low

```
