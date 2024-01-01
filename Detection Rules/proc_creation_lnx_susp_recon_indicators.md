---
title: "Linux Recon Indicators"
status: "test"
created: "2022/06/20"
last_modified: ""
tags: [reconnaissance, t1592_004, credential_access, t1552_001, detection_rule]
logsrc_product: "linux"
logsrc_service: ""
level: "high"
---

## Linux Recon Indicators

### Description

Detects events with patterns found in commands used for reconnaissance on linux systems

```yml
title: Linux Recon Indicators
id: 0cf7a157-8879-41a2-8f55-388dd23746b7
status: test
description: Detects events with patterns found in commands used for reconnaissance on linux systems
references:
    - https://github.com/sleventyeleven/linuxprivchecker/blob/0d701080bbf92efd464e97d71a70f97c6f2cd658/linuxprivchecker.py
author: Florian Roth (Nextron Systems)
date: 2022/06/20
tags:
    - attack.reconnaissance
    - attack.t1592.004
    - attack.credential_access
    - attack.t1552.001
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        CommandLine|contains:
            - ' -name .htpasswd'
            - ' -perm -4000 '
    condition: selection
falsepositives:
    - Legitimate administration activities
level: high

```
