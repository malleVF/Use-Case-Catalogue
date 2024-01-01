---
title: "Systemd Service Reload or Start"
status: "test"
created: "2019/09/23"
last_modified: "2021/11/27"
tags: [persistence, t1543_002, detection_rule]
logsrc_product: "linux"
logsrc_service: "auditd"
level: "low"
---

## Systemd Service Reload or Start

### Description

Detects a reload or a start of a service.

```yml
title: Systemd Service Reload or Start
id: 2625cc59-0634-40d0-821e-cb67382a3dd7
status: test
description: Detects a reload or a start of a service.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1543.002/T1543.002.md
author: Jakob Weinzettl, oscd.community
date: 2019/09/23
modified: 2021/11/27
tags:
    - attack.persistence
    - attack.t1543.002
logsource:
    product: linux
    service: auditd
detection:
    selection:
        type: 'EXECVE'
        a0|contains: 'systemctl'
        a1|contains:
            - 'daemon-reload'
            - 'start'
    condition: selection
falsepositives:
    - Installation of legitimate service.
    - Legitimate reconfiguration of service.
level: low

```
