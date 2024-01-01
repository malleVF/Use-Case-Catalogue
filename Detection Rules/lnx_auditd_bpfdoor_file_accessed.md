---
title: "BPFDoor Abnormal Process ID or Lock File Accessed"
status: "test"
created: "2022/08/10"
last_modified: ""
tags: [execution, t1106, t1059, detection_rule]
logsrc_product: "linux"
logsrc_service: "auditd"
level: "high"
---

## BPFDoor Abnormal Process ID or Lock File Accessed

### Description

detects BPFDoor .lock and .pid files access in temporary file storage facility

```yml
title: BPFDoor Abnormal Process ID or Lock File Accessed
id: 808146b2-9332-4d78-9416-d7e47012d83d
status: test
description: detects BPFDoor .lock and .pid files access in temporary file storage facility
references:
    - https://www.sandflysecurity.com/blog/bpfdoor-an-evasive-linux-backdoor-technical-analysis/
    - https://www.elastic.co/security-labs/a-peek-behind-the-bpfdoor
author: Rafal Piasecki
date: 2022/08/10
tags:
    - attack.execution
    - attack.t1106
    - attack.t1059
logsource:
    product: linux
    service: auditd
detection:
    selection:
        type: 'PATH'
        name:
            - /var/run/haldrund.pid
            - /var/run/xinetd.lock
            - /var/run/kdevrund.pid
    condition: selection
falsepositives:
    - Unlikely
level: high

```
