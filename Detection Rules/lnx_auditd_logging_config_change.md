---
title: "Logging Configuration Changes on Linux Host"
status: "test"
created: "2019/10/25"
last_modified: "2021/11/27"
tags: [defense_evasion, t1562_006, detection_rule]
logsrc_product: "linux"
logsrc_service: "auditd"
level: "high"
---

## Logging Configuration Changes on Linux Host

### Description

Detect changes of syslog daemons configuration files

```yml
title: Logging Configuration Changes on Linux Host
id: c830f15d-6f6e-430f-8074-6f73d6807841
status: test
description: Detect changes of syslog daemons configuration files
references:
    - self experience
author: Mikhail Larin, oscd.community
date: 2019/10/25
modified: 2021/11/27
tags:
    - attack.defense_evasion
    - attack.t1562.006
logsource:
    product: linux
    service: auditd
detection:
    selection:
        type: 'PATH'
        name:
            - /etc/syslog.conf
            - /etc/rsyslog.conf
            - /etc/syslog-ng/syslog-ng.conf
    condition: selection
fields:
    - exe
    - comm
    - key
falsepositives:
    - Legitimate administrative activity
level: high

```
