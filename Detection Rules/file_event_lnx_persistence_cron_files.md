---
title: "Persistence Via Cron Files"
status: "test"
created: "2021/10/15"
last_modified: "2022/12/31"
tags: [persistence, t1053_003, detection_rule]
logsrc_product: "linux"
logsrc_service: ""
level: "medium"
---

## Persistence Via Cron Files

### Description

Detects creation of cron file or files in Cron directories which could indicates potential persistence.

```yml
title: Persistence Via Cron Files
id: 6c4e2f43-d94d-4ead-b64d-97e53fa2bd05
status: test
description: Detects creation of cron file or files in Cron directories which could indicates potential persistence.
references:
    - https://github.com/microsoft/MSTIC-Sysmon/blob/f1477c0512b0747c1455283069c21faec758e29d/linux/configs/attack-based/persistence/T1053.003_Cron_Activity.xml
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research), MSTIC
date: 2021/10/15
modified: 2022/12/31
tags:
    - attack.persistence
    - attack.t1053.003
logsource:
    product: linux
    category: file_event
detection:
    selection1:
        TargetFilename|startswith:
            - '/etc/cron.d/'
            - '/etc/cron.daily/'
            - '/etc/cron.hourly/'
            - '/etc/cron.monthly/'
            - '/etc/cron.weekly/'
            - '/var/spool/cron/crontabs/'
    selection2:
        TargetFilename|contains:
            - '/etc/cron.allow'
            - '/etc/cron.deny'
            - '/etc/crontab'
    condition: 1 of selection*
falsepositives:
    - Any legitimate cron file.
level: medium

```
