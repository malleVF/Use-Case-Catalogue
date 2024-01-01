---
title: "Modifying Crontab"
status: "test"
created: "2022/04/16"
last_modified: ""
tags: [persistence, t1053_003, detection_rule]
logsrc_product: "linux"
logsrc_service: "cron"
level: "medium"
---

## Modifying Crontab

### Description

Detects suspicious modification of crontab file.

```yml
title: Modifying Crontab
id: af202fd3-7bff-4212-a25a-fb34606cfcbe
status: test
description: Detects suspicious modification of crontab file.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1053.003/T1053.003.md
author: Pawel Mazur
date: 2022/04/16
tags:
    - attack.persistence
    - attack.t1053.003
logsource:
    product: linux
    service: cron
detection:
    keywords:
        - 'REPLACE'
    condition: keywords
falsepositives:
    - Legitimate modification of crontab
level: medium

```
