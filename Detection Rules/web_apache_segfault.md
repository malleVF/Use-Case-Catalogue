---
title: "Apache Segmentation Fault"
status: "test"
created: "2017/02/28"
last_modified: "2021/11/27"
tags: [impact, t1499_004, detection_rule]
logsrc_product: ""
logsrc_service: "apache"
level: "high"
---

## Apache Segmentation Fault

### Description

Detects a segmentation fault error message caused by a crashing apache worker process

```yml
title: Apache Segmentation Fault
id: 1da8ce0b-855d-4004-8860-7d64d42063b1
status: test
description: Detects a segmentation fault error message caused by a crashing apache worker process
references:
    - http://www.securityfocus.com/infocus/1633
author: Florian Roth (Nextron Systems)
date: 2017/02/28
modified: 2021/11/27
tags:
    - attack.impact
    - attack.t1499.004
logsource:
    service: apache
    definition: 'Requirements: Must be able to collect the error.log file'
detection:
    keywords:
        - 'exit signal Segmentation Fault'
    condition: keywords
falsepositives:
    - Unknown
level: high

```
