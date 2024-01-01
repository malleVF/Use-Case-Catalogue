---
title: "AWS Config Disabling Channel/Recorder"
status: "test"
created: "2020/01/21"
last_modified: "2022/10/09"
tags: [defense_evasion, t1562_001, detection_rule]
logsrc_product: "aws"
logsrc_service: "cloudtrail"
level: "high"
---

## AWS Config Disabling Channel/Recorder

### Description

Detects AWS Config Service disabling

```yml
title: AWS Config Disabling Channel/Recorder
id: 07330162-dba1-4746-8121-a9647d49d297
status: test
description: Detects AWS Config Service disabling
author: vitaliy0x1
date: 2020/01/21
modified: 2022/10/09
tags:
    - attack.defense_evasion
    - attack.t1562.001
logsource:
    product: aws
    service: cloudtrail
detection:
    selection_source:
        eventSource: config.amazonaws.com
        eventName:
            - DeleteDeliveryChannel
            - StopConfigurationRecorder
    condition: selection_source
falsepositives:
    - Valid change in AWS Config Service
level: high

```
