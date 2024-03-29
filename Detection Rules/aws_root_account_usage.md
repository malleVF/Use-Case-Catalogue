---
title: "AWS Root Credentials"
status: "test"
created: "2020/01/21"
last_modified: "2022/10/09"
tags: [privilege_escalation, t1078_004, detection_rule]
logsrc_product: "aws"
logsrc_service: "cloudtrail"
level: "medium"
---

## AWS Root Credentials

### Description

Detects AWS root account usage

```yml
title: AWS Root Credentials
id: 8ad1600d-e9dc-4251-b0ee-a65268f29add
status: test
description: Detects AWS root account usage
references:
    - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html
author: vitaliy0x1
date: 2020/01/21
modified: 2022/10/09
tags:
    - attack.privilege_escalation
    - attack.t1078.004
logsource:
    product: aws
    service: cloudtrail
detection:
    selection_usertype:
        userIdentity.type: Root
    selection_eventtype:
        eventType: AwsServiceEvent
    condition: selection_usertype and not selection_eventtype
falsepositives:
    - AWS Tasks That Require AWS Account Root User Credentials https://docs.aws.amazon.com/general/latest/gr/aws_tasks-that-require-root.html
level: medium

```
