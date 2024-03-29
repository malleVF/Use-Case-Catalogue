---
title: "AWS Suspicious SAML Activity"
status: "test"
created: "2021/09/22"
last_modified: "2022/12/18"
tags: [initial_access, t1078, lateral_movement, t1548, privilege_escalation, t1550, t1550_001, detection_rule]
logsrc_product: "aws"
logsrc_service: "cloudtrail"
level: "medium"
---

## AWS Suspicious SAML Activity

### Description

Identifies when suspicious SAML activity has occurred in AWS. An adversary could gain backdoor access via SAML.

```yml
title: AWS Suspicious SAML Activity
id: f43f5d2f-3f2a-4cc8-b1af-81fde7dbaf0e
status: test
description: Identifies when suspicious SAML activity has occurred in AWS. An adversary could gain backdoor access via SAML.
references:
    - https://docs.aws.amazon.com/IAM/latest/APIReference/API_UpdateSAMLProvider.html
    - https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithSAML.html
author: Austin Songer
date: 2021/09/22
modified: 2022/12/18
tags:
    - attack.initial_access
    - attack.t1078
    - attack.lateral_movement
    - attack.t1548
    - attack.privilege_escalation
    - attack.t1550
    - attack.t1550.001
logsource:
    product: aws
    service: cloudtrail
detection:
    selection_sts:
        eventSource: 'sts.amazonaws.com'
        eventName: 'AssumeRoleWithSAML'
    selection_iam:
        eventSource: 'iam.amazonaws.com'
        eventName: 'UpdateSAMLProvider'
    condition: 1 of selection_*
falsepositives:
    - Automated processes that uses Terraform may lead to false positives.
    - SAML Provider could be updated by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
    - SAML Provider being updated from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
level: medium

```
