---
title: "AWS STS AssumeRole Misuse"
status: "test"
created: "2021/07/24"
last_modified: "2022/10/09"
tags: [lateral_movement, privilege_escalation, t1548, t1550, t1550_001, detection_rule]
logsrc_product: "aws"
logsrc_service: "cloudtrail"
level: "low"
---

## AWS STS AssumeRole Misuse

### Description

Identifies the suspicious use of AssumeRole. Attackers could move laterally and escalate privileges.

```yml
title: AWS STS AssumeRole Misuse
id: 905d389b-b853-46d0-9d3d-dea0d3a3cd49
status: test
description: Identifies the suspicious use of AssumeRole. Attackers could move laterally and escalate privileges.
references:
    - https://github.com/elastic/detection-rules/pull/1214
    - https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html
author: Austin Songer @austinsonger
date: 2021/07/24
modified: 2022/10/09
tags:
    - attack.lateral_movement
    - attack.privilege_escalation
    - attack.t1548
    - attack.t1550
    - attack.t1550.001
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        userIdentity.type: AssumedRole
        userIdentity.sessionContext.sessionIssuer.type: Role
    condition: selection
falsepositives:
    - AssumeRole may be done by a system or network administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
    - AssumeRole from unfamiliar users or hosts should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
    - Automated processes that uses Terraform may lead to false positives.
level: low

```
