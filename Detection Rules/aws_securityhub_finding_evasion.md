---
title: "AWS SecurityHub Findings Evasion"
status: "stable"
created: "2021/06/28"
last_modified: ""
tags: [defense_evasion, t1562, detection_rule]
logsrc_product: "aws"
logsrc_service: "cloudtrail"
level: "high"
---

## AWS SecurityHub Findings Evasion

### Description

Detects the modification of the findings on SecurityHub.

```yml
title: AWS SecurityHub Findings Evasion
id: a607e1fe-74bf-4440-a3ec-b059b9103157
status: stable
description: Detects the modification of the findings on SecurityHub.
references:
    - https://docs.aws.amazon.com/cli/latest/reference/securityhub/
author: Sittikorn S
date: 2021/06/28
tags:
    - attack.defense_evasion
    - attack.t1562
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: securityhub.amazonaws.com
        eventName:
            - 'BatchUpdateFindings'
            - 'DeleteInsight'
            - 'UpdateFindings'
            - 'UpdateInsight'
    condition: selection
fields:
    - sourceIPAddress
    - userIdentity.arn
falsepositives:
    - System or Network administrator behaviors
    - DEV, UAT, SAT environment. You should apply this rule with PROD environment only.
level: high

```
