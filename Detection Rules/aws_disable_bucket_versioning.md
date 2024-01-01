---
title: "AWS S3 Bucket Versioning Disable"
status: "experimental"
created: "2023/10/28"
last_modified: ""
tags: [impact, t1490, detection_rule]
logsrc_product: "aws"
logsrc_service: "cloudtrail"
level: "medium"
---

## AWS S3 Bucket Versioning Disable

### Description

Detects when S3 bucket versioning is disabled. Threat actors use this technique during AWS ransomware incidents prior to deleting S3 objects.

```yml
title: AWS S3 Bucket Versioning Disable
id: a136ac98-b2bc-4189-a14d-f0d0388e57a7
status: experimental
description: Detects when S3 bucket versioning is disabled. Threat actors use this technique during AWS ransomware incidents prior to deleting S3 objects.
references:
    - https://invictus-ir.medium.com/ransomware-in-the-cloud-7f14805bbe82
author: Sean Johnstone | Unit 42
date: 2023/10/28
tags:
    - attack.impact
    - attack.t1490
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: s3.amazonaws.com
        eventName: PutBucketVersioning
        requestParameters|contains: 'Suspended'
    condition: selection
falsepositives:
    - AWS administrator legitimately disabling bucket versioning
level: medium

```
