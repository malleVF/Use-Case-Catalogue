---
title: "AWS IAM S3Browser Templated S3 Bucket Policy Creation"
status: "experimental"
created: "2023/05/17"
last_modified: "2023/05/17"
tags: [execution, t1059_009, persistence, t1078_004, detection_rule]
logsrc_product: "aws"
logsrc_service: "cloudtrail"
level: "high"
---

## AWS IAM S3Browser Templated S3 Bucket Policy Creation

### Description

Detects S3 browser utility creating Inline IAM policy containing default S3 bucket name placeholder value of "<YOUR-BUCKET-NAME>".

```yml
title: AWS IAM S3Browser Templated S3 Bucket Policy Creation
id: db014773-7375-4f4e-b83b-133337c0ffee
status: experimental
description: Detects S3 browser utility creating Inline IAM policy containing default S3 bucket name placeholder value of "<YOUR-BUCKET-NAME>".
references:
    - https://permiso.io/blog/s/unmasking-guivil-new-cloud-threat-actor
author: daniel.bohannon@permiso.io (@danielhbohannon)
date: 2023/05/17
modified: 2023/05/17
tags:
    - attack.execution
    - attack.t1059.009
    - attack.persistence
    - attack.t1078.004
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: iam.amazonaws.com
        eventName: PutUserPolicy
        userAgent|contains: 'S3 Browser'
        requestParameters|contains|all:
            - '"arn:aws:s3:::<YOUR-BUCKET-NAME>/*"'
            - '"s3:GetObject"'
            - '"Allow"'
    condition: selection
falsepositives:
    - Valid usage of S3 browser with accidental creation of default Inline IAM policy without changing default S3 bucket name placeholder value
level: high

```
