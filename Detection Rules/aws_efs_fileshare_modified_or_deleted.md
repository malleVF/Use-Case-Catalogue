---
title: "AWS EFS Fileshare Modified or Deleted"
status: "test"
created: "2021/08/15"
last_modified: "2022/10/09"
tags: [impact, detection_rule]
logsrc_product: "aws"
logsrc_service: "cloudtrail"
level: "medium"
---

## AWS EFS Fileshare Modified or Deleted

### Description

Detects when a EFS Fileshare is modified or deleted.
You can't delete a file system that is in use.
If the file system has any mount targets, the adversary must first delete them, so deletion of a mount will occur before deletion of a fileshare.


```yml
title: AWS EFS Fileshare Modified or Deleted
id: 25cb1ba1-8a19-4a23-a198-d252664c8cef
status: test
description: |
  Detects when a EFS Fileshare is modified or deleted.
  You can't delete a file system that is in use.
  If the file system has any mount targets, the adversary must first delete them, so deletion of a mount will occur before deletion of a fileshare.
references:
    - https://docs.aws.amazon.com/efs/latest/ug/API_DeleteFileSystem.html
author: Austin Songer @austinsonger
date: 2021/08/15
modified: 2022/10/09
tags:
    - attack.impact
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: elasticfilesystem.amazonaws.com
        eventName: DeleteFileSystem
    condition: selection
falsepositives:
    - Unknown
level: medium

```
