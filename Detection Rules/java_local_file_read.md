---
title: "Potential Local File Read Vulnerability In JVM Based Application"
status: "experimental"
created: "2023/02/11"
last_modified: ""
tags: [initial_access, t1190, detection_rule]
logsrc_product: "jvm"
logsrc_service: ""
level: "high"
---

## Potential Local File Read Vulnerability In JVM Based Application

### Description

Detects potential local file read vulnerability in JVM based apps.
If the exceptions are caused due to user input and contain path traversal payloads then it's a red flag.


```yml
title: Potential Local File Read Vulnerability In JVM Based Application
id: e032f5bc-4563-4096-ae3b-064bab588685
status: experimental
description: |
    Detects potential local file read vulnerability in JVM based apps.
    If the exceptions are caused due to user input and contain path traversal payloads then it's a red flag.
references:
    - https://www.wix.engineering/post/threat-and-vulnerability-hunting-with-application-server-error-logs
author: Moti Harmats
date: 2023/02/11
tags:
    - attack.initial_access
    - attack.t1190
logsource:
    category: application
    product: jvm
    definition: 'Requirements: application error logs must be collected (with LOG_LEVEL=ERROR and above)'
detection:
    keywords_local_file_read:
        '|all':
            - 'FileNotFoundException'
            - '/../../..'
    condition: keywords_local_file_read
falsepositives:
    - Application bugs
level: high

```
