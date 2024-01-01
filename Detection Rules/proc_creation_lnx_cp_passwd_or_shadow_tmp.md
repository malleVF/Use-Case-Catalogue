---
title: "Copy Passwd Or Shadow From TMP Path"
status: "test"
created: "2023/01/31"
last_modified: ""
tags: [credential_access, t1552_001, detection_rule]
logsrc_product: "linux"
logsrc_service: ""
level: "high"
---

## Copy Passwd Or Shadow From TMP Path

### Description

Detects when the file "passwd" or "shadow" is copied from tmp path

```yml
title: Copy Passwd Or Shadow From TMP Path
id: fa4aaed5-4fe0-498d-bbc0-08e3346387ba
status: test
description: Detects when the file "passwd" or "shadow" is copied from tmp path
references:
    - https://blogs.blackberry.com/
    - https://twitter.com/Joseliyo_Jstnk/status/1620131033474822144
author: Joseliyo Sanchez, @Joseliyo_Jstnk
date: 2023/01/31
tags:
    - attack.credential_access
    - attack.t1552.001
logsource:
    product: linux
    category: process_creation
detection:
    selection_img:
        Image|endswith: '/cp'
    selection_path:
        CommandLine|contains: '/tmp/'
    selection_file:
        CommandLine|contains:
            - 'passwd'
            - 'shadow'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high

```
