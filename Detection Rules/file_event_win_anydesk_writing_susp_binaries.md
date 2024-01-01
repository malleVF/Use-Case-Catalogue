---
title: "Suspicious Binary Writes Via AnyDesk"
status: "test"
created: "2022/09/28"
last_modified: ""
tags: [command_and_control, t1219, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Suspicious Binary Writes Via AnyDesk

### Description

Detects AnyDesk writing binary files to disk other than "gcapi.dll".
According to RedCanary research it is highly abnormal for AnyDesk to write executable files to disk besides gcapi.dll,
which is a legitimate DLL that is part of the Google Chrome web browser used to interact with the Google Cloud API. (See reference section for more details)


```yml
title: Suspicious Binary Writes Via AnyDesk
id: 2d367498-5112-4ae5-a06a-96e7bc33a211
status: test
description: |
    Detects AnyDesk writing binary files to disk other than "gcapi.dll".
    According to RedCanary research it is highly abnormal for AnyDesk to write executable files to disk besides gcapi.dll,
    which is a legitimate DLL that is part of the Google Chrome web browser used to interact with the Google Cloud API. (See reference section for more details)
references:
    - https://redcanary.com/blog/misbehaving-rats/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/09/28
tags:
    - attack.command_and_control
    - attack.t1219
logsource:
    product: windows
    category: file_event
detection:
    selection:
        Image|endswith: '\anydesk.exe'
        TargetFilename|endswith:
            - '.dll'
            - '.exe'
    filter_dlls:
        TargetFilename|endswith: '\gcapi.dll'
    condition: selection and not 1 of filter_*
falsepositives:
    - Unknown
level: high

```
