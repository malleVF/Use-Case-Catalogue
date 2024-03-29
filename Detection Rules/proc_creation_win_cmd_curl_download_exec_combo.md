---
title: "Curl Download And Execute Combination"
status: "test"
created: "2020/01/13"
last_modified: "2023/03/06"
tags: [execution, t1218, command_and_control, t1105, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Curl Download And Execute Combination

### Description

Adversaries can use curl to download payloads remotely and execute them. Curl is included by default in Windows 10 build 17063 and later.

```yml
title: Curl Download And Execute Combination
id: 21dd6d38-2b18-4453-9404-a0fe4a0cc288
status: test
description: Adversaries can use curl to download payloads remotely and execute them. Curl is included by default in Windows 10 build 17063 and later.
references:
    - https://medium.com/@reegun/curl-exe-is-the-new-rundll32-exe-lolbin-3f79c5f35983 # Dead Link
author: Sreeman, Nasreddine Bencherchali (Nextron Systems)
date: 2020/01/13
modified: 2023/03/06
tags:
    - attack.execution
    - attack.t1218
    - attack.command_and_control
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - ' /c '
            - 'curl '
            - 'http'
            - '-o'
            - '&'
    condition: selection
fields:
    - ParentImage
    - CommandLine
falsepositives:
    - Unknown
level: high

```
