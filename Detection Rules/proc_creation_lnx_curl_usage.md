---
title: "Curl Usage on Linux"
status: "test"
created: "2022/09/15"
last_modified: ""
tags: [command_and_control, t1105, detection_rule]
logsrc_product: "linux"
logsrc_service: ""
level: "low"
---

## Curl Usage on Linux

### Description

Detects a curl process start on linux, which indicates a file download from a remote location or a simple web request to a remote server

```yml
title: Curl Usage on Linux
id: ea34fb97-e2c4-4afb-810f-785e4459b194
status: test
description: Detects a curl process start on linux, which indicates a file download from a remote location or a simple web request to a remote server
references:
    - https://www.trendmicro.com/en_us/research/22/i/how-malicious-actors-abuse-native-linux-tools-in-their-attacks.html
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/09/15
tags:
    - attack.command_and_control
    - attack.t1105
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith: '/curl'
    condition: selection
falsepositives:
    - Scripts created by developers and admins
    - Administrative activity
level: low

```
