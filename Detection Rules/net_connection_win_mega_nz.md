---
title: "Communication To Mega.nz"
status: "test"
created: "2021/12/06"
last_modified: "2022/12/25"
tags: [exfiltration, t1567_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Communication To Mega.nz

### Description

Detects an executable accessing mega.co.nz, which could be a sign of forbidden file sharing use of data exfiltration by malicious actors

```yml
title: Communication To Mega.nz
id: fdeebdf0-9f3f-4d08-84a6-4c4d13e39fe4
status: test
description: Detects an executable accessing mega.co.nz, which could be a sign of forbidden file sharing use of data exfiltration by malicious actors
references:
    - https://megatools.megous.com/
    - https://www.mandiant.com/resources/russian-targeting-gov-business
author: Florian Roth (Nextron Systems)
date: 2021/12/06
modified: 2022/12/25
tags:
    - attack.exfiltration
    - attack.t1567.001
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        Initiated: 'true'
        DestinationHostname|endswith: 'api.mega.co.nz'
    condition: selection
falsepositives:
    - Legitimate use of mega.nz uploaders and tools
level: high

```
