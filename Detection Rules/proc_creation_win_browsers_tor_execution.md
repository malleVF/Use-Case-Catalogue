---
title: "Tor Client/Browser Execution"
status: "test"
created: "2022/02/20"
last_modified: "2023/02/13"
tags: [command_and_control, t1090_003, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Tor Client/Browser Execution

### Description

Detects the use of Tor or Tor-Browser to connect to onion routing networks

```yml
title: Tor Client/Browser Execution
id: 62f7c9bf-9135-49b2-8aeb-1e54a6ecc13c
status: test
description: Detects the use of Tor or Tor-Browser to connect to onion routing networks
references:
    - https://www.logpoint.com/en/blog/detecting-tor-use-with-logpoint/
author: frack113
date: 2022/02/20
modified: 2023/02/13
tags:
    - attack.command_and_control
    - attack.t1090.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\tor.exe'
            - '\Tor Browser\Browser\firefox.exe'
    condition: selection
falsepositives:
    - Unknown
level: high

```
