---
title: "DNS TXT Answer with Possible Execution Strings"
status: "test"
created: "2018/08/08"
last_modified: "2021/11/27"
tags: [command_and_control, t1071_004, detection_rule]
logsrc_product: ""
logsrc_service: ""
level: "high"
---

## DNS TXT Answer with Possible Execution Strings

### Description

Detects strings used in command execution in DNS TXT Answer

```yml
title: DNS TXT Answer with Possible Execution Strings
id: 8ae51330-899c-4641-8125-e39f2e07da72
status: test
description: Detects strings used in command execution in DNS TXT Answer
references:
    - https://twitter.com/stvemillertime/status/1024707932447854592
    - https://github.com/samratashok/nishang/blob/414ee1104526d7057f9adaeee196d91ae447283e/Backdoors/DNS_TXT_Pwnage.ps1
author: Markus Neis
date: 2018/08/08
modified: 2021/11/27
tags:
    - attack.command_and_control
    - attack.t1071.004
logsource:
    category: dns
detection:
    selection:
        record_type: 'TXT'
        answer|contains:
            - 'IEX'
            - 'Invoke-Expression'
            - 'cmd.exe'
    condition: selection
falsepositives:
    - Unknown
level: high

```
