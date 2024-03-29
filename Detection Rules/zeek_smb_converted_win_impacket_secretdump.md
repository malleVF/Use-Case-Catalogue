---
title: "Possible Impacket SecretDump Remote Activity - Zeek"
status: "test"
created: "2020/03/19"
last_modified: "2021/11/27"
tags: [credential_access, t1003_002, t1003_004, t1003_003, detection_rule]
logsrc_product: "zeek"
logsrc_service: "smb_files"
level: "high"
---

## Possible Impacket SecretDump Remote Activity - Zeek

### Description

Detect AD credential dumping using impacket secretdump HKTL. Based on the SIGMA rules/windows/builtin/win_impacket_secretdump.yml

```yml
title: Possible Impacket SecretDump Remote Activity - Zeek
id: 92dae1ed-1c9d-4eff-a567-33acbd95b00e
status: test
description: 'Detect AD credential dumping using impacket secretdump HKTL. Based on the SIGMA rules/windows/builtin/win_impacket_secretdump.yml'
references:
    - https://blog.menasec.net/2019/02/threat-huting-10-impacketsecretdump.html
author: 'Samir Bousseaden, @neu5ron'
date: 2020/03/19
modified: 2021/11/27
tags:
    - attack.credential_access
    - attack.t1003.002
    - attack.t1003.004
    - attack.t1003.003
logsource:
    product: zeek
    service: smb_files
detection:
    selection:
        path|contains|all:
            - '\'
            - 'ADMIN$'
        name|contains: 'SYSTEM32\'
        name|endswith: '.tmp'
    condition: selection
falsepositives:
    - Unknown
level: high

```
