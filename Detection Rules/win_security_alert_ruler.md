---
title: "Hacktool Ruler"
status: "test"
created: "2017/05/31"
last_modified: "2022/10/09"
tags: [discovery, execution, t1087, t1114, t1059, t1550_002, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "high"
---

## Hacktool Ruler

### Description

This events that are generated when using the hacktool Ruler by Sensepost

```yml
title: Hacktool Ruler
id: 24549159-ac1b-479c-8175-d42aea947cae
status: test
description: This events that are generated when using the hacktool Ruler by Sensepost
references:
    - https://github.com/sensepost/ruler
    - https://github.com/sensepost/ruler/issues/47
    - https://github.com/staaldraad/go-ntlm/blob/cd032d41aa8ce5751c07cb7945400c0f5c81e2eb/ntlm/ntlmv1.go#L427
    - https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4776
    - https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624
author: Florian Roth (Nextron Systems)
date: 2017/05/31
modified: 2022/10/09
tags:
    - attack.discovery
    - attack.execution
    - attack.t1087
    - attack.t1114
    - attack.t1059
    - attack.t1550.002
logsource:
    product: windows
    service: security
detection:
    selection1:
        EventID: 4776
        Workstation: 'RULER'
    selection2:
        EventID:
            - 4624
            - 4625
        WorkstationName: 'RULER'
    condition: (1 of selection*)
falsepositives:
    - Go utilities that use staaldraad awesome NTLM library
level: high

```
