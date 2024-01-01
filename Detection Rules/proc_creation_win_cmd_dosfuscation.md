---
title: "Potential Dosfuscation Activity"
status: "experimental"
created: "2022/02/15"
last_modified: "2023/03/06"
tags: [execution, t1059, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Potential Dosfuscation Activity

### Description

Detects possible payload obfuscation via the commandline

```yml
title: Potential Dosfuscation Activity
id: a77c1610-fc73-4019-8e29-0f51efc04a51
status: experimental
description: Detects possible payload obfuscation via the commandline
references:
    - https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/dosfuscation-report.pdf
    - https://github.com/danielbohannon/Invoke-DOSfuscation
author: frack113, Nasreddine Bencherchali (Nextron Systems)
date: 2022/02/15
modified: 2023/03/06
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - '^^'
            - '^|^'
            - ',;,'
            - ';;;;'
            - ';; ;;'
            - '(,(,'
            - '%COMSPEC:~'
            - ' c^m^d'
            - '^c^m^d'
            - ' c^md'
            - ' cm^d'
            - '^cm^d'
            - ' s^et '
            - ' s^e^t '
            - ' se^t '
            # - '%%'
            # - '&&'
            # - '""'
    condition: selection
falsepositives:
    - Unknown
level: medium

```
