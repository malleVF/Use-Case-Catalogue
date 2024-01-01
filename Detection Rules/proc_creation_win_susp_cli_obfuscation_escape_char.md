---
title: "Potential Commandline Obfuscation Using Escape Characters"
status: "test"
created: "2018/12/11"
last_modified: "2023/03/03"
tags: [defense_evasion, t1140, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Potential Commandline Obfuscation Using Escape Characters

### Description

Detects potential commandline obfuscation using known escape characters

```yml
title: Potential Commandline Obfuscation Using Escape Characters
id: f0cdd048-82dc-4f7a-8a7a-b87a52b6d0fd
status: test
description: Detects potential commandline obfuscation using known escape characters
references:
    - https://twitter.com/vysecurity/status/885545634958385153
    - https://twitter.com/Hexacorn/status/885553465417756673 # Dead link
    - https://twitter.com/Hexacorn/status/885570278637678592 # Dead link
    - https://www.mandiant.com/resources/blog/obfuscation-wild-targeted-attackers-lead-way-evasion-techniques
    - https://web.archive.org/web/20190213114956/http://www.windowsinspired.com/understanding-the-command-line-string-and-arguments-received-by-a-windows-program/
author: juju4
date: 2018/12/11
modified: 2023/03/03
tags:
    - attack.defense_evasion
    - attack.t1140
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            # - <TAB>   # no TAB modifier in sigmac yet, so this matches <TAB> (or TAB in elasticsearch backends without DSL queries)
            - 'h^t^t^p'
            - 'h"t"t"p'
    condition: selection
falsepositives:
    - Unknown
level: medium

```