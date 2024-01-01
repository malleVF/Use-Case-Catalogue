---
title: "Suspicious Encoded And Obfuscated Reflection Assembly Load Function Call"
status: "test"
created: "2022/03/01"
last_modified: "2023/04/06"
tags: [execution, defense_evasion, t1059_001, t1027, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Suspicious Encoded And Obfuscated Reflection Assembly Load Function Call

### Description

Detects suspicious base64 encoded and obfuscated "LOAD" keyword used in .NET "reflection.assembly"

```yml
title: Suspicious Encoded And Obfuscated Reflection Assembly Load Function Call
id: 9c0295ce-d60d-40bd-bd74-84673b7592b1
related:
    - id: 62b7ccc9-23b4-471e-aa15-6da3663c4d59
      type: similar
status: test
description: Detects suspicious base64 encoded and obfuscated "LOAD" keyword used in .NET "reflection.assembly"
references:
    - https://github.com/Neo23x0/Raccine/blob/20a569fa21625086433dcce8bb2765d0ea08dcb6/yara/mal_revil.yar
    - https://thedfirreport.com/2022/05/09/seo-poisoning-a-gootloader-story/
    - https://learn.microsoft.com/en-us/dotnet/api/system.appdomain.load?view=net-7.0
author: pH-T (Nextron Systems)
date: 2022/03/01
modified: 2023/04/06
tags:
    - attack.execution
    - attack.defense_evasion
    - attack.t1059.001
    - attack.t1027
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            # ::("L"+"oad")
            - 'OgA6ACgAIgBMACIAKwAiAG8AYQBkACIAKQ'
            - 'oAOgAoACIATAAiACsAIgBvAGEAZAAiACkA'
            - '6ADoAKAAiAEwAIgArACIAbwBhAGQAIgApA'
            # ::("Lo"+"ad")
            - 'OgA6ACgAIgBMAG8AIgArACIAYQBkACIAKQ'
            - 'oAOgAoACIATABvACIAKwAiAGEAZAAiACkA'
            - '6ADoAKAAiAEwAbwAiACsAIgBhAGQAIgApA'
            # ::("Loa"+"d")
            - 'OgA6ACgAIgBMAG8AYQAiACsAIgBkACIAKQ'
            - 'oAOgAoACIATABvAGEAIgArACIAZAAiACkA'
            - '6ADoAKAAiAEwAbwBhACIAKwAiAGQAIgApA'
            # ::('L'+'oad')
            - 'OgA6ACgAJwBMACcAKwAnAG8AYQBkACcAKQ'
            - 'oAOgAoACcATAAnACsAJwBvAGEAZAAnACkA'
            - '6ADoAKAAnAEwAJwArACcAbwBhAGQAJwApA'
            # ::('Lo'+'ad')
            - 'OgA6ACgAJwBMAG8AJwArACcAYQBkACcAKQ'
            - 'oAOgAoACcATABvACcAKwAnAGEAZAAnACkA'
            - '6ADoAKAAnAEwAbwAnACsAJwBhAGQAJwApA'
            # ::('Loa'+'d')
            - 'OgA6ACgAJwBMAG8AYQAnACsAJwBkACcAKQ'
            - 'oAOgAoACcATABvAGEAJwArACcAZAAnACkA'
            - '6ADoAKAAnAEwAbwBhACcAKwAnAGQAJwApA'
    condition: selection
fields:
    - CommandLine
falsepositives:
    - Unlikely
level: high

```