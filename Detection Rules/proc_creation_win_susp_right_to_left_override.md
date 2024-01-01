---
title: "Potential Defense Evasion Via Right-to-Left Override"
status: "experimental"
created: "2023/02/15"
last_modified: ""
tags: [defense_evasion, t1036_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Potential Defense Evasion Via Right-to-Left Override

### Description

Detects the presence of the "u202+E" character, which causes a terminal, browser, or operating system to render text in a right-to-left sequence.
This is used as an obfuscation and masquerading techniques.


```yml
title: Potential Defense Evasion Via Right-to-Left Override
id: ad691d92-15f2-4181-9aa4-723c74f9ddc3
status: experimental
description: |
    Detects the presence of the "u202+E" character, which causes a terminal, browser, or operating system to render text in a right-to-left sequence.
    This is used as an obfuscation and masquerading techniques.
references:
    - https://redcanary.com/blog/right-to-left-override/
    - https://www.malwarebytes.com/blog/news/2014/01/the-rtlo-method
    - https://unicode-explorer.com/c/202E
author: Micah Babinski, @micahbabinski
date: 2023/02/15
tags:
    - attack.defense_evasion
    - attack.t1036.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: "\u202e"
    condition: selection
falsepositives:
    - Commandlines that contains scriptures such as arabic or hebrew might make use of this character
level: high

```
