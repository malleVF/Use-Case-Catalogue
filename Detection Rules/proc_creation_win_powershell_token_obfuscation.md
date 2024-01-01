---
title: "Powershell Token Obfuscation - Process Creation"
status: "test"
created: "2022/12/27"
last_modified: "2022/12/30"
tags: [defense_evasion, t1027_009, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Powershell Token Obfuscation - Process Creation

### Description

Detects TOKEN OBFUSCATION technique from Invoke-Obfuscation

```yml
title: Powershell Token Obfuscation - Process Creation
id: deb9b646-a508-44ee-b7c9-d8965921c6b6
related:
    - id: f3a98ce4-6164-4dd4-867c-4d83de7eca51
      type: similar
status: test
description: Detects TOKEN OBFUSCATION technique from Invoke-Obfuscation
references:
    - https://github.com/danielbohannon/Invoke-Obfuscation
author: frack113
date: 2022/12/27
modified: 2022/12/30
tags:
    - attack.defense_evasion
    - attack.t1027.009
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        # Examples:
        #   IN`V`o`Ke-eXp`ResSIOn (Ne`W-ob`ject Net.WebClient).DownloadString
        #   &('In'+'voke-Expressi'+'o'+'n') (.('New-Ob'+'jec'+'t') Net.WebClient).DownloadString
        #   &("{2}{3}{0}{4}{1}"-f 'e','Expression','I','nvok','-') (&("{0}{1}{2}"-f'N','ew-O','bject') Net.WebClient).DownloadString
        #   ${e`Nv:pATh}
        - CommandLine|re: '\w+`(\w+|-|.)`[\w+|\s]'
        # - CommandLine|re: '\((\'(\w|-|\.)+\'\+)+\'(\w|-|\.)+\'\)' TODO: fixme
        - CommandLine|re: '"(\{\d\})+"\s*-f'
        - CommandLine|re: '\$\{((e|n|v)*`(e|n|v)*)+:path\}|\$\{((e|n|v)*`(e|n|v)*)+:((p|a|t|h)*`(p|a|t|h)*)+\}|\$\{env:((p|a|t|h)*`(p|a|t|h)*)+\}'
    condition: selection
falsepositives:
    - Unknown
level: high

```