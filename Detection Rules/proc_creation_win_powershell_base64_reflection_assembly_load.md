---
title: "PowerShell Base64 Encoded Reflective Assembly Load"
status: "test"
created: "2022/03/01"
last_modified: "2023/01/30"
tags: [execution, t1059_001, defense_evasion, t1027, t1620, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## PowerShell Base64 Encoded Reflective Assembly Load

### Description

Detects base64 encoded .NET reflective loading of Assembly

```yml
title: PowerShell Base64 Encoded Reflective Assembly Load
id: 62b7ccc9-23b4-471e-aa15-6da3663c4d59
related:
    - id: 9c0295ce-d60d-40bd-bd74-84673b7592b1
      type: similar
status: test
description: Detects base64 encoded .NET reflective loading of Assembly
references:
    - https://github.com/Neo23x0/Raccine/blob/20a569fa21625086433dcce8bb2765d0ea08dcb6/yara/mal_revil.yar
    - https://thedfirreport.com/2022/05/09/seo-poisoning-a-gootloader-story/
author: Christian Burkard (Nextron Systems), pH-T (Nextron Systems)
date: 2022/03/01
modified: 2023/01/30
tags:
    - attack.execution
    - attack.t1059.001
    - attack.defense_evasion
    - attack.t1027
    - attack.t1620
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            # [Reflection.Assembly]::Load(
            - 'WwBSAGUAZgBsAGUAYwB0AGkAbwBuAC4AQQBzAHMAZQBtAGIAbAB5AF0AOgA6AEwAbwBhAGQAKA'
            - 'sAUgBlAGYAbABlAGMAdABpAG8AbgAuAEEAcwBzAGUAbQBiAGwAeQBdADoAOgBMAG8AYQBkACgA'
            - 'bAFIAZQBmAGwAZQBjAHQAaQBvAG4ALgBBAHMAcwBlAG0AYgBsAHkAXQA6ADoATABvAGEAZAAoA'
            # [reflection.assembly]::("Load")
            - 'AFsAcgBlAGYAbABlAGMAdABpAG8AbgAuAGEAcwBzAGUAbQBiAGwAeQBdADoAOgAoACIATABvAGEAZAAiAC'
            - 'BbAHIAZQBmAGwAZQBjAHQAaQBvAG4ALgBhAHMAcwBlAG0AYgBsAHkAXQA6ADoAKAAiAEwAbwBhAGQAIgAp'
            - 'AWwByAGUAZgBsAGUAYwB0AGkAbwBuAC4AYQBzAHMAZQBtAGIAbAB5AF0AOgA6ACgAIgBMAG8AYQBkACIAK'
            # [Reflection.Assembly]::("Load")
            - 'WwBSAGUAZgBsAGUAYwB0AGkAbwBuAC4AQQBzAHMAZQBtAGIAbAB5AF0AOgA6ACgAIgBMAG8AYQBkACIAKQ'
            - 'sAUgBlAGYAbABlAGMAdABpAG8AbgAuAEEAcwBzAGUAbQBiAGwAeQBdADoAOgAoACIATABvAGEAZAAiACkA'
            - 'bAFIAZQBmAGwAZQBjAHQAaQBvAG4ALgBBAHMAcwBlAG0AYgBsAHkAXQA6ADoAKAAiAEwAbwBhAGQAIgApA'
            # [reflection.assembly]::Load(
            - 'WwByAGUAZgBsAGUAYwB0AGkAbwBuAC4AYQBzAHMAZQBtAGIAbAB5AF0AOgA6AEwAbwBhAGQAKA'
            - 'sAcgBlAGYAbABlAGMAdABpAG8AbgAuAGEAcwBzAGUAbQBiAGwAeQBdADoAOgBMAG8AYQBkACgA'
            - 'bAHIAZQBmAGwAZQBjAHQAaQBvAG4ALgBhAHMAcwBlAG0AYgBsAHkAXQA6ADoATABvAGEAZAAoA'
    condition: selection
fields:
    - CommandLine
falsepositives:
    - Unlikely
level: high

```