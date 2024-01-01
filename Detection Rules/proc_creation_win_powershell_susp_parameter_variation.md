---
title: "Suspicious PowerShell Parameter Substring"
status: "test"
created: "2019/01/16"
last_modified: "2022/07/14"
tags: [execution, t1059_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Suspicious PowerShell Parameter Substring

### Description

Detects suspicious PowerShell invocation with a parameter substring

```yml
title: Suspicious PowerShell Parameter Substring
id: 36210e0d-5b19-485d-a087-c096088885f0
status: test
description: Detects suspicious PowerShell invocation with a parameter substring
references:
    - http://www.danielbohannon.com/blog-1/2017/3/12/powershell-execution-argument-obfuscation-how-it-can-make-detection-easier
author: Florian Roth (Nextron Systems), Daniel Bohannon (idea), Roberto Rodriguez (Fix)
date: 2019/01/16
modified: 2022/07/14
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
        CommandLine|contains:
            - ' -windowstyle h '
            - ' -windowstyl h'
            - ' -windowsty h'
            - ' -windowst h'
            - ' -windows h'
            - ' -windo h'
            - ' -wind h'
            - ' -win h'
            - ' -wi h'
            - ' -win h '
            - ' -win hi '
            - ' -win hid '
            - ' -win hidd '
            - ' -win hidde '
            - ' -NoPr '
            - ' -NoPro '
            - ' -NoProf '
            - ' -NoProfi '
            - ' -NoProfil '
            - ' -nonin '
            - ' -nonint '
            - ' -noninte '
            - ' -noninter '
            - ' -nonintera '
            - ' -noninterac '
            - ' -noninteract '
            - ' -noninteracti '
            - ' -noninteractiv '
            - ' -ec '
            - ' -encodedComman '
            - ' -encodedComma '
            - ' -encodedComm '
            - ' -encodedCom '
            - ' -encodedCo '
            - ' -encodedC '
            - ' -encoded '
            - ' -encode '
            - ' -encod '
            - ' -enco '
            - ' -en '
            - ' -executionpolic '
            - ' -executionpoli '
            - ' -executionpol '
            - ' -executionpo '
            - ' -executionp '
            - ' -execution bypass'
            - ' -executio bypass'
            - ' -executi bypass'
            - ' -execut bypass'
            - ' -execu bypass'
            - ' -exec bypass'
            - ' -exe bypass'
            - ' -ex bypass'
            - ' -ep bypass'
            - ' /windowstyle h '
            - ' /windowstyl h'
            - ' /windowsty h'
            - ' /windowst h'
            - ' /windows h'
            - ' /windo h'
            - ' /wind h'
            - ' /win h'
            - ' /wi h'
            - ' /win h '
            - ' /win hi '
            - ' /win hid '
            - ' /win hidd '
            - ' /win hidde '
            - ' /NoPr '
            - ' /NoPro '
            - ' /NoProf '
            - ' /NoProfi '
            - ' /NoProfil '
            - ' /nonin '
            - ' /nonint '
            - ' /noninte '
            - ' /noninter '
            - ' /nonintera '
            - ' /noninterac '
            - ' /noninteract '
            - ' /noninteracti '
            - ' /noninteractiv '
            - ' /ec '
            - ' /encodedComman '
            - ' /encodedComma '
            - ' /encodedComm '
            - ' /encodedCom '
            - ' /encodedCo '
            - ' /encodedC '
            - ' /encoded '
            - ' /encode '
            - ' /encod '
            - ' /enco '
            - ' /en '
            - ' /executionpolic '
            - ' /executionpoli '
            - ' /executionpol '
            - ' /executionpo '
            - ' /executionp '
            - ' /execution bypass'
            - ' /executio bypass'
            - ' /executi bypass'
            - ' /execut bypass'
            - ' /execu bypass'
            - ' /exec bypass'
            - ' /exe bypass'
            - ' /ex bypass'
            - ' /ep bypass'
    condition: selection
falsepositives:
    - Unknown
level: high

```