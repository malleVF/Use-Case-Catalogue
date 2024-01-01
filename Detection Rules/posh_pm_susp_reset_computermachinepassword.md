---
title: "Suspicious Computer Machine Password by PowerShell"
status: "test"
created: "2022/02/21"
last_modified: ""
tags: [initial_access, t1078, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Suspicious Computer Machine Password by PowerShell

### Description

The Reset-ComputerMachinePassword cmdlet changes the computer account password that the computers use to authenticate to the domain controllers in the domain.
You can use it to reset the password of the local computer.


```yml
title: Suspicious Computer Machine Password by PowerShell
id: e3818659-5016-4811-a73c-dde4679169d2
status: test
description: |
    The Reset-ComputerMachinePassword cmdlet changes the computer account password that the computers use to authenticate to the domain controllers in the domain.
    You can use it to reset the password of the local computer.
references:
    - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/reset-computermachinepassword?view=powershell-5.1
    - https://thedfirreport.com/2022/02/21/qbot-and-zerologon-lead-to-full-domain-compromise/
author: frack113
date: 2022/02/21
tags:
    - attack.initial_access
    - attack.t1078
logsource:
    product: windows
    category: ps_module
    definition: 0ad03ef1-f21b-4a79-8ce8-e6900c54b65b
detection:
    selection:
        ContextInfo|contains: 'Reset-ComputerMachinePassword'
    condition: selection
falsepositives:
    - Administrator PowerShell scripts
level: medium

```
