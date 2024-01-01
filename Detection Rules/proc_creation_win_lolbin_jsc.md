---
title: "JSC Convert Javascript To Executable"
status: "test"
created: "2022/05/02"
last_modified: ""
tags: [defense_evasion, t1127, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## JSC Convert Javascript To Executable

### Description

Detects the execution of the LOLBIN jsc.exe used by .NET to compile javascript code to .exe or .dll format

```yml
title: JSC Convert Javascript To Executable
id: 52788a70-f1da-40dd-8fbd-73b5865d6568
status: test
description: Detects the execution of the LOLBIN jsc.exe used by .NET to compile javascript code to .exe or .dll format
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Jsc/
author: frack113
date: 2022/05/02
tags:
    - attack.defense_evasion
    - attack.t1127
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\jsc.exe'
        CommandLine|contains: '.js'
    condition: selection
falsepositives:
    - Unknown
level: medium

```