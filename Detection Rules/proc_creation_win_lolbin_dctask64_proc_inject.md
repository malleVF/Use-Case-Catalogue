---
title: "ZOHO Dctask64 Process Injection"
status: "test"
created: "2020/01/28"
last_modified: "2021/11/27"
tags: [defense_evasion, t1055_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## ZOHO Dctask64 Process Injection

### Description

Detects suspicious process injection using ZOHO's dctask64.exe

```yml
title: ZOHO Dctask64 Process Injection
id: 6345b048-8441-43a7-9bed-541133633d7a
status: test
description: Detects suspicious process injection using ZOHO's dctask64.exe
references:
    - https://twitter.com/gN3mes1s/status/1222088214581825540
    - https://twitter.com/gN3mes1s/status/1222095963789111296
    - https://twitter.com/gN3mes1s/status/1222095371175911424
author: Florian Roth (Nextron Systems)
date: 2020/01/28
modified: 2021/11/27
tags:
    - attack.defense_evasion
    - attack.t1055.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\dctask64.exe'
    filter:
        CommandLine|contains: 'DesktopCentral_Agent\agent'
    condition: selection and not filter
fields:
    - CommandLine
    - ParentCommandLine
    - ParentImage
falsepositives:
    - Unknown
level: high

```