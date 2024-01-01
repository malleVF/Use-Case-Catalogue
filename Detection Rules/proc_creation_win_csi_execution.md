---
title: "Suspicious Csi.exe Usage"
status: "test"
created: "2020/10/17"
last_modified: "2022/07/11"
tags: [execution, t1072, defense_evasion, t1218, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Suspicious Csi.exe Usage

### Description

Csi.exe is a signed binary from Microsoft that comes with Visual Studio and provides C# interactive capabilities. It can be used to run C# code from a file passed as a parameter in command line. Early version of this utility provided with Microsoft “Roslyn” Community Technology Preview was named 'rcsi.exe'

```yml
title: Suspicious Csi.exe Usage
id: 40b95d31-1afc-469e-8d34-9a3a667d058e
status: test
description: Csi.exe is a signed binary from Microsoft that comes with Visual Studio and provides C# interactive capabilities. It can be used to run C# code from a file passed as a parameter in command line. Early version of this utility provided with Microsoft âRoslynâ Community Technology Preview was named 'rcsi.exe'
references:
    - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Csi/
    - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Rcsi/
    - https://enigma0x3.net/2016/11/21/bypassing-application-whitelisting-by-using-rcsi-exe/
    - https://twitter.com/Z3Jpa29z/status/1317545798981324801
author: Konstantin Grishchenko, oscd.community
date: 2020/10/17
modified: 2022/07/11
tags:
    - attack.execution
    - attack.t1072
    - attack.defense_evasion
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith:
              - '\csi.exe'
              - '\rcsi.exe'
        - OriginalFileName:
              - 'csi.exe'
              - 'rcsi.exe'
    selection_cli:
        Company: 'Microsoft Corporation'
    condition: all of selection*
fields:
    - ComputerName
    - User
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Legitimate usage by software developers
level: medium

```