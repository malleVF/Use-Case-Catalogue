---
title: "Suspicious ZipExec Execution"
status: "test"
created: "2021/11/07"
last_modified: "2022/12/25"
tags: [execution, defense_evasion, t1218, t1202, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Suspicious ZipExec Execution

### Description

ZipExec is a Proof-of-Concept (POC) tool to wrap binary-based tools into a password-protected zip file.

```yml
title: Suspicious ZipExec Execution
id: 90dcf730-1b71-4ae7-9ffc-6fcf62bd0132
status: test
description: ZipExec is a Proof-of-Concept (POC) tool to wrap binary-based tools into a password-protected zip file.
references:
    - https://twitter.com/SBousseaden/status/1451237393017839616
    - https://github.com/Tylous/ZipExec
author: frack113
date: 2021/11/07
modified: 2022/12/25
tags:
    - attack.execution
    - attack.defense_evasion
    - attack.t1218
    - attack.t1202
logsource:
    category: process_creation
    product: windows
detection:
    run:
        CommandLine|contains|all:
            - '/generic:Microsoft_Windows_Shell_ZipFolder:filename='
            - '.zip'
            - '/pass:'
            - '/user:'
    delete:
        CommandLine|contains|all:
            - '/delete'
            - 'Microsoft_Windows_Shell_ZipFolder:filename='
            - '.zip'
    condition: run or delete
falsepositives:
    - Unknown
level: medium

```
