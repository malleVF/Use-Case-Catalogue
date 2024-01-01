---
title: "HackTool - HandleKatz LSASS Dumper Execution"
status: "test"
created: "2022/08/18"
last_modified: "2023/02/04"
tags: [credential_access, t1003_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## HackTool - HandleKatz LSASS Dumper Execution

### Description

Detects the use of HandleKatz, a tool that demonstrates the usage of cloned handles to Lsass in order to create an obfuscated memory dump of the same

```yml
title: HackTool - HandleKatz LSASS Dumper Execution
id: ca621ba5-54ab-4035-9942-d378e6fcde3c
status: test
description: Detects the use of HandleKatz, a tool that demonstrates the usage of cloned handles to Lsass in order to create an obfuscated memory dump of the same
references:
    - https://github.com/codewhitesec/HandleKatz
author: Florian Roth (Nextron Systems)
date: 2022/08/18
modified: 2023/02/04
tags:
    - attack.credential_access
    - attack.t1003.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_loader_img:
        Image|endswith: '\loader.exe'
        CommandLine|contains: '--pid:'
    selection_loader_imphash:
        - Imphash:
              - '38d9e015591bbfd4929e0d0f47fa0055'
              - '0e2216679ca6e1094d63322e3412d650'
        - Hashes:
              - 'IMPHASH=38D9E015591BBFD4929E0D0F47FA0055'
              - 'IMPHASH=0E2216679CA6E1094D63322E3412D650'
    selection_flags:
        CommandLine|contains|all:
            - '--pid:'
            - '--outfile:'
        CommandLine|contains:
            - '.dmp'
            - 'lsass'
            - '.obf'
            - 'dump'
    condition: 1 of selection_*
falsepositives:
    - Unknown
level: high

```