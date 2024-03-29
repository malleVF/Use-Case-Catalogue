---
title: "HackTool - Quarks PwDump Execution"
status: "experimental"
created: "2022/09/05"
last_modified: "2023/02/05"
tags: [credential_access, t1003_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## HackTool - Quarks PwDump Execution

### Description

Detects usage of the Quarks PwDump tool via commandline arguments

```yml
title: HackTool - Quarks PwDump Execution
id: 0685b176-c816-4837-8e7b-1216f346636b
status: experimental
description: Detects usage of the Quarks PwDump tool via commandline arguments
references:
    - https://github.com/quarkslab/quarkspwdump
    - https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/seedworm-apt-iran-middle-east
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/09/05
modified: 2023/02/05
tags:
    - attack.credential_access
    - attack.t1003.002
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        Image|endswith: '\QuarksPwDump.exe'
    selection_cli:
        CommandLine:
            - ' -dhl'
            - ' --dump-hash-local'
            - ' -dhdc'
            - ' --dump-hash-domain-cached'
            - ' --dump-bitlocker'
            - ' -dhd '
            - ' --dump-hash-domain '
            - '--ntds-file'
    condition: 1 of selection_*
falsepositives:
    - Unlikely
level: high

```
