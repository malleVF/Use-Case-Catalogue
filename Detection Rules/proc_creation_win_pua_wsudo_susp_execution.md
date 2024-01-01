---
title: "PUA - Wsudo Suspicious Execution"
status: "experimental"
created: "2022/12/02"
last_modified: "2023/02/14"
tags: [execution, privilege_escalation, t1059, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## PUA - Wsudo Suspicious Execution

### Description

Detects usage of wsudo (Windows Sudo Utility). Which is a tool that let the user execute programs with different permissions (System, Trusted Installer, Administrator...etc)

```yml
title: PUA - Wsudo Suspicious Execution
id: bdeeabc9-ff2a-4a51-be59-bb253aac7891
status: experimental
description: Detects usage of wsudo (Windows Sudo Utility). Which is a tool that let the user execute programs with different permissions (System, Trusted Installer, Administrator...etc)
references:
    - https://github.com/M2Team/Privexec/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/12/02
modified: 2023/02/14
tags:
    - attack.execution
    - attack.privilege_escalation
    - attack.t1059
logsource:
    category: process_creation
    product: windows
detection:
    selection_metadata:
        - Image|endswith: '\wsudo.exe'
        - OriginalFileName: 'wsudo.exe'
        - Description: 'Windows sudo utility'
        - ParentImage|endswith: '\wsudo-bridge.exe'
    selection_cli:
        CommandLine|contains:
            - '-u System'
            - '-uSystem'
            - '-u TrustedInstaller'
            - '-uTrustedInstaller'
            - ' --ti '
    condition: 1 of selection_*
falsepositives:
    - Unknown
level: high

```
