---
title: "Use of Forfiles For Execution"
status: "test"
created: "2022/06/14"
last_modified: ""
tags: [execution, t1059, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Use of Forfiles For Execution

### Description

Execute commands and binaries from the context of "forfiles". This is used as a LOLBIN for example to bypass application whitelisting.

```yml
title: Use of Forfiles For Execution
id: 9aa5106d-bce3-4b13-86df-3a20f1d5cf0b
related:
    - id: a85cf4e3-56ee-4e79-adeb-789f8fb209a8
      type: obsoletes
    - id: fa47597e-90e9-41cd-ab72-c3b74cfb0d02
      type: obsoletes
status: test
description: Execute commands and binaries from the context of "forfiles". This is used as a LOLBIN for example to bypass application whitelisting.
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Forfiles/
    - https://pentestlab.blog/2020/07/06/indirect-command-execution/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/06/14
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\forfiles.exe'
        - OriginalFileName: 'forfiles.exe'
    selection_cli_p:
        CommandLine|contains:
            - ' /p '
            - ' -p '
    selection_cli_m:
        CommandLine|contains:
            - ' /m '
            - ' -m '
    selection_cli_c:
        CommandLine|contains:
            - ' /c '
            - ' -c '
    condition: all of selection*
falsepositives:
    - Legitimate use via a batch script or by an administrator.
level: medium

```
