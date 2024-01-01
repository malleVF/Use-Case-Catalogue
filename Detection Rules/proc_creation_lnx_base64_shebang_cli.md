---
title: "Linux Base64 Encoded Shebang In CLI"
status: "test"
created: "2022/09/15"
last_modified: ""
tags: [defense_evasion, t1140, detection_rule]
logsrc_product: "linux"
logsrc_service: ""
level: "medium"
---

## Linux Base64 Encoded Shebang In CLI

### Description

Detects the presence of a base64 version of the shebang in the commandline, which could indicate a malicious payload about to be decoded

```yml
title: Linux Base64 Encoded Shebang In CLI
id: fe2f9663-41cb-47e2-b954-8a228f3b9dff
status: test
description: Detects the presence of a base64 version of the shebang in the commandline, which could indicate a malicious payload about to be decoded
references:
    - https://www.trendmicro.com/pl_pl/research/20/i/the-evolution-of-malicious-shell-scripts.html
    - https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/09/15
tags:
    - attack.defense_evasion
    - attack.t1140
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - "IyEvYmluL2Jhc2" # Note: #!/bin/bash"
            - "IyEvYmluL2Rhc2" # Note: #!/bin/dash"
            - "IyEvYmluL3pza" # Note: #!/bin/zsh"
            - "IyEvYmluL2Zpc2" # Note: #!/bin/fish
            - "IyEvYmluL3No" # Note: # !/bin/sh"
    condition: selection
falsepositives:
    - Legitimate administration activities
level: medium

```
