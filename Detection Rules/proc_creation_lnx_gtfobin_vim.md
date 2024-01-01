---
title: "Vim GTFOBin Abuse - Linux"
status: "test"
created: "2022/12/28"
last_modified: ""
tags: [discovery, t1083, detection_rule]
logsrc_product: "linux"
logsrc_service: ""
level: "high"
---

## Vim GTFOBin Abuse - Linux

### Description

Detects usage of "vim" and it's siblings as a GTFOBin to execute and proxy command and binary execution

```yml
title: Vim GTFOBin Abuse - Linux
id: 7ab8f73a-fcff-428b-84aa-6a5ff7877dea
status: test
description: Detects usage of "vim" and it's siblings as a GTFOBin to execute and proxy command and binary execution
references:
    - https://gtfobins.github.io/gtfobins/vim/
    - https://gtfobins.github.io/gtfobins/rvim/
    - https://gtfobins.github.io/gtfobins/vimdiff/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/12/28
tags:
    - attack.discovery
    - attack.t1083
logsource:
    category: process_creation
    product: linux
detection:
    selection_img:
        Image|endswith:
            - '/vim'
            - '/rvim'
            - '/vimdiff'
        CommandLine|contains:
            - ' -c '
            - ' --cmd'
    selection_cli:
        CommandLine|contains:
            - ':!/'
            - ':py '
            - ':lua '
            - '/bin/sh'
            - '/bin/bash'
            - '/bin/dash'
            - '/bin/zsh'
            - '/bin/fish'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high

```
