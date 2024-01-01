---
title: "ESXi Admin Permission Assigned To Account Via ESXCLI"
status: "experimental"
created: "2023/09/04"
last_modified: ""
tags: [execution, detection_rule]
logsrc_product: "linux"
logsrc_service: ""
level: "high"
---

## ESXi Admin Permission Assigned To Account Via ESXCLI

### Description

Detects execution of the "esxcli" command with the "system" and "permission" flags in order to assign admin permissions to an account.

```yml
title: ESXi Admin Permission Assigned To Account Via ESXCLI
id: 9691f58d-92c1-4416-8bf3-2edd753ec9cf
status: experimental
description: Detects execution of the "esxcli" command with the "system" and "permission" flags in order to assign admin permissions to an account.
references:
    - https://developer.vmware.com/docs/11743/esxi-7-0-esxcli-command-reference/namespace/esxcli_system.html
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/09/04
tags:
    - attack.execution
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith: '/esxcli'
        CommandLine|contains: 'system'
        CommandLine|contains|all:
            - ' permission '
            - ' set'
            - 'Admin'
    condition: selection
falsepositives:
    - Legitimate administration activities
level: high

```
