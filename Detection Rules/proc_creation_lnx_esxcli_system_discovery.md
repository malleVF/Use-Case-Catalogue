---
title: "ESXi System Information Discovery Via ESXCLI"
status: "experimental"
created: "2023/09/04"
last_modified: ""
tags: [discovery, t1033, t1007, detection_rule]
logsrc_product: "linux"
logsrc_service: ""
level: "medium"
---

## ESXi System Information Discovery Via ESXCLI

### Description

Detects execution of the "esxcli" command with the "system" flag in order to retrieve information about the different component of the system. Such as accounts, modules, NTP, etc.

```yml
title: ESXi System Information Discovery Via ESXCLI
id: e80273e1-9faf-40bc-bd85-dbaff104c4e9
status: experimental
description: Detects execution of the "esxcli" command with the "system" flag in order to retrieve information about the different component of the system. Such as accounts, modules, NTP, etc.
references:
    - https://www.crowdstrike.com/blog/hypervisor-jackpotting-ecrime-actors-increase-targeting-of-esxi-servers/
    - https://developer.vmware.com/docs/11743/esxi-7-0-esxcli-command-reference/namespace/esxcli_system.html
author: Cedric Maurugeon
date: 2023/09/04
tags:
    - attack.discovery
    - attack.t1033
    - attack.t1007
logsource:
    category: process_creation
    product: linux
detection:
    selection_img:
        Image|endswith: '/esxcli'
        CommandLine|contains: 'system'
    selection_cli:
        CommandLine|contains:
            - ' get'
            - ' list'
    condition: all of selection_*
falsepositives:
    - Legitimate administration activities
level: medium

```
