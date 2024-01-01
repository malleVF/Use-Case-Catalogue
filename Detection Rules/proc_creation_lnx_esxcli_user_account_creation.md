---
title: "ESXi Account Creation Via ESXCLI"
status: "experimental"
created: "2023/08/22"
last_modified: ""
tags: [persistence, t1136, detection_rule]
logsrc_product: "linux"
logsrc_service: ""
level: "medium"
---

## ESXi Account Creation Via ESXCLI

### Description

Detects user account creation on ESXi system via esxcli

```yml
title: ESXi Account Creation Via ESXCLI
id: b28e4eb3-8bbc-4f0c-819f-edfe8e2f25db
status: experimental
description: Detects user account creation on ESXi system via esxcli
references:
    - https://developer.vmware.com/docs/11743/esxi-7-0-esxcli-command-reference/namespace/esxcli_system.html
author: Cedric Maurugeon
date: 2023/08/22
tags:
    - attack.persistence
    - attack.t1136
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith: '/esxcli'
        CommandLine|contains|all:
            - 'system '
            - 'account '
            - 'add '
    condition: selection
falsepositives:
    - Legitimate administration activities
level: medium

```
