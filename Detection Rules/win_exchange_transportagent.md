---
title: "MSExchange Transport Agent Installation - Builtin"
status: "test"
created: "2021/06/08"
last_modified: "2022/11/27"
tags: [persistence, t1505_002, detection_rule]
logsrc_product: "windows"
logsrc_service: "msexchange-management"
level: "medium"
---

## MSExchange Transport Agent Installation - Builtin

### Description

Detects the Installation of a Exchange Transport Agent

```yml
title: MSExchange Transport Agent Installation - Builtin
id: 4fe151c2-ecf9-4fae-95ae-b88ec9c2fca6
related:
    - id: 83809e84-4475-4b69-bc3e-4aad8568612f
      type: derived
status: test
description: Detects the Installation of a Exchange Transport Agent
references:
    - https://speakerdeck.com/heirhabarov/hunting-for-persistence-via-microsoft-exchange-server-or-outlook?slide=7
author: Tobias Michalski (Nextron Systems)
date: 2021/06/08
modified: 2022/11/27
tags:
    - attack.persistence
    - attack.t1505.002
logsource:
    product: windows
    service: msexchange-management
detection:
    selection:
        - 'Install-TransportAgent'
    condition: selection
fields:
    - AssemblyPath
falsepositives:
    - Legitimate installations of exchange TransportAgents. AssemblyPath is a good indicator for this.
level: medium

```
