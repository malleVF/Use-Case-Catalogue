---
title: "MSExchange Transport Agent Installation"
status: "test"
created: "2021/06/08"
last_modified: "2022/10/09"
tags: [persistence, t1505_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## MSExchange Transport Agent Installation

### Description

Detects the Installation of a Exchange Transport Agent

```yml
title: MSExchange Transport Agent Installation
id: 83809e84-4475-4b69-bc3e-4aad8568612f
related:
    - id: 83809e84-4475-4b69-bc3e-4aad8568612f
      type: similar
status: test
description: Detects the Installation of a Exchange Transport Agent
references:
    - https://speakerdeck.com/heirhabarov/hunting-for-persistence-via-microsoft-exchange-server-or-outlook?slide=7
author: Tobias Michalski (Nextron Systems)
date: 2021/06/08
modified: 2022/10/09
tags:
    - attack.persistence
    - attack.t1505.002
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains: 'Install-TransportAgent'
    condition: selection
fields:
    - AssemblyPath
falsepositives:
    - Legitimate installations of exchange TransportAgents. AssemblyPath is a good indicator for this.
level: medium

```
