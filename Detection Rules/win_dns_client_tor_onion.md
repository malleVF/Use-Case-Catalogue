---
title: "Query Tor Onion Address - DNS Client"
status: "test"
created: "2022/02/20"
last_modified: ""
tags: [command_and_control, t1090_003, detection_rule]
logsrc_product: "windows"
logsrc_service: "dns-client"
level: "high"
---

## Query Tor Onion Address - DNS Client

### Description

Detects DNS resolution of an .onion address related to Tor routing networks

```yml
title: Query Tor Onion Address - DNS Client
id: 8384bd26-bde6-4da9-8e5d-4174a7a47ca2
related:
    - id: b55ca2a3-7cff-4dda-8bdd-c7bfa63bf544
      type: similar
status: test
description: Detects DNS resolution of an .onion address related to Tor routing networks
references:
    - https://www.logpoint.com/en/blog/detecting-tor-use-with-logpoint/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/02/20
tags:
    - attack.command_and_control
    - attack.t1090.003
logsource:
    product: windows
    service: dns-client
    definition: 'Requirements: Microsoft-Windows-DNS Client Events/Operational Event Log must be enabled/collected in order to receive the events.'
detection:
    selection:
        EventID: 3008
        QueryName|contains: '.onion'
    condition: selection
falsepositives:
    - Unlikely
level: high

```
