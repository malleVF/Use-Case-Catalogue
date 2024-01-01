---
title: "Cloudflared Tunnel Execution"
status: "experimental"
created: "2023/05/17"
last_modified: "2023/12/20"
tags: [command_and_control, t1102, t1090, t1572, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Cloudflared Tunnel Execution

### Description

Detects execution of the "cloudflared" tool to connect back to a tunnel. This was seen used by threat actors to maintain persistence and remote access to compromised networks.

```yml
title: Cloudflared Tunnel Execution
id: 9a019ffc-3580-4c9d-8d87-079f7e8d3fd4
status: experimental
description: Detects execution of the "cloudflared" tool to connect back to a tunnel. This was seen used by threat actors to maintain persistence and remote access to compromised networks.
references:
    - https://blog.reconinfosec.com/emergence-of-akira-ransomware-group
    - https://github.com/cloudflare/cloudflared
    - https://developers.cloudflare.com/cloudflare-one/connections/connect-apps
author: Janantha Marasinghe, Nasreddine Bencherchali (Nextron Systems)
date: 2023/05/17
modified: 2023/12/20
tags:
    - attack.command_and_control
    - attack.t1102
    - attack.t1090
    - attack.t1572
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - ' tunnel '
            - ' run '
        CommandLine|contains:
            - '-config '
            - '-credentials-contents '
            - '-credentials-file '
            - '-token '
    condition: selection
falsepositives:
    - Legitimate usage of Cloudflared tunnel.
level: medium

```