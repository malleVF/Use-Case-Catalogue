---
title: "Potential Linux Amazon SSM Agent Hijacking"
status: "experimental"
created: "2023/08/03"
last_modified: ""
tags: [command_and_control, persistence, t1219, detection_rule]
logsrc_product: "linux"
logsrc_service: ""
level: "medium"
---

## Potential Linux Amazon SSM Agent Hijacking

### Description

Detects potential Amazon SSM agent hijack attempts as outlined in the Mitiga research report.

```yml
title: Potential Linux Amazon SSM Agent Hijacking
id: f9b3edc5-3322-4fc7-8aa3-245d646cc4b7
status: experimental
description: Detects potential Amazon SSM agent hijack attempts as outlined in the Mitiga research report.
references:
    - https://www.mitiga.io/blog/mitiga-security-advisory-abusing-the-ssm-agent-as-a-remote-access-trojan
    - https://www.bleepingcomputer.com/news/security/amazons-aws-ssm-agent-can-be-used-as-post-exploitation-rat-malware/
    - https://www.helpnetsecurity.com/2023/08/02/aws-instances-attackers-access/
author: Muhammad Faisal
date: 2023/08/03
tags:
    - attack.command_and_control
    - attack.persistence
    - attack.t1219
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith: '/amazon-ssm-agent'
        CommandLine|contains|all:
            - '-register '
            - '-code '
            - '-id '
            - '-region '
    condition: selection
falsepositives:
    - Legitimate activity of system administrators
level: medium

```