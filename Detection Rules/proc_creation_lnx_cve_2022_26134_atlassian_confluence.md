---
title: "Atlassian Confluence CVE-2022-26134"
status: "test"
created: "2022/06/03"
last_modified: ""
tags: [initial_access, execution, t1190, t1059, cve_2022_26134, detection_rule]
logsrc_product: "linux"
logsrc_service: ""
level: "high"
---

## Atlassian Confluence CVE-2022-26134

### Description

Detects spawning of suspicious child processes by Atlassian Confluence server which may indicate successful exploitation of CVE-2022-26134

```yml
title: Atlassian Confluence CVE-2022-26134
id: 7fb14105-530e-4e2e-8cfb-99f7d8700b66
related:
    - id: 245f92e3-c4da-45f1-9070-bc552e06db11
      type: derived
status: test
description: Detects spawning of suspicious child processes by Atlassian Confluence server which may indicate successful exploitation of CVE-2022-26134
references:
    - https://www.volexity.com/blog/2022/06/02/zero-day-exploitation-of-atlassian-confluence/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/06/03
tags:
    - attack.initial_access
    - attack.execution
    - attack.t1190
    - attack.t1059
    - cve.2022.26134
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        # Monitor suspicious child processes spawned by Confluence
        ParentImage|startswith: '/opt/atlassian/confluence/'
        ParentImage|endswith: '/java'
        CommandLine|contains:
            - '/bin/sh'
            - 'bash'
            - 'dash'
            - 'ksh'
            - 'zsh'
            - 'csh'
            - 'fish'
            - 'curl'
            - 'wget'
            - 'python'
    condition: selection
falsepositives:
    - Unknown
level: high

```