---
title: "Gpresult Display Group Policy Information"
status: "test"
created: "2022/05/01"
last_modified: ""
tags: [discovery, t1615, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Gpresult Display Group Policy Information

### Description

Detects cases in which a user uses the built-in Windows utility gpresult to display the Resultant Set of Policy (RSoP) information

```yml
title: Gpresult Display Group Policy Information
id: e56d3073-83ff-4021-90fe-c658e0709e72
status: test
description: Detects cases in which a user uses the built-in Windows utility gpresult to display the Resultant Set of Policy (RSoP) information
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1615/T1615.md
    - https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/gpresult
    - https://unit42.paloaltonetworks.com/emissary-trojan-changelog-did-operation-lotus-blossom-cause-it-to-evolve/
    - https://www.welivesecurity.com/wp-content/uploads/2020/05/ESET_Turla_ComRAT.pdf
author: frack113
date: 2022/05/01
tags:
    - attack.discovery
    - attack.t1615
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\gpresult.exe'
        CommandLine|contains:
            - '/z'
            - '/v'
    condition: selection
falsepositives:
    - Unknown
level: medium

```