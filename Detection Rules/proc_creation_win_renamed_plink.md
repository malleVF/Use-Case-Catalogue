---
title: "Renamed Plink Execution"
status: "test"
created: "2022/06/06"
last_modified: "2023/02/03"
tags: [defense_evasion, t1036, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Renamed Plink Execution

### Description

Detects the execution of a renamed version of the Plink binary

```yml
title: Renamed Plink Execution
id: 1c12727d-02bf-45ff-a9f3-d49806a3cf43
status: test
description: Detects the execution of a renamed version of the Plink binary
references:
    - https://thedfirreport.com/2022/06/06/will-the-real-msiexec-please-stand-up-exploit-leads-to-data-exfiltration/
    - https://the.earth.li/~sgtatham/putty/0.58/htmldoc/Chapter7.html
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/06/06
modified: 2023/02/03
tags:
    - attack.defense_evasion
    - attack.t1036
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - OriginalFileName: 'Plink'
        - CommandLine|contains|all:
              - ' -l forward'
              - ' -P '
              - ' -R '
    filter:
        Image|endswith: '\plink.exe'
    condition: selection and not filter
falsepositives:
    - Unknown
level: high

```
