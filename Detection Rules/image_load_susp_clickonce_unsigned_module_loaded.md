---
title: "Unsigned Module Loaded by ClickOnce Application"
status: "experimental"
created: "2023/06/08"
last_modified: ""
tags: [persistence, t1574_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Unsigned Module Loaded by ClickOnce Application

### Description

Detects unsigned module load by ClickOnce application.

```yml
title: Unsigned Module Loaded by ClickOnce Application
id: 060d5ad4-3153-47bb-8382-43e5e29eda92
status: experimental
description: Detects unsigned module load by ClickOnce application.
references:
    - https://posts.specterops.io/less-smartscreen-more-caffeine-ab-using-clickonce-for-trusted-code-execution-1446ea8051c5
author: '@SerkinValery'
date: 2023/06/08
tags:
    - attack.persistence
    - attack.t1574.002
logsource:
    category: image_load
    product: windows
detection:
    selection_path:
        Image|contains: '\AppData\Local\Apps\2.0\'
    selection_sig_status:
        - Signed: 'false'
        - SignatureStatus: 'Expired'
    condition: all of selection_*
falsepositives:
    - Unlikely
level: medium

```
