---
title: "Suspicious SQL Query"
status: "test"
created: "2022/12/27"
last_modified: ""
tags: [exfiltration, initial_access, privilege_escalation, t1190, t1505_001, detection_rule]
logsrc_product: ""
logsrc_service: ""
level: "medium"
---

## Suspicious SQL Query

### Description

Detects suspicious SQL query keywrods that are often used during recon, exfiltration or destructive activities. Such as dropping tables and selecting wildcard fields

```yml
title: Suspicious SQL Query
id: d84c0ded-edd7-4123-80ed-348bb3ccc4d5
status: test
description: Detects suspicious SQL query keywrods that are often used during recon, exfiltration or destructive activities. Such as dropping tables and selecting wildcard fields
author: '@juju4'
date: 2022/12/27
references:
    - https://github.com/sqlmapproject/sqlmap
tags:
    - attack.exfiltration
    - attack.initial_access
    - attack.privilege_escalation
    - attack.t1190
    - attack.t1505.001
logsource:
    category: database
    definition: 'Requirements: Must be able to log the SQL queries'
detection:
    keywords:
        - 'drop'
        - 'truncate'
        - 'dump'
        - 'select \*'
    condition: keywords
falsepositives:
    - Inventory and monitoring activity
    - Vulnerability scanners
    - Legitimate applications
level: medium

```
