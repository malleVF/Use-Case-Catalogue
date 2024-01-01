---
title: "MSSQL SPProcoption Set"
status: "test"
created: "2022/07/13"
last_modified: ""
tags: [persistence, detection_rule]
logsrc_product: "windows"
logsrc_service: "application"
level: "high"
---

## MSSQL SPProcoption Set

### Description

Detects when the a stored procedure is set or cleared for automatic execution in MSSQL. A stored procedure that is set to automatic execution runs every time an instance of SQL Server is started

```yml
title: MSSQL SPProcoption Set
id: b3d57a5c-c92e-4b48-9a79-5f124b7cf964
status: test
description: Detects when the a stored procedure is set or cleared for automatic execution in MSSQL. A stored procedure that is set to automatic execution runs every time an instance of SQL Server is started
references:
    - https://www.netspi.com/blog/technical/network-penetration-testing/sql-server-persistence-part-1-startup-stored-procedures/
    - https://docs.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-procoption-transact-sql?view=sql-server-ver16
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/07/13
tags:
    - attack.persistence
logsource:
    product: windows
    service: application
    definition: MSSQL audit policy to monitor for 'sp_procoption' must be enabled in order to receive this event in the application log
    # warning: The 'data' field used in the detection section is the container for the event data as a whole. You may have to adapt the rule for your backend accordingly
detection:
    selection:
        Provider_Name: 'MSSQLSERVER'
        EventID: 33205
        Data|contains|all:
            - 'object_name:sp_procoption'
            - 'statement:EXEC'
    condition: selection
falsepositives:
    - Legitimate use of the feature by administrators (rare)
level: high

```