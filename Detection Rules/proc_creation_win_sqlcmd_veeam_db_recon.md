---
title: "Veeam Backup Database Suspicious Query"
status: "experimental"
created: "2023/05/04"
last_modified: ""
tags: [collection, t1005, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Veeam Backup Database Suspicious Query

### Description

Detects potentially suspicious SQL queries using SQLCmd targeting the Veeam backup databases in order to steal information.

```yml
title: Veeam Backup Database Suspicious Query
id: 696bfb54-227e-4602-ac5b-30d9d2053312
status: experimental
description: Detects potentially suspicious SQL queries using SQLCmd targeting the Veeam backup databases in order to steal information.
references:
    - https://labs.withsecure.com/publications/fin7-target-veeam-servers
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/05/04
tags:
    - attack.collection
    - attack.t1005
logsource:
    category: process_creation
    product: windows
detection:
    selection_sql:
        Image|endswith: '\sqlcmd.exe'
        CommandLine|contains|all:
            - 'VeeamBackup'
            - 'From '
    selection_db:
        CommandLine|contains:
            - 'BackupRepositories'
            - 'Backups'
            - 'Credentials'
            - 'HostCreds'
            - 'SmbFileShares'
            - 'Ssh_creds'
            - 'VSphereInfo'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium

```
