---
title: "Microsoft IIS Connection Strings Decryption"
status: "test"
created: "2022/09/28"
last_modified: "2022/12/30"
tags: [credential_access, t1003, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Microsoft IIS Connection Strings Decryption

### Description

Detects use of aspnet_regiis to decrypt Microsoft IIS connection strings. An attacker with Microsoft IIS web server access via a webshell or alike can decrypt and dump any hardcoded connection strings, such as the MSSQL service account password using aspnet_regiis command.

```yml
title: Microsoft IIS Connection Strings Decryption
id: 97dbf6e2-e436-44d8-abee-4261b24d3e41
status: test
description: Detects use of aspnet_regiis to decrypt Microsoft IIS connection strings. An attacker with Microsoft IIS web server access via a webshell or alike can decrypt and dump any hardcoded connection strings, such as the MSSQL service account password using aspnet_regiis command.
references:
    - https://www.elastic.co/guide/en/security/current/microsoft-iis-connection-strings-decryption.html
author: Tim Rauch
date: 2022/09/28
modified: 2022/12/30
tags:
    - attack.credential_access
    - attack.t1003
logsource:
    category: process_creation
    product: windows
detection:
    selection_name:
        - Image|endswith: '\aspnet_regiis.exe'
        - OriginalFileName: 'aspnet_regiis.exe'
    selection_args:
        CommandLine|contains|all:
            - 'connectionStrings'
            - ' -pdf'
    condition: all of selection*
falsepositives:
    - Unknown
level: high

```
