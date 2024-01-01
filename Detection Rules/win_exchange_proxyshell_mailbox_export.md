---
title: "Mailbox Export to Exchange Webserver"
status: "experimental"
created: "2021/08/09"
last_modified: "2023/04/30"
tags: [persistence, t1505_003, detection_rule]
logsrc_product: "windows"
logsrc_service: "msexchange-management"
level: "critical"
---

## Mailbox Export to Exchange Webserver

### Description

Detects a successful export of an Exchange mailbox to untypical directory or with aspx name suffix which can be used to place a webshell or the needed role assignment for it

```yml
title: Mailbox Export to Exchange Webserver
id: 516376b4-05cd-4122-bae0-ad7641c38d48
status: experimental
description: Detects a successful export of an Exchange mailbox to untypical directory or with aspx name suffix which can be used to place a webshell or the needed role assignment for it
references:
    - https://blog.orange.tw/2021/08/proxylogon-a-new-attack-surface-on-ms-exchange-part-1.html
author: Florian Roth (Nextron Systems), Rich Warren, Christian Burkard (Nextron Systems)
date: 2021/08/09
modified: 2023/04/30
tags:
    - attack.persistence
    - attack.t1505.003
logsource:
    service: msexchange-management
    product: windows
detection:
    export_command:
        '|all':
            - 'New-MailboxExportRequest'
            - ' -Mailbox '
    export_params:
        - '-FilePath "\\\\' # We care about any share location.
        - '.aspx'
    role_assignment:
        '|all':
            - 'New-ManagementRoleAssignment'
            - ' -Role "Mailbox Import Export"'
            - ' -User '
    condition: (export_command and export_params) or role_assignment
falsepositives:
    - Unlikely
level: critical

```
