---
title: "Remove Exported Mailbox from Exchange Webserver"
status: "test"
created: "2021/08/27"
last_modified: "2023/01/23"
tags: [defense_evasion, t1070, detection_rule]
logsrc_product: "windows"
logsrc_service: "msexchange-management"
level: "high"
---

## Remove Exported Mailbox from Exchange Webserver

### Description

Detects removal of an exported Exchange mailbox which could be to cover tracks from ProxyShell exploit

```yml
title: Remove Exported Mailbox from Exchange Webserver
id: 09570ae5-889e-43ea-aac0-0e1221fb3d95
status: test
description: Detects removal of an exported Exchange mailbox which could be to cover tracks from ProxyShell exploit
references:
    - https://github.com/rapid7/metasploit-framework/blob/1416b5776d963f21b7b5b45d19f3e961201e0aed/modules/exploits/windows/http/exchange_proxyshell_rce.rb#L430
author: Christian Burkard (Nextron Systems)
date: 2021/08/27
modified: 2023/01/23
tags:
    - attack.defense_evasion
    - attack.t1070
logsource:
    service: msexchange-management
    product: windows
detection:
    keywords:
        '|all':
            - 'Remove-MailboxExportRequest'
            - ' -Identity '
            - ' -Confirm "False"'
    condition: keywords
falsepositives:
    - Unknown
level: high

```
