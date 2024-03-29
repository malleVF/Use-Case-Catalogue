---
title: "Metasploit SMB Authentication"
status: "test"
created: "2020/05/06"
last_modified: "2022/10/09"
tags: [lateral_movement, t1021_002, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "high"
---

## Metasploit SMB Authentication

### Description

Alerts on Metasploit host's authentications on the domain.

```yml
title: Metasploit SMB Authentication
id: 72124974-a68b-4366-b990-d30e0b2a190d
status: test
description: Alerts on Metasploit host's authentications on the domain.
references:
    - https://github.com/rapid7/metasploit-framework/blob/1416b5776d963f21b7b5b45d19f3e961201e0aed/lib/rex/proto/smb/client.rb
author: Chakib Gzenayi (@Chak092), Hosni Mribah
date: 2020/05/06
modified: 2022/10/09
tags:
    - attack.lateral_movement
    - attack.t1021.002
logsource:
    product: windows
    service: security
detection:
    selection1:
        EventID:
            - 4625
            - 4624
        LogonType: 3
        AuthenticationPackageName: 'NTLM'
        WorkstationName|re: '^[A-Za-z0-9]{16}$'
    selection2:
        ProcessName:
        EventID: 4776
        Workstation|re: '^[A-Za-z0-9]{16}$'
    condition: 1 of selection*
falsepositives:
    - Linux hostnames composed of 16 characters.
level: high

```
