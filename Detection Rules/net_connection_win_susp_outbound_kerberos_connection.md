---
title: "Suspicious Outbound Kerberos Connection"
status: "test"
created: "2019/10/24"
last_modified: "2023/01/30"
tags: [credential_access, t1558, lateral_movement, t1550_003, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Suspicious Outbound Kerberos Connection

### Description

Detects suspicious outbound network activity via kerberos default port indicating possible lateral movement or first stage PrivEsc via delegation.

```yml
title: Suspicious Outbound Kerberos Connection
id: e54979bd-c5f9-4d6c-967b-a04b19ac4c74
related:
    - id: eca91c7c-9214-47b9-b4c5-cb1d7e4f2350
      type: similar
status: test
description: Detects suspicious outbound network activity via kerberos default port indicating possible lateral movement or first stage PrivEsc via delegation.
references:
    - https://github.com/GhostPack/Rubeus
author: Ilyas Ochkov, oscd.community
date: 2019/10/24
modified: 2023/01/30
tags:
    - attack.credential_access
    - attack.t1558
    - attack.lateral_movement
    - attack.t1550.003
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        DestinationPort: 88
        Initiated: 'true'
    filter_exact:
        Image:
            - 'C:\Windows\System32\lsass.exe'
            - 'C:\Program Files\Google\Chrome\Application\chrome.exe'
            - 'C:\Program Files\Mozilla Firefox\firefox.exe'
    # filter_browsers:
    #    Image|endswith:
    #        - '\opera.exe'
    #        - '\tomcat\bin\tomcat8.exe'
    condition: selection and not 1 of filter_*
falsepositives:
    - Web Browsers
level: high

```
