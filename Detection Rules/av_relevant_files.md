---
title: "Antivirus Relevant File Paths Alerts"
status: "test"
created: "2018/09/09"
last_modified: "2023/10/23"
tags: [resource_development, t1588, detection_rule]
logsrc_product: ""
logsrc_service: ""
level: "high"
---

## Antivirus Relevant File Paths Alerts

### Description

Detects an Antivirus alert in a highly relevant file path or with a relevant file name

```yml
title: Antivirus Relevant File Paths Alerts
id: c9a88268-0047-4824-ba6e-4d81ce0b907c
status: test
description: Detects an Antivirus alert in a highly relevant file path or with a relevant file name
references:
    - https://www.nextron-systems.com/?s=antivirus
author: Florian Roth (Nextron Systems), Arnim Rupp
date: 2018/09/09
modified: 2023/10/23
tags:
    - attack.resource_development
    - attack.t1588
logsource:
    category: antivirus
detection:
    selection_path:
        Filename|contains:
            # could be startswith, if there is a better backend handling
            - ':\Windows\'
            - ':\Temp\'
            - ':\PerfLogs\'
            - ':\Users\Public\'
            - ':\Users\Default\'
            # true 'contains' matches:
            - '\Client\'
            - '\tsclient\'
            - '\inetpub\'
            - '/www/'
            - 'apache'
            - 'tomcat'
            - 'nginx'
            - 'weblogic'
    selection_ext:
        Filename|endswith:
            - '.asax'
            - '.ashx'
            - '.asmx'
            - '.asp'
            - '.aspx'
            - '.bat'
            - '.cfm'
            - '.cgi'
            - '.chm'
            - '.cmd'
            - '.dat'
            - '.ear'
            - '.gif'
            - '.hta'
            - '.jpeg'
            - '.jpg'
            - '.jsp'
            - '.jspx'
            - '.lnk'
            - '.php'
            - '.pl'
            - '.png'
            - '.ps1'
            - '.psm1'
            - '.py'
            - '.pyc'
            - '.rb'
            - '.scf'
            - '.sct'
            - '.sh'
            - '.svg'
            - '.txt'
            - '.vbe'
            - '.vbs'
            - '.war'
            - '.wsf'
            - '.wsh'
            - '.xml'
    condition: 1 of selection_*
fields:
    - Signature
    - User
falsepositives:
    - Unlikely
level: high

```
