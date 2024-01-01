---
title: "Source Code Enumeration Detection by Keyword"
status: "test"
created: "2019/06/08"
last_modified: "2022/10/05"
tags: [discovery, t1083, detection_rule]
logsrc_product: ""
logsrc_service: ""
level: "medium"
---

## Source Code Enumeration Detection by Keyword

### Description

Detects source code enumeration that use GET requests by keyword searches in URL strings

```yml
title: Source Code Enumeration Detection by Keyword
id: 953d460b-f810-420a-97a2-cfca4c98e602
status: test
description: Detects source code enumeration that use GET requests by keyword searches in URL strings
references:
    - https://pentester.land/tutorials/2018/10/25/source-code-disclosure-via-exposed-git-folder.html
    - https://medium.com/@logicbomb_1/bugbounty-how-i-was-able-to-download-the-source-code-of-indias-largest-telecom-service-52cf5c5640a1
author: James Ahearn
date: 2019/06/08
modified: 2022/10/05
tags:
    - attack.discovery
    - attack.t1083
logsource:
    category: webserver
detection:
    keywords:
        - '.git/'
    condition: keywords
fields:
    - client_ip
    - vhost
    - url
    - response
falsepositives:
    - Unknown
level: medium

```
