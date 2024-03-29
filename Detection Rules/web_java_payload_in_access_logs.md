---
title: "Java Payload Strings"
status: "test"
created: "2022/06/04"
last_modified: "2023/01/19"
tags: [cve_2022_26134, cve_2021_26084, initial_access, t1190, detection_rule]
logsrc_product: ""
logsrc_service: ""
level: "high"
---

## Java Payload Strings

### Description

Detects possible Java payloads in web access logs

```yml
title: Java Payload Strings
id: 583aa0a2-30b1-4d62-8bf3-ab73689efe6c
status: test
description: Detects possible Java payloads in web access logs
references:
    - https://www.rapid7.com/blog/post/2022/06/02/active-exploitation-of-confluence-cve-2022-26134/
    - https://www.rapid7.com/blog/post/2021/09/02/active-exploitation-of-confluence-server-cve-2021-26084/
    - https://github.com/httpvoid/writeups/blob/62d3751945289d088ccfdf4d0ffbf61598a2cd7d/Confluence-RCE.md
    - https://twitter.com/httpvoid0x2f/status/1532924261035384832
    - https://medium.com/geekculture/text4shell-exploit-walkthrough-ebc02a01f035
author: frack113, Harjot Singh, "@cyb3rjy0t" (update)
date: 2022/06/04
modified: 2023/01/19
tags:
    - cve.2022.26134
    - cve.2021.26084
    - attack.initial_access
    - attack.t1190
logsource:
    category: webserver
detection:
    keywords:
        - '%24%7B%28%23a%3D%40'
        - '${(#a=@'
        - '%24%7B%40java'
        - '${@java'
        - 'u0022java'
        - '%2F%24%7B%23'
        - '/${#'
        - 'new+java.'
        - 'getRuntime().exec('
        - 'getRuntime%28%29.exec%28'
    condition: keywords
falsepositives:
    - Legitimate apps
level: high

```
