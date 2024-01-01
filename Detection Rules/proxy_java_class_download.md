---
title: "Java Class Proxy Download"
status: "test"
created: "2021/12/21"
last_modified: "2022/12/25"
tags: [initial_access, detection_rule]
logsrc_product: ""
logsrc_service: ""
level: "high"
---

## Java Class Proxy Download

### Description

Detects Java class download in proxy logs, e.g. used in Log4shell exploitation attacks against Log4j.

```yml
title: Java Class Proxy Download
id: 53c15703-b04c-42bb-9055-1937ddfb3392
status: test
description: Detects Java class download in proxy logs, e.g. used in Log4shell exploitation attacks against Log4j.
references:
    - https://www.lunasec.io/docs/blog/log4j-zero-day/
author: Andreas Hunkeler (@Karneades)
date: 2021/12/21
modified: 2022/12/25
tags:
    - attack.initial_access
logsource:
    category: proxy
detection:
    selection:
        c-uri|endswith: '.class'
    condition: selection
falsepositives:
    - Unknown
level: high

```
