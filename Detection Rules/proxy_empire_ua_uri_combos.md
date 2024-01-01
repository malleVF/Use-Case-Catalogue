---
title: "Empire UserAgent URI Combo"
status: "test"
created: "2020/07/13"
last_modified: "2022/08/05"
tags: [defense_evasion, command_and_control, t1071_001, detection_rule]
logsrc_product: ""
logsrc_service: ""
level: "high"
---

## Empire UserAgent URI Combo

### Description

Detects user agent and URI paths used by empire agents

```yml
title: Empire UserAgent URI Combo
id: b923f7d6-ac89-4a50-a71a-89fb846b4aa8
status: test
description: Detects user agent and URI paths used by empire agents
references:
    - https://github.com/BC-SECURITY/Empire
author: Florian Roth (Nextron Systems)
date: 2020/07/13
modified: 2022/08/05
tags:
    - attack.defense_evasion
    - attack.command_and_control
    - attack.t1071.001
logsource:
    category: proxy
detection:
    selection:
        c-useragent: 'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko'
        cs-uri:
            - '/admin/get.php'
            - '/news.php'
            - '/login/process.php'
        cs-method: 'POST'
    condition: selection
falsepositives:
    - Valid requests with this exact user agent to server scripts of the defined names
level: high

```