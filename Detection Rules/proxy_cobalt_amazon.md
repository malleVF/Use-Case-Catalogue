---
title: "CobaltStrike Malleable Amazon Browsing Traffic Profile"
status: "test"
created: "2019/11/12"
last_modified: "2022/07/07"
tags: [defense_evasion, command_and_control, t1071_001, detection_rule]
logsrc_product: ""
logsrc_service: ""
level: "high"
---

## CobaltStrike Malleable Amazon Browsing Traffic Profile

### Description

Detects Malleable Amazon Profile

```yml
title: CobaltStrike Malleable Amazon Browsing Traffic Profile
id: 953b895e-5cc9-454b-b183-7f3db555452e
status: test
description: Detects Malleable Amazon Profile
references:
    - https://github.com/rsmudge/Malleable-C2-Profiles/blob/26323784672913923d20c5a638c6ca79459e8529/normal/amazon.profile
    - https://www.hybrid-analysis.com/sample/ee5eca8648e45e2fea9dac0d920ef1a1792d8690c41ee7f20343de1927cc88b9?environmentId=100
author: Markus Neis
date: 2019/11/12
modified: 2022/07/07
tags:
    - attack.defense_evasion
    - attack.command_and_control
    - attack.t1071.001
logsource:
    category: proxy
detection:
    selection_1:
        c-useragent: 'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko'
        cs-method: 'GET'
        c-uri: '/s/ref=nb_sb_noss_1/167-3294888-0262949/field-keywords=books'
        cs-host: 'www.amazon.com'
        cs-cookie|endswith: '=csm-hit=s-24KU11BB82RZSYGJ3BDK|1419899012996'
    selection_2:
        c-useragent: 'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko'
        cs-method: 'POST'
        c-uri: '/N4215/adj/amzn.us.sr.aps'
        cs-host: 'www.amazon.com'
    condition: 1 of selection_*
falsepositives:
    - Unknown
level: high

```
