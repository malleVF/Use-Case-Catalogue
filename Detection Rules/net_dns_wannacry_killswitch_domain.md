---
title: "Wannacry Killswitch Domain"
status: "test"
created: "2020/09/16"
last_modified: "2022/03/24"
tags: [command_and_control, t1071_001, detection_rule]
logsrc_product: ""
logsrc_service: ""
level: "high"
---

## Wannacry Killswitch Domain

### Description

Detects wannacry killswitch domain dns queries

```yml
title: Wannacry Killswitch Domain
id: 3eaf6218-3bed-4d8a-8707-274096f12a18
status: test
description: Detects wannacry killswitch domain dns queries
references:
    - https://www.mandiant.com/resources/blog/wannacry-ransomware-campaign
author: Mike Wade
date: 2020/09/16
modified: 2022/03/24
tags:
    - attack.command_and_control
    - attack.t1071.001
logsource:
    category: dns
detection:
    selection:
        query:
            - 'ifferfsodp9ifjaposdfjhgosurijfaewrwergwea.testing'
            - 'ifferfsodp9ifjaposdfjhgosurijfaewrwergwea.test'
            - 'ifferfsodp9ifjaposdfjhgosurijfaewrwergwea.com'
            - 'ayylmaotjhsstasdfasdfasdfasdfasdfasdfasdf.com'
            - 'iuqssfsodp9ifjaposdfjhgosurijfaewrwergwea.com'
    condition: selection
falsepositives:
    - Analyst testing
level: high

```