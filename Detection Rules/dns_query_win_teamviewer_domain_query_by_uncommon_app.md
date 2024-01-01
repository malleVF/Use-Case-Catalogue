---
title: "TeamViewer Domain Query By Non-TeamViewer Application"
status: "test"
created: "2022/01/30"
last_modified: "2023/09/18"
tags: [command_and_control, t1219, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## TeamViewer Domain Query By Non-TeamViewer Application

### Description

Detects DNS queries to a TeamViewer domain only resolved by a TeamViewer client by an image that isn't named TeamViewer (sometimes used by threat actors for obfuscation)

```yml
title: TeamViewer Domain Query By Non-TeamViewer Application
id: 778ba9a8-45e4-4b80-8e3e-34a419f0b85e
status: test
description: Detects DNS queries to a TeamViewer domain only resolved by a TeamViewer client by an image that isn't named TeamViewer (sometimes used by threat actors for obfuscation)
references:
    - https://www.teamviewer.com/en-us/
author: Florian Roth (Nextron Systems)
date: 2022/01/30
modified: 2023/09/18
tags:
    - attack.command_and_control
    - attack.t1219
logsource:
    product: windows
    category: dns_query
detection:
    selection:
        QueryName:
            - 'taf.teamviewer.com'
            - 'udp.ping.teamviewer.com'
    filter_main_teamviewer:
        # Note: To avoid evasion based on similar names. Best add full install location of TeamViewer
        Image|contains: 'TeamViewer'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown binary names of TeamViewer
    - Depending on the environment the rule might require some initial tuning before usage to avoid FP with third party applications
level: medium

```
