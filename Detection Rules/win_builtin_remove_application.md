---
title: "Application Uninstalled"
status: "test"
created: "2022/01/28"
last_modified: "2022/09/17"
tags: [impact, t1489, detection_rule]
logsrc_product: "windows"
logsrc_service: "application"
level: "low"
---

## Application Uninstalled

### Description

An application has been removed. Check if it is critical.

```yml
title: Application Uninstalled
id: 570ae5ec-33dc-427c-b815-db86228ad43e
status: test
description: An application has been removed. Check if it is critical.
author: frack113
date: 2022/01/28
modified: 2022/09/17
tags:
    - attack.impact
    - attack.t1489
logsource:
    product: windows
    service: application
detection:
    selection:
        Provider_Name: 'MsiInstaller'
        EventID:
            - 11724
            - 1034
    condition: selection
falsepositives:
    - Unknown
# Level is low as it can be very verbose, you can use the top or less 10 "Product Name" to have a quick overview
level: low

```
