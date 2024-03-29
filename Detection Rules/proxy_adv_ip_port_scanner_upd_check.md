---
title: "Advanced IP/Port Scanner Update Check"
status: "test"
created: "2022/08/14"
last_modified: ""
tags: [discovery, t1590, detection_rule]
logsrc_product: ""
logsrc_service: ""
level: "medium"
---

## Advanced IP/Port Scanner Update Check

### Description

Detect update check performed by Advanced IP Scanner and Advanced Port Scanner

```yml
title: Advanced IP/Port Scanner Update Check
id: 1a9bb21a-1bb5-42d7-aa05-3219c7c8f47d
status: test
description: Detect update check performed by Advanced IP Scanner and Advanced Port Scanner
references:
    - https://www.advanced-ip-scanner.com/
    - https://www.advanced-port-scanner.com/
author: Axel Olsson
date: 2022/08/14
tags:
    - attack.discovery
    - attack.t1590
logsource:
    category: proxy
detection:
    selection:
      # Example request: http://www.advanced-port-scanner.com/checkupdate.php?lng=en&ver=2-5-3680&beta=n&type=upd&rmode=p&product=aps
      # Example request2: http://www.advanced-ip-scanner.com/checkupdate.php?lng=en&ver=2-5-3499&beta=n&type=upd&rmode=p&product=aips
        c-uri|contains: '/checkupdate.php'
        c-uri-query|contains|all:
            - 'lng='
            - 'ver='
            - 'beta='
            - 'type='
            - 'rmode='
            - 'product='
    condition: selection
fields:
    - c-ip
falsepositives:
    - Legitimate use by administrators
level: medium

```
