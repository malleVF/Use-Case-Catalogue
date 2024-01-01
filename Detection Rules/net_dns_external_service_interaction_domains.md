---
title: "DNS Query to External Service Interaction Domains"
status: "test"
created: "2022/06/07"
last_modified: ""
tags: [initial_access, t1190, reconnaissance, t1595_002, detection_rule]
logsrc_product: ""
logsrc_service: ""
level: "high"
---

## DNS Query to External Service Interaction Domains

### Description

Detects suspicious DNS queries to external service interaction domains often used for out-of-band interactions after successful RCE

```yml
title: DNS Query to External Service Interaction Domains
id: aff715fa-4dd5-497a-8db3-910bea555566
status: test
description: Detects suspicious DNS queries to external service interaction domains often used for out-of-band interactions after successful RCE
references:
    - https://twitter.com/breakersall/status/1533493587828260866
author: Florian Roth (Nextron Systems), Matt Kelly (list of domains)
date: 2022/06/07
tags:
    - attack.initial_access
    - attack.t1190
    - attack.reconnaissance
    - attack.t1595.002
logsource:
    category: dns
detection:
    selection:
        query|contains:
            - '.interact.sh'
            - '.oast.pro'
            - '.oast.live'
            - '.oast.site'
            - '.oast.online'
            - '.oast.fun'
            - '.oast.me'
            - '.burpcollaborator.net'
            - '.oastify.com'
            - '.canarytokens.com'
            - '.requestbin.net'
            - '.dnslog.cn'
    condition: selection
falsepositives:
    - Unknown
level: high

```
