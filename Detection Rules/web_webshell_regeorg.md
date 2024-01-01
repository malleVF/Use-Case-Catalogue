---
title: "Webshell ReGeorg Detection Via Web Logs"
status: "test"
created: "2020/08/04"
last_modified: "2023/01/02"
tags: [persistence, t1505_003, detection_rule]
logsrc_product: ""
logsrc_service: ""
level: "high"
---

## Webshell ReGeorg Detection Via Web Logs

### Description

Certain strings in the uri_query field when combined with null referer and null user agent can indicate activity associated with the webshell ReGeorg.

```yml
title: Webshell ReGeorg Detection Via Web Logs
id: 2ea44a60-cfda-11ea-87d0-0242ac130003
status: test
description: Certain strings in the uri_query field when combined with null referer and null user agent can indicate activity associated with the webshell ReGeorg.
references:
    - https://community.rsa.com/community/products/netwitness/blog/2019/02/19/web-shells-and-netwitness-part-3
    - https://github.com/sensepost/reGeorg
author: Cian Heasley
date: 2020/08/04
modified: 2023/01/02
tags:
    - attack.persistence
    - attack.t1505.003
logsource:
    category: webserver
detection:
    selection:
        cs-uri-query|contains:
            - 'cmd=read'
            - 'connect&target'
            - 'cmd=connect'
            - 'cmd=disconnect'
            - 'cmd=forward'
    filter:
        cs-referer: null
        cs-user-agent: null
        cs-method: POST
    condition: selection and filter
falsepositives:
    - Web applications that use the same URL parameters as ReGeorg
fields:
    - cs-uri-query
    - cs-referer
    - cs-method
    - cs-User-Agent
level: high

```