---
title: "Hack Tool User Agent"
status: "test"
created: "2017/07/08"
last_modified: "2022/07/07"
tags: [initial_access, t1190, credential_access, t1110, detection_rule]
logsrc_product: ""
logsrc_service: ""
level: "high"
---

## Hack Tool User Agent

### Description

Detects suspicious user agent strings user by hack tools in proxy logs

```yml
title: Hack Tool User Agent
id: c42a3073-30fb-48ae-8c99-c23ada84b103
status: test
description: Detects suspicious user agent strings user by hack tools in proxy logs
references:
    - https://github.com/fastly/waf_testbed/blob/8bfc406551f3045e418cbaad7596cff8da331dfc/templates/default/scanners-user-agents.data.erb
    - http://rules.emergingthreats.net/open/snort-2.9.0/rules/emerging-user_agents.rules
author: Florian Roth (Nextron Systems)
date: 2017/07/08
modified: 2022/07/07
tags:
    - attack.initial_access
    - attack.t1190
    - attack.credential_access
    - attack.t1110
logsource:
    category: proxy
detection:
    selection:
        c-useragent|contains:
            # Vulnerability scanner and brute force tools
            - '(hydra)'
            - ' arachni/'
            - ' BFAC '
            - ' brutus '
            - ' cgichk '
            - 'core-project/1.0'
            - ' crimscanner/'
            - 'datacha0s'
            - 'dirbuster'
            - 'domino hunter'
            - 'dotdotpwn'
            - 'FHScan Core'
            - 'floodgate'
            - 'get-minimal'
            - 'gootkit auto-rooter scanner'
            - 'grendel-scan'
            - ' inspath '
            - 'internet ninja'
            - 'jaascois'
            - ' zmeu '
            - 'masscan'
            - ' metis '
            - 'morfeus fucking scanner'
            - 'n-stealth'
            - 'nsauditor'
            - 'pmafind'
            - 'security scan'
            - 'springenwerk'
            - 'teh forest lobster'
            - 'toata dragostea'
            - ' vega/'
            - 'voideye'
            - 'webshag'
            - 'webvulnscan'
            - ' whcc/'
            # SQL Injection
            - ' Havij'
            - 'absinthe'
            - 'bsqlbf'
            - 'mysqloit'
            - 'pangolin'
            - 'sql power injector'
            - 'sqlmap'
            - 'sqlninja'
            - 'uil2pn'
            # Hack tool
            - 'ruler'  # https://www.crowdstrike.com/blog/using-outlook-forms-lateral-movement-persistence/
            - 'Mozilla/5.0 (Windows; U; Windows NT 5.1; pt-PT; rv:1.9.1.2) Gecko/20090729 Firefox/3.5.2 (.NET CLR 3.5.30729)'  # SQLi Dumper
    condition: selection
fields:
    - ClientIP
    - c-uri
    - c-useragent
falsepositives:
    - Unknown
level: high

```