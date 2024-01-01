---
title: "Windows WebDAV User Agent"
status: "test"
created: "2018/04/06"
last_modified: "2021/11/27"
tags: [command_and_control, t1071_001, detection_rule]
logsrc_product: ""
logsrc_service: ""
level: "high"
---

## Windows WebDAV User Agent

### Description

Detects WebDav DownloadCradle

```yml
title: Windows WebDAV User Agent
id: e09aed7a-09e0-4c9a-90dd-f0d52507347e
status: test
description: Detects WebDav DownloadCradle
references:
    - https://mgreen27.github.io/posts/2018/04/02/DownloadCradle.html
author: Florian Roth (Nextron Systems)
date: 2018/04/06
modified: 2021/11/27
tags:
    - attack.command_and_control
    - attack.t1071.001
logsource:
    category: proxy
detection:
    selection:
        c-useragent|startswith: 'Microsoft-WebDAV-MiniRedir/'
        cs-method: 'GET'
    condition: selection
fields:
    - ClientIP
    - c-uri
    - c-useragent
    - cs-method
falsepositives:
    - Administrative scripts that download files from the Internet
    - Administrative scripts that retrieve certain website contents
    - Legitimate WebDAV administration
level: high

```
