---
title: "Browser Started with Remote Debugging"
status: "test"
created: "2022/07/27"
last_modified: "2022/12/23"
tags: [credential_access, t1185, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Browser Started with Remote Debugging

### Description

Detects browsers starting with the remote debugging flags. Which is a technique often used to perform browser injection attacks

```yml
title: Browser Started with Remote Debugging
id: b3d34dc5-2efd-4ae3-845f-8ec14921f449
related:
    - id: 3e8207c5-fcd2-4ea6-9418-15d45b4890e4
      type: derived
status: test
description: Detects browsers starting with the remote debugging flags. Which is a technique often used to perform browser injection attacks
references:
    - https://yoroi.company/wp-content/uploads/2022/05/EternityGroup_report_compressed.pdf
    - https://www.mdsec.co.uk/2022/10/analysing-lastpass-part-1/
    - https://github.com/defaultnamehere/cookie_crimes/
    - https://github.com/wunderwuzzi23/firefox-cookiemonster
author: pH-T (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
date: 2022/07/27
modified: 2022/12/23
tags:
    - attack.credential_access
    - attack.t1185
logsource:
    category: process_creation
    product: windows
detection:
    selection_chromium_based:
        # Covers: --remote-debugging-address, --remote-debugging-port, --remote-debugging-socket-name, --remote-debugging-pipe....etc
        CommandLine|contains: ' --remote-debugging-'
    selection_firefox:
        Image|endswith: '\firefox.exe'
        CommandLine|contains: ' -start-debugger-server'
    condition: 1 of selection_*
falsepositives:
    - Unknown
level: medium

```