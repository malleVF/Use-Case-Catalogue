---
title: "Suspicious Atbroker Execution"
status: "test"
created: "2020/10/12"
last_modified: "2022/10/09"
tags: [defense_evasion, t1218, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Suspicious Atbroker Execution

### Description

Atbroker executing non-deafualt Assistive Technology applications

```yml
title: Suspicious Atbroker Execution
id: f24bcaea-0cd1-11eb-adc1-0242ac120002
status: test
description: Atbroker executing non-deafualt Assistive Technology applications
references:
    - http://www.hexacorn.com/blog/2016/07/22/beyond-good-ol-run-key-part-42/
    - https://lolbas-project.github.io/lolbas/Binaries/Atbroker/
author: Mateusz Wydra, oscd.community
date: 2020/10/12
modified: 2022/10/09
tags:
    - attack.defense_evasion
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: 'AtBroker.exe'
        CommandLine|contains: 'start'
    filter:
        CommandLine|contains:
            - animations
            - audiodescription
            - caretbrowsing
            - caretwidth
            - colorfiltering
            - cursorscheme
            - filterkeys
            - focusborderheight
            - focusborderwidth
            - highcontrast
            - keyboardcues
            - keyboardpref
            - magnifierpane
            - messageduration
            - minimumhitradius
            - mousekeys
            - Narrator
            - osk
            - overlappedcontent
            - showsounds
            - soundsentry
            - stickykeys
            - togglekeys
            - windowarranging
            - windowtracking
            - windowtrackingtimeout
            - windowtrackingzorder
    condition: selection and not filter
falsepositives:
    - Legitimate, non-default assistive technology applications execution
level: high

```
