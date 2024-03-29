---
title: "Linux Doas Conf File Creation"
status: "stable"
created: "2022/01/20"
last_modified: "2022/12/31"
tags: [privilege_escalation, t1548, detection_rule]
logsrc_product: "linux"
logsrc_service: ""
level: "medium"
---

## Linux Doas Conf File Creation

### Description

Detects the creation of doas.conf file in linux host platform.

```yml
title: Linux Doas Conf File Creation
id: 00eee2a5-fdb0-4746-a21d-e43fbdea5681
status: stable
description: Detects the creation of doas.conf file in linux host platform.
references:
    - https://research.splunk.com/endpoint/linux_doas_conf_file_creation/
    - https://www.makeuseof.com/how-to-install-and-use-doas/
author: Sittikorn S, Teoderick Contreras
date: 2022/01/20
modified: 2022/12/31
tags:
    - attack.privilege_escalation
    - attack.t1548
logsource:
    product: linux
    category: file_event
detection:
    selection:
        TargetFilename|endswith: '/etc/doas.conf'
    condition: selection
falsepositives:
    - Unlikely
level: medium

```
