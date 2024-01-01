---
title: "Default Cobalt Strike Certificate"
status: "test"
created: "2021/06/23"
last_modified: "2022/10/09"
tags: [command_and_control, s0154, detection_rule]
logsrc_product: "zeek"
logsrc_service: "x509"
level: "high"
---

## Default Cobalt Strike Certificate

### Description

Detects the presence of default Cobalt Strike certificate in the HTTPS traffic

```yml
title: Default Cobalt Strike Certificate
id: 7100f7e3-92ce-4584-b7b7-01b40d3d4118
status: test
description: Detects the presence of default Cobalt Strike certificate in the HTTPS traffic
references:
    - https://sergiusechel.medium.com/improving-the-network-based-detection-of-cobalt-strike-c2-servers-in-the-wild-while-reducing-the-6964205f6468
author: Bhabesh Raj
date: 2021/06/23
modified: 2022/10/09
tags:
    - attack.command_and_control
    - attack.s0154
logsource:
    product: zeek
    service: x509
detection:
    selection:
        certificate.serial: 8BB00EE
    condition: selection
fields:
    - san.dns
    - certificate.subject
    - certificate.issuer
falsepositives:
    - Unknown
level: high

```
