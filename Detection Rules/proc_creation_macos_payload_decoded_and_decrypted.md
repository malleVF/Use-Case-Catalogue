---
title: "Payload Decoded and Decrypted via Built-in Utilities"
status: "test"
created: "2022/10/17"
last_modified: ""
tags: [t1059, t1204, execution, t1140, defense_evasion, s0482, s0402, detection_rule]
logsrc_product: "macos"
logsrc_service: ""
level: "medium"
---

## Payload Decoded and Decrypted via Built-in Utilities

### Description

Detects when a built-in utility is used to decode and decrypt a payload after a macOS disk image (DMG) is executed. Malware authors may attempt to evade detection and trick users into executing malicious code by encoding and encrypting their payload and placing it in a disk image file. This behavior is consistent with adware or malware families such as Bundlore and Shlayer.

```yml
title: Payload Decoded and Decrypted via Built-in Utilities
id: 234dc5df-40b5-49d1-bf53-0d44ce778eca
status: test
description: Detects when a built-in utility is used to decode and decrypt a payload after a macOS disk image (DMG) is executed. Malware authors may attempt to evade detection and trick users into executing malicious code by encoding and encrypting their payload and placing it in a disk image file. This behavior is consistent with adware or malware families such as Bundlore and Shlayer.
references:
    - https://github.com/elastic/protections-artifacts/commit/746086721fd385d9f5c6647cada1788db4aea95f#diff-5d42c3d772e04f1e8d0eb60f5233bc79def1ea73105a2d8822f44164f77ef823
author: Tim Rauch (rule), Elastic (idea)
date: 2022/10/17
tags:
    - attack.t1059
    - attack.t1204
    - attack.execution
    - attack.t1140
    - attack.defense_evasion
    - attack.s0482
    - attack.s0402
logsource:
    category: process_creation
    product: macos
detection:
    selection:
        Image|endswith: '/openssl'
        CommandLine|contains|all:
            - '/Volumes/'
            - 'enc'
            - '-base64'
            - ' -d '
    condition: selection
falsepositives:
    - Unknown
level: medium

```
