---
title: "Suspicious File Creation Activity From Fake Recycle.Bin Folder"
status: "experimental"
created: "2023/07/12"
last_modified: "2023/12/11"
tags: [persistence, defense_evasion, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Suspicious File Creation Activity From Fake Recycle.Bin Folder

### Description

Detects file write event from/to a fake recycle bin folder that is often used as a staging directory for malware

```yml
title: Suspicious File Creation Activity From Fake Recycle.Bin Folder
id: cd8b36ac-8e4a-4c2f-a402-a29b8fbd5bca
related:
    - id: 5ce0f04e-3efc-42af-839d-5b3a543b76c0
      type: derived
status: experimental
description: Detects file write event from/to a fake recycle bin folder that is often used as a staging directory for malware
references:
    - https://www.mandiant.com/resources/blog/infected-usb-steal-secrets
    - https://unit42.paloaltonetworks.com/cloaked-ursa-phishing/
author: X__Junior (Nextron Systems)
date: 2023/07/12
modified: 2023/12/11
tags:
    - attack.persistence
    - attack.defense_evasion
logsource:
    category: file_event
    product: windows
detection:
    selection:
        - Image|contains:
              # e.g. C:\$RECYCLER.BIN
              - 'RECYCLERS.BIN\'
              - 'RECYCLER.BIN\'
        - TargetFilename|contains:
              # e.g. C:\$RECYCLER.BIN
              - 'RECYCLERS.BIN\'
              - 'RECYCLER.BIN\'
    condition: selection
falsepositives:
    - Unknown
level: high

```