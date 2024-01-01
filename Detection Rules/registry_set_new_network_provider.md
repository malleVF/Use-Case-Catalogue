---
title: "Potential Credential Dumping Attempt Using New NetworkProvider - REG"
status: "experimental"
created: "2022/08/23"
last_modified: "2023/08/17"
tags: [credential_access, t1003, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Potential Credential Dumping Attempt Using New NetworkProvider - REG

### Description

Detects when an attacker tries to add a new network provider in order to dump clear text credentials, similar to how the NPPSpy tool does it

```yml
title: Potential Credential Dumping Attempt Using New NetworkProvider - REG
id: 0442defa-b4a2-41c9-ae2c-ea7042fc4701
related:
    - id: baef1ec6-2ca9-47a3-97cc-4cf2bda10b77
      type: similar
status: experimental
description: Detects when an attacker tries to add a new network provider in order to dump clear text credentials, similar to how the NPPSpy tool does it
references:
    - https://docs.microsoft.com/en-us/troubleshoot/windows-client/deployment/network-provider-settings-removed-in-place-upgrade
    - https://github.com/gtworek/PSBits/tree/master/PasswordStealing/NPPSpy
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/08/23
modified: 2023/08/17
tags:
    - attack.credential_access
    - attack.t1003
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains|all:
            - '\System\CurrentControlSet\Services\'
            - '\NetworkProvider'
    filter:
        TargetObject|contains:
            - '\System\CurrentControlSet\Services\WebClient\NetworkProvider'
            - '\System\CurrentControlSet\Services\LanmanWorkstation\NetworkProvider'
            - '\System\CurrentControlSet\Services\RDPNP\NetworkProvider'
            # - '\System\CurrentControlSet\Services\P9NP\NetworkProvider' # Related to WSL remove the comment if you use WSL in your ENV
    filter_valid_procs:
        Image: C:\Windows\System32\poqexec.exe
    condition: selection and not 1 of filter*
falsepositives:
    - Other legitimate network providers used and not filtred in this rule
level: medium

```