---
title: "Potential RemoteFXvGPUDisablement.EXE Abuse - PowerShell Module"
status: "experimental"
created: "2021/07/13"
last_modified: "2023/05/09"
tags: [defense_evasion, t1218, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Potential RemoteFXvGPUDisablement.EXE Abuse - PowerShell Module

### Description

Detects PowerShell module creation where the module Contents are set to "function Get-VMRemoteFXPhysicalVideoAdapter". This could be a sign of potential abuse of the "RemoteFXvGPUDisablement.exe" binary which is known to be vulnerable to module load-order hijacking.

```yml
title: Potential RemoteFXvGPUDisablement.EXE Abuse - PowerShell Module
id: 38a7625e-b2cb-485d-b83d-aff137d859f4
related:
    - id: a6fc3c46-23b8-4996-9ea2-573f4c4d88c5 # ProcCreation
      type: similar
    - id: f65e22f9-819e-4f96-9c7b-498364ae7a25 # PS Classic
      type: similar
    - id: cacef8fc-9d3d-41f7-956d-455c6e881bc5 # PS ScriptBlock
      type: similar
status: experimental
description: Detects PowerShell module creation where the module Contents are set to "function Get-VMRemoteFXPhysicalVideoAdapter". This could be a sign of potential abuse of the "RemoteFXvGPUDisablement.exe" binary which is known to be vulnerable to module load-order hijacking.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1218/T1218.md
    - https://github.com/redcanaryco/AtomicTestHarnesses/blob/7e1e4da116801e3d6fcc6bedb207064577e40572/TestHarnesses/T1218_SignedBinaryProxyExecution/InvokeRemoteFXvGPUDisablementCommand.ps1
author: Nasreddine Bencherchali (Nextron Systems), frack113
date: 2021/07/13
modified: 2023/05/09
tags:
    - attack.defense_evasion
    - attack.t1218
logsource:
    product: windows
    category: ps_module
    definition: 0ad03ef1-f21b-4a79-8ce8-e6900c54b65b
detection:
    selection:
        Payload|contains: 'ModuleContents=function Get-VMRemoteFXPhysicalVideoAdapter {'
    condition: selection
falsepositives:
    - Unknown
level: high

```