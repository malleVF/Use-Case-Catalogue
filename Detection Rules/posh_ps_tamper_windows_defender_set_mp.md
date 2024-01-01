---
title: "Tamper Windows Defender - ScriptBlockLogging"
status: "experimental"
created: "2022/01/16"
last_modified: "2023/06/21"
tags: [defense_evasion, t1562_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Tamper Windows Defender - ScriptBlockLogging

### Description

Detects PowerShell scripts attempting to disable scheduled scanning and other parts of Windows Defender ATP or set default actions to allow.

```yml
title: Tamper Windows Defender - ScriptBlockLogging
id: 14c71865-6cd3-44ae-adaa-1db923fae5f2
related:
    - id: ec19ebab-72dc-40e1-9728-4c0b805d722c
      type: derived
status: experimental
description: Detects PowerShell scripts attempting to disable scheduled scanning and other parts of Windows Defender ATP or set default actions to allow.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.001/T1562.001.md
    - https://docs.microsoft.com/en-us/powershell/module/defender/set-mppreference?view=windowsserver2022-ps
    - https://bidouillesecurity.com/disable-windows-defender-in-powershell/
author: frack113, elhoim, Tim Shelton (fps, alias support), Swachchhanda Shrawan Poudel, Nasreddine Bencherchali (Nextron Systems)
date: 2022/01/16
modified: 2023/06/21
tags:
    - attack.defense_evasion
    - attack.t1562.001
logsource:
    product: windows
    category: ps_script
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    selection_options_disabling_preference:
        ScriptBlockText|contains: 'Set-MpPreference'
    selection_options_disabling_function:
        ScriptBlockText|contains:
            - '-dbaf $true'
            - '-dbaf 1'
            - '-dbm $true'
            - '-dbm 1'
            - '-dips $true'
            - '-dips 1'
            - '-DisableArchiveScanning $true'
            - '-DisableArchiveScanning 1'
            - '-DisableBehaviorMonitoring $true'
            - '-DisableBehaviorMonitoring 1'
            - '-DisableBlockAtFirstSeen $true'
            - '-DisableBlockAtFirstSeen 1'
            - '-DisableIntrusionPreventionSystem $true'
            - '-DisableIntrusionPreventionSystem 1'
            - '-DisableIOAVProtection $true'
            - '-DisableIOAVProtection 1'
            - '-DisableRealtimeMonitoring $true'
            - '-DisableRealtimeMonitoring 1'
            - '-DisableRemovableDriveScanning $true'
            - '-DisableRemovableDriveScanning 1'
            - '-DisableScanningMappedNetworkDrivesForFullScan $true'
            - '-DisableScanningMappedNetworkDrivesForFullScan 1'
            - '-DisableScanningNetworkFiles $true'
            - '-DisableScanningNetworkFiles 1'
            - '-DisableScriptScanning $true'
            - '-DisableScriptScanning 1'
            - '-drdsc $true'
            - '-drdsc 1'
            - '-drtm $true'
            - '-drtm 1'
            - '-dscrptsc $true'
            - '-dscrptsc 1'
            - '-dsmndf $true'
            - '-dsmndf 1'
            - '-dsnf $true'
            - '-dsnf 1'
            - '-dss $true'
            - '-dss 1'
    selection_other_default_actions_allow:
        ScriptBlockText|contains: 'Set-MpPreference'
    selection_other_default_actions_func:
        ScriptBlockText|contains:
            - 'HighThreatDefaultAction Allow'
            - 'htdefac Allow'
            - 'LowThreatDefaultAction Allow'
            - 'ltdefac Allow'
            - 'ModerateThreatDefaultAction Allow'
            - 'mtdefac Allow'
            - 'SevereThreatDefaultAction Allow'
            - 'stdefac Allow'
    condition: all of selection_options_disabling_* or all of selection_other_default_actions_*
falsepositives:
    - Legitimate PowerShell scripts that disable Windows Defender for troubleshooting purposes. Must be investigated.
level: high

```