---
title: "Suspicious Installer Package Child Process"
status: "experimental"
created: "2023/02/18"
last_modified: ""
tags: [t1059, t1059_007, t1071, t1071_001, execution, command_and_control, detection_rule]
logsrc_product: "macos"
logsrc_service: ""
level: "medium"
---

## Suspicious Installer Package Child Process

### Description

Detects the execution of suspicious child processes from macOS installer package parent process. This includes osascript, JXA, curl and wget amongst other interpreters

```yml
title: Suspicious Installer Package Child Process
id: e0cfaecd-602d-41af-988d-f6ccebb2af26
status: experimental
description: Detects the execution of suspicious child processes from macOS installer package parent process. This includes osascript, JXA, curl and wget amongst other interpreters
references:
    - https://redcanary.com/blog/clipping-silver-sparrows-wings/
    - https://github.com/elastic/detection-rules/blob/4312d8c9583be524578a14fe6295c3370b9a9307/rules/macos/execution_installer_package_spawned_network_event.toml
author: Sohan G (D4rkCiph3r)
date: 2023/02/18
tags:
    - attack.t1059
    - attack.t1059.007
    - attack.t1071
    - attack.t1071.001
    - attack.execution
    - attack.command_and_control
logsource:
    category: process_creation
    product: macos
detection:
    selection_installer:
        ParentImage|endswith:
            - '/package_script_service'
            - '/installer'
        Image|endswith:
            - '/sh'
            - '/bash'
            - '/dash'
            - '/python'
            - '/ruby'
            - '/perl'
            - '/php'
            - '/javascript'
            - '/osascript'
            - '/tclsh'
            - '/curl'
            - '/wget'
        CommandLine|contains:
            - 'preinstall'
            - 'postinstall'
    condition: selection_installer
falsepositives:
    - Legitimate software uses the scripts (preinstall, postinstall)
level: medium

```
