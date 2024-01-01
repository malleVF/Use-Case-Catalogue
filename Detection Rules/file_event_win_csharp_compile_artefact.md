---
title: "Dynamic CSharp Compile Artefact"
status: "test"
created: "2022/01/09"
last_modified: "2023/02/17"
tags: [defense_evasion, t1027_004, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "low"
---

## Dynamic CSharp Compile Artefact

### Description

When C# is compiled dynamically, a .cmdline file will be created as a part of the process.
Certain processes are not typically observed compiling C# code, but can do so without touching disk.
This can be used to unpack a payload for execution


```yml
title: Dynamic CSharp Compile Artefact
id: e4a74e34-ecde-4aab-b2fb-9112dd01aed0
status: test
description: |
    When C# is compiled dynamically, a .cmdline file will be created as a part of the process.
    Certain processes are not typically observed compiling C# code, but can do so without touching disk.
    This can be used to unpack a payload for execution
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1027.004/T1027.004.md#atomic-test-2---dynamic-c-compile
author: frack113
date: 2022/01/09
modified: 2023/02/17
tags:
    - attack.defense_evasion
    - attack.t1027.004
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|endswith: '.cmdline'
    condition: selection
falsepositives:
    - Unknown
level: low

```
