---
title: "Invoke-Obfuscation Obfuscated IEX Invocation - Security"
status: "test"
created: "2019/11/08"
last_modified: "2022/11/27"
tags: [defense_evasion, t1027, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "high"
---

## Invoke-Obfuscation Obfuscated IEX Invocation - Security

### Description

Detects all variations of obfuscated powershell IEX invocation code generated by Invoke-Obfuscation framework from the code block linked in the references

```yml
title: Invoke-Obfuscation Obfuscated IEX Invocation - Security
id: fd0f5778-d3cb-4c9a-9695-66759d04702a
related:
    - id: 51aa9387-1c53-4153-91cc-d73c59ae1ca9
      type: derived
status: test
description: Detects all variations of obfuscated powershell IEX invocation code generated by Invoke-Obfuscation framework from the code block linked in the references
references:
    - https://github.com/danielbohannon/Invoke-Obfuscation/blob/f20e7f843edd0a3a7716736e9eddfa423395dd26/Out-ObfuscatedStringCommand.ps1#L873-L888
author: Daniel Bohannon (@Mandiant/@FireEye), oscd.community
date: 2019/11/08
modified: 2022/11/27
tags:
    - attack.defense_evasion
    - attack.t1027
logsource:
    product: windows
    service: security
    definition: The 'System Security Extension' audit subcategory need to be enabled to log the EID 4697
detection:
    selection_eid:
        EventID: 4697
    selection_servicefilename:
        - ServiceFileName|re: '\$PSHome\[\s*\d{1,3}\s*\]\s*\+\s*\$PSHome\['
        - ServiceFileName|re: '\$ShellId\[\s*\d{1,3}\s*\]\s*\+\s*\$ShellId\['
        - ServiceFileName|re: '\$env:Public\[\s*\d{1,3}\s*\]\s*\+\s*\$env:Public\['
        - ServiceFileName|re: '\$env:ComSpec\[(\s*\d{1,3}\s*,){2}'
        - ServiceFileName|re: '\\*mdr\*\W\s*\)\.Name'
        - ServiceFileName|re: '\$VerbosePreference\.ToString\('
        - ServiceFileName|re: '\String\]\s*\$VerbosePreference'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high

```