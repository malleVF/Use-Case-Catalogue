---
title: "Dump Credentials from Windows Credential Manager With PowerShell"
status: "test"
created: "2021/12/20"
last_modified: "2022/12/25"
tags: [credential_access, t1555, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Dump Credentials from Windows Credential Manager With PowerShell

### Description

Adversaries may search for common password storage locations to obtain user credentials.
Passwords are stored in several places on a system, depending on the operating system or application holding the credentials.


```yml
title: Dump Credentials from Windows Credential Manager With PowerShell
id: 99c49d9c-34ea-45f7-84a7-4751ae6b2cbc
status: test
description: |
    Adversaries may search for common password storage locations to obtain user credentials.
    Passwords are stored in several places on a system, depending on the operating system or application holding the credentials.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1555/T1555.md
author: frack113
date: 2021/12/20
modified: 2022/12/25
tags:
    - attack.credential_access
    - attack.t1555
logsource:
    product: windows
    category: ps_script
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    selection_kiddie:
        ScriptBlockText|contains:
            - 'Get-PasswordVaultCredentials'
            - 'Get-CredManCreds'
    selection_rename_Password:
        ScriptBlockText|contains|all:
            - 'New-Object'
            - 'Windows.Security.Credentials.PasswordVault'
    selection_rename_credman:
        ScriptBlockText|contains|all:
            - 'New-Object'
            - 'Microsoft.CSharp.CSharpCodeProvider'
            - '[System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())'
            - 'Collections.ArrayList'
            - 'System.CodeDom.Compiler.CompilerParameters'
    condition: 1 of selection_*
falsepositives:
    - Unknown
level: medium

```
