---
tags: [T1547, atomic_test]
filename: "[[T1547 - Boot or Logon Autostart Execution]]"
---
# T1547 - Boot or Logon Autostart Execution

## Atomic Test #1 - Add a driver
Install a driver via pnputil.exe lolbin

**Supported Platforms:** Windows


**auto_generated_guid:** cb01b3da-b0e7-4e24-bf6d-de5223526785





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| driver_inf | A built-in, already installed windows driver inf | path | C:&#92;Windows&#92;INF&#92;usbstor.inf|


#### Attack Commands: Run with `command_prompt`! 


```cmd
pnputil.exe /add-driver "#{driver_inf}"
```






<br/>
