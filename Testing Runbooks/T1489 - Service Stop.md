---
tags: [T1489, atomic_test]
filename: "[[T1489 - Service Stop]]"
---
# T1489 - Service Stop

## Atomic Test #1 - Windows - Stop service using Service Controller
Stops a specified service using the sc.exe command. Upon execution, if the spooler service was running infomration will be displayed saying
it has changed to a state of STOP_PENDING. If the spooler service was not running "The service has not been started." will be displayed and it can be
started by running the cleanup command.

**Supported Platforms:** Windows


**auto_generated_guid:** 21dfb440-830d-4c86-a3e5-2a491d5a8d04





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| service_name | Name of a service to stop | string | spooler|


#### Attack Commands: Run with `command_prompt`!  Elevation Required (e.g. root or admin) 


```cmd
sc.exe stop #{service_name}
```

#### Cleanup Commands:
```cmd
sc.exe start #{service_name} >nul 2>&1
```





<br/>
<br/>

## Atomic Test #2 - Windows - Stop service using net.exe
Stops a specified service using the net.exe command. Upon execution, if the service was running "The Print Spooler service was stopped successfully."
will be displayed. If the service was not running, "The Print Spooler service is not started." will be displayed and it can be
started by running the cleanup command.

**Supported Platforms:** Windows


**auto_generated_guid:** 41274289-ec9c-4213-bea4-e43c4aa57954





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| service_name | Name of a service to stop | string | spooler|


#### Attack Commands: Run with `command_prompt`!  Elevation Required (e.g. root or admin) 


```cmd
net.exe stop #{service_name}
```

#### Cleanup Commands:
```cmd
net.exe start #{service_name} >nul 2>&1
```





<br/>
<br/>

## Atomic Test #3 - Windows - Stop service by killing process
Stops a specified service killng the service's process.
This technique was used by WannaCry. Upon execution, if the spoolsv service was running "SUCCESS: The process "spoolsv.exe" with PID 2316 has been terminated."
will be displayed. If the service was not running "ERROR: The process "spoolsv.exe" not found." will be displayed and it can be
started by running the cleanup command.

**Supported Platforms:** Windows


**auto_generated_guid:** f3191b84-c38b-400b-867e-3a217a27795f





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| process_name | Name of a process to kill | string | spoolsv.exe|


#### Attack Commands: Run with `command_prompt`! 


```cmd
taskkill.exe /f /im #{process_name}
```






<br/>
