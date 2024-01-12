---
tags: [T1125, atomic_test]
filename: "[[T1125 - Video Capture]]"
---
# T1125 - Video Capture

## Atomic Test #1 - Registry artefact when application use webcam
[can-you-track-processes-accessing-the-camera-and-microphone](https://svch0st.medium.com/can-you-track-processes-accessing-the-camera-and-microphone-7e6885b37072)

**Supported Platforms:** Windows


**auto_generated_guid:** 6581e4a7-42e3-43c5-a0d2-5a0d62f9702a






#### Attack Commands: Run with `command_prompt`! 


```cmd
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\NonPackaged\C:#Windows#Temp#atomic.exe /v LastUsedTimeStart /t REG_BINARY /d a273b6f07104d601 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\NonPackaged\C:#Windows#Temp#atomic.exe /v LastUsedTimeStop /t REG_BINARY /d 96ef514b7204d601 /f
```

#### Cleanup Commands:
```cmd
reg DELETE HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\NonPackaged\C:#Windows#Temp#atomic.exe /f
```





<br/>
