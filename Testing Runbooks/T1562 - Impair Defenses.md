---
tags: [T1562, atomic_test]
filename: "[[T1562 - Impair Defenses]]"
---
# T1562 - Impair Defenses

## Atomic Test #1 - Windows Disable LSA Protection
The following Atomic adds a registry entry to disable LSA Protection.

The LSA controls and manages user rights information, password hashes and other important bits of information in memory. Attacker tools, such as mimikatz, rely on accessing this content to scrape password hashes or clear-text passwords. Enabling LSA Protection configures Windows to control the information stored in memory in a more secure fashion - specifically, to prevent non-protected processes from accessing that data.
Upon successful execution, the registry will be modified and RunAsPPL will be set to 0, disabling Lsass protection.
https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection#how-to-disable-lsa-protection
https://blog.netwrix.com/2022/01/11/understanding-lsa-protection/
https://thedfirreport.com/2022/03/21/phosphorus-automates-initial-access-using-proxyshell/

**Supported Platforms:** Windows


**auto_generated_guid:** 40075d5f-3a70-4c66-9125-f72bee87247d






#### Attack Commands: Run with `command_prompt`!  Elevation Required (e.g. root or admin) 


```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL /t REG_DWORD /d 0 /f
```

#### Cleanup Commands:
```cmd
reg delete HKLM\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL /f >nul 2>&1
```





<br/>
<br/>

## Atomic Test #2 - Disable journal logging via systemctl utility
The atomic test disables the journal logging using built-in systemctl utility

**Supported Platforms:** Linux


**auto_generated_guid:** c3a377f9-1203-4454-aa35-9d391d34768f






#### Attack Commands: Run with `sh`!  Elevation Required (e.g. root or admin) 


```sh
sudo systemctl stop systemd-journald #disables journal logging
```

#### Cleanup Commands:
```sh
sudo systemctl start systemd-journald #starts journal service
sudo systemctl enable systemd-journald #starts journal service automatically at boot time
```





<br/>
<br/>

## Atomic Test #3 - Disable journal logging via sed utility
The atomic test disables the journal logging by searching and replacing the "Storage" parameter to "none" within the journald.conf file, thus any new journal entries will only be temporarily available in memory and not written to disk

**Supported Platforms:** Linux


**auto_generated_guid:** 12e5551c-8d5c-408e-b3e4-63f53b03379f






#### Attack Commands: Run with `sh`!  Elevation Required (e.g. root or admin) 


```sh
sudo sed -i 's/Storage=auto/Storage=none/' /etc/systemd/journald.conf
```

#### Cleanup Commands:
```sh
sudo sed -i 's/Storage=none/Storage=auto/' /etc/systemd/journald.conf #re-enables storage of journal data
sudo systemctl restart systemd-journald #restart the journal service
```





<br/>
