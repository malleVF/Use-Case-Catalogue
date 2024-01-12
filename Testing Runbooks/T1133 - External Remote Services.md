---
tags: [T1133, atomic_test]
filename: "[[T1133 - External Remote Services]]"
---
# T1133 - External Remote Services

## Atomic Test #1 - Running Chrome VPN Extensions via the Registry 2 vpn extension
Running Chrome VPN Extensions via the Registry install 2 vpn extension, please see "T1133\src\list of vpn extension.txt" to view complete list

**Supported Platforms:** Windows


**auto_generated_guid:** 4c8db261-a58b-42a6-a866-0a294deedde4





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| chrome_url | chrome installer download URL | url | https://dl.google.com/tag/s/appguid%3D%7B8A69D345-D564-463C-AFF1-A69D9E530F96%7D%26iid%3D%7BFD62DDBC-14C6-20BD-706F-C7744738E422%7D%26lang%3Den%26browser%3D3%26usagestats%3D0%26appname%3DGoogle%2520Chrome%26needsadmin%3Dprefers%26ap%3Dx64-stable-statsdef_1%26installdataindex%3Dempty/chrome/install/ChromeStandaloneSetup64.exe|
| extension_id | chrome extension id | string | "fcfhplploccackoneaefokcmbjfbkenj", "fdcgdnkidjaadafnichfpabhfomcebme"|


#### Attack Commands: Run with `powershell`!  Elevation Required (e.g. root or admin) 


```powershell
$extList = #{extension_id}
foreach ($extension in $extList) {
  New-Item -Path HKLM:\Software\Wow6432Node\Google\Chrome\Extensions\$extension -Force
  New-ItemProperty -Path "HKLM:\Software\Wow6432Node\Google\Chrome\Extensions\$extension" -Name "update_url" -Value "https://clients2.google.com/service/update2/crx" -PropertyType "String" -Force}
Start chrome
Start-Sleep -Seconds 30
Stop-Process -Name "chrome"
```

#### Cleanup Commands:
```powershell
$extList = #{extension_id}
foreach ($extension in $extList) {
Remove-Item -Path "HKLM:\Software\Wow6432Node\Google\Chrome\Extensions\$extension" -ErrorAction Ignore}
```



#### Dependencies:  Run with `powershell`!
##### Description: Chrome must be installed
##### Check Prereq Commands:
```powershell
if ((Test-Path "C:\Program Files\Google\Chrome\Application\chrome.exe") -Or (Test-Path "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe")) {exit 0} else {exit 1}
```
##### Get Prereq Commands:
```powershell
New-Item -Type Directory "PathToAtomicsFolder\..\ExternalPayloads\" -ErrorAction Ignore -Force | Out-Null
Invoke-WebRequest -OutFile "PathToAtomicsFolder\..\ExternalPayloads\ChromeStandaloneSetup64.exe" #{chrome_url}
Start-Process "PathToAtomicsFolder\..\ExternalPayloads\ChromeStandaloneSetup64.exe" /S
```




<br/>
