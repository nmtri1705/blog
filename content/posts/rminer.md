---
title: "Recovering Ransomware-Deleted Files from Sysmon Archives and MFT Resident Data"
description: "A walkthrough of “The miner that mined the victim” challenge from Hi Cyber Con 2026, tracing the ransomware attack and recovering deleted files."
publishDate: "2026-11-2"
tags: ["malware", "disk", "ctf", "ransomware"]
section: "posts"
draft: False
coverImage:
  src: "/images/hiCTF/HI_Cyber_Con_2026__CTFtime_Logo__Transparent.png"
  alt: "thumbnail"
---
```text
============================    ================================
            The miner that mined the victim
============================================================
Scenario:
A user was desperate to find quick ways to earn money online. After browsing for free earning tricks, crypto mining tools, and cracked software, they found a Telegraph page advertising "CoinBoost Pro v3.2 - Free Mining Optimizer".
The page claimed the tool could improve mining performance, auto-select profitable pools, track daily earnings, and unlock premium features for free.
Soon after running the downloaded binary, the victim noticed that several text files were no longer readable and a ransom note appeared on the Desktop. In panic, the victim deleted the folder that contained the suspicious program, thinking the infection would be removed.
You have been given a triage-style C drive artifact collection from the victim machine. Reconstruct the attack chain and understand what actually happened in there.
Note: The triage may contains live malicious software. Interact with the triage cautiously

============================================================
```
`SHA-256: 5ac6011a696266ecaa40b9cb4948a247a6a3ca1ebe465cc60249c170d77d2182`<br>
Tools used: `FTK Imager`, `Sysmon View`, `Registry Explorer`, `PECmd`, `MFTECmd`, `Timeline Explorer`, `HxD`.
# Investigation
At first glance, the `Document` folder contains several encrypted `.vibed` files. Using `MFTECmd` to parse `$MFT` file then we know there were 34 file text was encrypted.
![encrypted](/images/hiCTF/count.png)
Inspect browser history in `C:\Users\milon1\AppData\Local\Microsoft\Edge\User Data\Default\History`. User download suspicious archive `miner.zip` relating to this scenario
![url](/images/hiCTF/url.png)
The files were encrypted around `2026-05-13 14:27:00 UTC`. I found evidence in the `Prefetch` artifacts that `miner.exe` had executed shortly before that time.
![prefetch](/images/hiCTF/prefetch.png)
However, I didn't found `miner.exe` in artifact, because it have been delete from system. 
![bin](/images/hiCTF/bin.png)
Then, how to recover those encrypted files ? <br> In this case, we don't need to decrypt those files because it still resident in `$MFT` record.<br>
In `Event log`, I found `Sysmon` log is avaiable in the system. This may help us recover deleted orginal file. I used [Sysmon View](https://github.com/nshalabi/SysmonTools) to easily inspect sysmon log

![sysmon](/images/hiCTF/sysmon.png)
The ransomware encrypted the files by writing the ciphertext to new files and then deleting the originals, rather than encrypting them in place. <br>However, Sysmon Event ID `23` recorded these deletions with `Archived=true`, indicating that copies of the original files had been preserved. Using the hashes recorded in these events, we located the corresponding archived files in the MFT and recovered their plaintext from the resident `$DATA` attributes.<br>
Search for hash `9398192738C982338B3788C3E9F3583B` of `vzcbegnag.txt` file. Then we got content of this file is `hiCTF{finally_u_proved_ur_worthiness}`<br>

![image](/images/hiCTF/important.png)
For more information about [$MFT Resident Data](https://www.mftparser.com/en/blog/resident-data)
# Q&A
**[Question 1/14]  
What is the OS version recorded during malware execution?**
> Microsoft Windows NT 10.0.26200.0

In `ransomware_debug.log`, we found `OS Version: Microsoft Windows NT 10.0.26200.0`.
**[Question 2/14]  
What effective UTC offset did the victim machine use during the incident, and what ActiveTimeBias value proves it?  
(\*\*\*-\*, \*\*\*)**
> UTC-7, 420


**[Question 3/14]  
What external URL, including the fragment, was used to download the malicious binary?**
> https://limewire.com/d/Ak55K#Yrx3FgK3du

In `C:\Users\milon1\AppData\Local\Microsoft\Edge\User Data\Default\History`<br>
**[Question 4/14]  
What is the downloadId GUID in the redirect URL used to deliver the malicious ZIP?**
> 42d377fe-8948-4a32-809f-69a51e6dbcfa

![guid](/images/hiCTF/guid.png)<br>
**[Question 5/14]  
At what exact UTC time did the browser finish downloading the malicious binary onto the victim machine? (yyyy-mm-dd hh:mm:ss UTC)**
> 2026-05-13 14:25:36 UTC

![time](/images/hiCTF/download_time.png)
**[Question 6/14]  
The victim later deleted the suspicious folder. Determine whether the program actually ran, when it first ran, and how many times it was launched. (yyyy-mm-dd hh:mm:ss UTC, count)**

> 2026-05-13 14:26:55 UTC, 1

Pasrse `C\Windows\Prefetch\MINER.EXE-9A2B223D.pf` into `PECmd`<br>

**[Question 7/14]  
Which .NET cryptography assembly did miner.exe load before the first .vibed file was created? Give its full path and the exact UTC timestamp of that load. (full path, yyyy-mm-dd hh:mm:ss UTC)**

> C:\Program Files\dotnet\shared\Microsoft.NETCore.App\9.0.16\System.Security.Cryptography.dll, 2026-05-13 14:26:58 UTC

![cryptol](/images/hiCTF/crypto_load.png)

**[Question 8/14]  
Which registry value did the payload successfully modify? (full registry value)**

> HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware

![registry](/images/hiCTF/registry.png)

**[Question 9/14]  
Which current MITRE ATT&CK technique ID corresponds to the suspicious security-control modification observed after the payload ran?**

> T1685

**[Question 10/14]  
Recover the important text from triage artifacts.**

> hiCTF{finally_u_proved_ur_worthiness}

`vzcbegnag` ROT13 --> `important`


**[Question 11/14]  
The victim deleted the malware folder. What exact original path was recorded for that deleted folder, and at what exact UTC time was it deleted? (full path, yyyy-mm-dd hh:mm:ss UTC)**

> C:\Users\milon1\Downloads\miner, 2026-05-13 14:27:47 UTC

Check file `$IGDL3PH` with record number `1904`, the address of MFT record is `1904 * 1024 (size of each record) = 1953792`
![folder](/images/hiCTF/ibin.png) <br>
**[Question 12/14]  
What is the exact byte size of the deleted miner folder?**

> 179623

![i](/images/hiCTF/i.png)
`80 00 00 00` is header of `$DATA` attribute<br>`78 00 00 00` --> `120` bytes is length of attribute<br> `A7 BD 02 00 00 00 00 00` --> `179623` bytes is size of deleted folder<br> `50 BA F3 AB E4 E2 DC 01` represents the deletion timestamp stored as a little-endian Windows FILETIME value, which decodes to `2026-05-13 14:27:47.957 UTC`. <br>
**[Question 13/14]  
Recover the plaintext of the deleted document bar.txt.**

> I will always be there for you bro!

**[Question 14/14]  
The deleted file noting.txt was overwritten with a 32-bit shred pattern. What four-character ASCII string is formed by the bytes of that pattern as stored on disk?**

> help

![image](/images/hiCTF/noting.png)
`0x706c6568` --> `help`<br>

All questions answered correctly!
<br>Flag: `hiCTF{c4r3ful_4b0ut_cr4ck3d_t001s_0fe10d9168}`