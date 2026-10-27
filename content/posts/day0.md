---
title: "Day-O"
description: "A document review session took an unexpected turn. Examine a Windows memory capture to reconstruct what ran, trace the suspicious activity, and recover what was left behind."
publishDate: "2026-10-25"
tags: ["downtime", "medium", "malware", "memory", "thm"]
section: "blue"
draft: False
coverImage:
  src: "/images/Day0/day0_thumbnail.png"
  alt: "thumbnail"
---
![sumary](/images/Day0/brief.png)

# Walkthrough
I inspected the output of `pslist` and `cmdline` and identified a suspicious process named `ReviewClient.exe`.
![pslist](/images/Day0/pslist.png)
![cmdline](/images/Day0/cmdline.png)
I then examined the `malfind` output and identified shellcode in a private executable memory region of `ReviewClient.exe` process.

```shell
$ vol -f memory.mem windows.malfind --pid 6260 --dump

6260	ReviewClient.e	0x8e0000	0x8e0fff	VadS	PAGE_EXECUTE_READWRITE	1	1	Disabled	Function prologue	
55 89 e5 83 ec 18 31 f6 56 6a 63 66 68 78 65 68 U.....1.Vjcfhxeh
57 69 6e 45 89 65 fc 64 8b 5e 30 8b 5b 0c 8b 5b WinE.e.d.^0.[..[
14 8b 1b 8b 1b 8b 5b 10 89 5d f8 8b 43 3c 01 d8 ......[..]..C<..
8b 40 78 01 d8 8b 48 24 01 d9 89 4d f4 31 c9 41 .@x...H$...M.1.A	
0x8e0000:	push	ebp
0x8e0001:	mov	ebp, esp
0x8e0003:	sub	esp, 0x18
0x8e0006:	xor	esi, esi
0x8e0008:	push	esi
0x8e0009:	push	0x63
0x8e000b:	push	0x6578
0x8e000f:	push	0x456e6957
0x8e0014:	mov	dword ptr [ebp - 4], esp
0x8e0017:	mov	ebx, dword ptr fs:[esi + 0x30]
0x8e001b:	mov	ebx, dword ptr [ebx + 0xc]
0x8e001e:	mov	ebx, dword ptr [ebx + 0x14]
0x8e0021:	mov	ebx, dword ptr [ebx]
0x8e0023:	mov	ebx, dword ptr [ebx]
0x8e0025:	mov	ebx, dword ptr [ebx + 0x10]
0x8e0028:	mov	dword ptr [ebp - 8], ebx
0x8e002b:	mov	eax, dword ptr [ebx + 0x3c]
0x8e002e:	add	eax, ebx
0x8e0030:	mov	eax, dword ptr [eax + 0x78]
0x8e0033:	add	eax, ebx
0x8e0035:	mov	ecx, dword ptr [eax + 0x24]
0x8e0038:	add	ecx, ebx
0x8e003a:	mov	dword ptr [ebp - 0xc], ecx
0x8e003d:	xor	ecx, ecx
0x8e003f:	inc	ecx
```
![dissasm](/images/Day0/dissambler.png)
```
00000000 55                              PUSH EBP
00000001 89E5                            MOV EBP,ESP
00000003 83EC18                          SUB ESP,00000018
00000006 31F6                            XOR ESI,ESI
00000008 56                              PUSH ESI
00000009 6A63                            PUSH 00000063
0000000B 66687865                        PUSH 6578
0000000F 6857696E45                      PUSH 456E6957
00000014 8965FC                          MOV DWORD PTR [EBP-04],ESP
00000017 648B5E30                        MOV EBX,DWORD PTR FS:[ESI+30]
0000001B 8B5B0C                          MOV EBX,DWORD PTR [EBX+0C]
0000001E 8B5B14                          MOV EBX,DWORD PTR [EBX+14]
00000021 8B1B                            MOV EBX,DWORD PTR [EBX]
00000023 8B1B                            MOV EBX,DWORD PTR [EBX]
00000025 8B5B10                          MOV EBX,DWORD PTR [EBX+10]
00000028 895DF8                          MOV DWORD PTR [EBP-08],EBX
0000002B 8B433C                          MOV EAX,DWORD PTR [EBX+3C]
0000002E 01D8                            ADD EAX,EBX
00000030 8B4078                          MOV EAX,DWORD PTR [EAX+78]
00000033 01D8                            ADD EAX,EBX
00000035 8B4824                          MOV ECX,DWORD PTR [EAX+24]
00000038 01D9                            ADD ECX,EBX
0000003A 894DF4                          MOV DWORD PTR [EBP-0C],ECX
0000003D 31C9                            XOR ECX,ECX
0000003F 41                              INC ECX
00000040 C1E105                          SHL ECX,05
00000043 8B3C08                          MOV EDI,DWORD PTR [EAX+ECX]
00000046 01DF                            ADD EDI,EBX
00000048 897DF0                          MOV DWORD PTR [EBP-10],EDI
0000004B 8B501C                          MOV EDX,DWORD PTR [EAX+1C]
0000004E 01DA                            ADD EDX,EBX
00000050 8955EC                          MOV DWORD PTR [EBP-14],EDX
00000053 8B5814                          MOV EBX,DWORD PTR [EAX+14]
00000056 31C0                            XOR EAX,EAX
00000058 8B55F8                          MOV EDX,DWORD PTR [EBP-08]
0000005B 8B7DF0                          MOV EDI,DWORD PTR [EBP-10]
0000005E 8B75FC                          MOV ESI,DWORD PTR [EBP-04]
00000061 31C9                            XOR ECX,ECX
00000063 FC                              CLD
00000064 8B3C87                          MOV EDI,DWORD PTR [EDI+EAX*4]
00000067 01D7                            ADD EDI,EDX
00000069 6683C108                        ADD CX,0008
0000006D F3A6                            REP  CMPS BYTE PTR [EDI],BYTE PTR [ESI]
0000006F 7406                            JE 00000077
00000071 40                              INC EAX
00000072 39D8                            CMP EAX,EBX
00000074 72E5                            JB 0000005B
00000076 C3                              RET
00000077 8B4DF4                          MOV ECX,DWORD PTR [EBP-0C]
0000007A 89D3                            MOV EBX,EDX
0000007C 8B55EC                          MOV EDX,DWORD PTR [EBP-14]
0000007F 668B0441                        MOV AX,WORD PTR [ECX+EAX*2]
00000083 8B0482                          MOV EAX,DWORD PTR [EDX+EAX*4]
00000086 01D8                            ADD EAX,EBX
00000088 31C9                            XOR ECX,ECX
0000008A 51                              PUSH ECX
0000008B 89E1                            MOV ECX,ESP
0000008D 6866622525                      PUSH 25256266
00000092 6876667076                      PUSH 76706676
00000097 686690666C                      PUSH 6C669066
0000009C 6888667166                      PUSH 66716688
000000A1 68679C6668                      PUSH 68669C67
000000A6 6894668676                      PUSH 76866694
000000AB 68669A666D                      PUSH 6D669A66
000000B0 688C667F76                      PUSH 767F668C
000000B5 68678F666C                      PUSH 6C668F67
000000BA 6872667E76                      PUSH 767E6672
000000BF 686699666C                      PUSH 6C669966
000000C4 687A66899C                      PUSH 9C89667A
000000C9 686795666C                      PUSH 6C669567
000000CE 687A66898C                      PUSH 8C89667A
000000D3 68679E666C                      PUSH 6C669E67
000000D8 688C666F9C                      PUSH 9C6F668C
000000DD 68679F6668                      PUSH 68669F67
000000E2 6876667F76                      PUSH 767F6676
000000E7 68675A666D                      PUSH 6D665A67
000000EC 689C66768C                      PUSH 8C76669C
000000F1 686798666C                      PUSH 6C669867
000000F6 687A667676                      PUSH 7676667A
000000FB 686755666C                      PUSH 6C665567
00000100 686E668676                      PUSH 7686666E
00000105 68677D666D                      PUSH 6D667D67
0000010A 689466748C                      PUSH 8C746694
0000010F 6867896669                      PUSH 69668967

[...]
000050B 68948B8E91                      PUSH 918E8B94
00000510 6873947597                      PUSH 97759473
00000515 689D8A4552                      PUSH 52458A9D
0000051A 689191538A                      PUSH 8A539191
0000051F 6897988D8A                      PUSH 8A8D9897
00000524 6895949C8A                      PUSH 8A9C9495
00000529 49                              DEC ECX
0000052A 29E1                            SUB ECX,ESP
0000052C 802C0C25                        SUB BYTE PTR [ESP+ECX],25
00000530 E2FA                            LOOP 0000052C
00000532 802C2425                        SUB BYTE PTR [ESP],25
00000536 89E6                            MOV ESI,ESP
00000538 6A05                            PUSH 00000005
0000053A 56                              PUSH ESI
0000053B FFD0                            CALL EAX
0000053D 89EC                            MOV ESP,EBP
0000053F 5D                              POP EBP
00000540 C3                              RET
00000541 0000                            ADD BYTE PTR [EAX],AL
00000543 0000                            ADD BYTE PTR [EAX],AL
00000545 0000                            ADD BYTE PTR [EAX],AL
00000547 0000                            ADD BYTE PTR [EAX],AL
00000549 0000                            ADD BYTE PTR [EAX],AL
0000054B 0000                            ADD BYTE PTR [EAX],AL
0000054D 0000                            ADD BYTE PTR [EAX],AL
0000054F 00                              ADD BYTE PTR [EAX],AL
```

I then used `Speakeasy` to emulate the shellcode and inspect its API calls.

![speakaeasy](/images/Day0/speakeasy.png)

Decoding the Base64-encoded PowerShell command revealed the following script:
```powershell
$k=[Convert]::FromBase64String('fXFKcmfoirwa/SI4MMt018hA9nf/Fl++ycE0WV8G+qg=');
$b=[IO.File]::ReadAllBytes('review-cache.dat');
$a=[Security.Cryptography.Aes]::Create();
$a.Key=$k;
$a.IV=$b[0..15];
$a.Mode='CBC';
$a.Padding='PKCS7';
$d=$a.CreateDecryptor().TransformFinalBlock($b,16,$b.Length-16);[IO.File]::WriteAllBytes('review-cache.zip',$d)
```
This script decrypts `review-cache.dat` using `AES-256-CBC` with the following key: `7d714a7267e88abc1afd223830cb74d7c840f677ff165fbec9c134595f06faa8`
```bash
$ dd if=review-cache.dat bs=1 skip=16 count=512 status=none | openssl enc -d -aes-256-cbc -nosalt -K 7d714a7267e88abc1afd223830cb74d7c840f677ff165fbec9c134595f06faa8 -iv "$(xxd -p -l 16 review-cache.dat)" -out review-cache.zip
```
Finally, I extracted `review-cache.zip` and got the flag.
![flag](/images/Day0/flag.png)
# Indicators of Compromise (IOCs)

| Category | Indicator / Value |
| --- | --- |
| Suspicious process | `ReviewClient.exe` |
| Executable path | `C:\Users\s.reyes\Downloads\DocumentReview\ReviewClient.exe` |
| Resolved Windows API | `WinExec` |
| Child-process command pattern | `powershell.exe -NoProfile -EncodedCommand` |
| Encrypted input filename | `review-cache.dat` |
| Encryption details | `AES-256-CBC`, `PKCS7`, first **16 bytes** of `.dat` used as IV |
# MITRE ATT&CK Mapping

| ATT&CK ID | Technique / Sub-technique |
| --- | --- |
| [T1027.009](https://attack.mitre.org/techniques/T1027/009/) | Obfuscated Files or Information: **Embedded Payloads** |
| [T1027.007](https://attack.mitre.org/techniques/T1027/007/) | Obfuscated Files or Information: **Dynamic API Resolution** |
| [T1027.010](https://attack.mitre.org/techniques/T1027/010/) | Obfuscated Files or Information: **Command Obfuscation** |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Command and Scripting Interpreter: **PowerShell** |
| [T1106](https://attack.mitre.org/techniques/T1106/) | **Native API** |
| [T1140](https://attack.mitre.org/techniques/T1140/) | **Deobfuscate/Decode Files or Information** |
| [T1027.013](https://attack.mitre.org/techniques/T1027/013/) | Obfuscated Files or Information: **Encrypted/Encoded File** |
| [T1027.003](https://attack.mitre.org/techniques/T1027/003/) | Obfuscated Files or Information: **Steganography** |

# Q&A
### Q1: Which executable contains the suspicious payload?
Answer: `ReviewClient.exe`
### Q2: What is the starting virtual address of its private executable memory region?
Based on `malfind` output. <br>
Answer: `0x8e0000`
### Q3: Which file associated with the process also contains the same payload?
Answer: `review-cover.png`
### Q4: Which MITRE ATT&CK sub-technique best describes how the payload is stored in the recovered PNG file?
Answer: [T1027.009](https://attack.mitre.org/techniques/T1027/009/)
### Q5: Which Windows API does the payload call to launch its next stage?
Answer: `kernel32.WinExec`
### Q6: What encryption key does the decoded stage use to decrypt the document cache?
Answer: `7d714a7267e88abc1afd223830cb74d7c840f677ff165fbec9c134595f06faa8`
### Q7: What is the flag?
Answer: `THM{2b3cc75adab999202e1879af542b2c11}`

