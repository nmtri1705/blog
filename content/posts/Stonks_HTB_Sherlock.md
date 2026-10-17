---
title: "Stonks"
description: "Insanse "
publishDate: "2026-10-17"
tags: ["sherlock", "insanse", "dfir", "htb"]
section: "blue"
draft: false
coverImage:
  src: "/images/stonks.png"
  alt: "thumbnail"
---
Scenario:
> A major real estate and development corporation is under investigation for large-scale financial fraud. The company allegedly inflated revenues and concealed massive debt in order to secure bank loans and push through a stock exchange listing. Public reports painted a picture of strong growth, but the truth tells otherwise. Law enforcement has seized a corporate server believed to store critical documents. However, investigators suspect that the original financial statements reflecting the company’s real losses were deleted in an attempt to cover up the fraud. As a digital forensics specialist, your mission is to recover the missing file and bring the hidden truth to light.

I solved the interesting challenge during my boring day and learned lots of new. <br>
We are given `evidence.ad1` which includes 2 physical drive in form of NTFS:
![evidence_tree](/public/images/evidenttree.png)

This sherlock primary focus on knowledge of Data Deduplication feature, so I find some usefull resource: [Data-deduplication](https://learn.microsoft.com/en-us/windows-server/storage/data-deduplication/overview), [How-it-work](https://learn.microsoft.com/en-us/windows-server/storage/data-deduplication/understand)<br>
:::note[Explanation]
The concept behind data deduplication is store only one copy of repeated data.<br>For example:<br>
file 1: [chunk A ][chunk B ][Chunk C ]<br>
file 2: [chunk A ][chunk B ][chunk E ][chunk D ]<br>
Without deduplication, the system stored 7 chunks for 2 files. With deduplication, it stores only the 5 unique chunks, plus references recording which chunks each file needs. The original file stream of now optimized files with a `reparse point` to the chunk store.<br>When you open a file the system follows those references and reconstructs its contents automatically. 
:::


### Q1: When was the Windows Data Deduplication feature first installed on the system?
I found a interesting research digging into 
[window data deduplication](https://blog.1234n6.com/windows-server-data-dedupliction-and-forensic-analysis/) 
. This blog mention the appearance of some registry key indicating that the 'Data Deduplication' feature has been installed.

```
HKLM\SYSTEM\CurrentControlSet\Services\ddpsvc
HKLM\SYSTEM\CurrentControlSet\Services\ddpvssvc
HKLM\SYSTEM\CurrentControlSet\Services\Dedup
```

![Registry](/public/images/registry.png)
It's around `2025-09-18 09:56:41` then I try 41, 40 and got the right answer. `2025-09-18 09:56:40`. <br> 
Other way: check `Setup.evtx` around the moment around creation time of `dedup` folder.
![evtx](/public/images/evtx.png)
Answer: `2025-09-18 09:56:40`



### Q2: How many bytes of disk space were saved after the first optimization job was completed by Data Deduplication?
I find first optimization job recorded in `Microsoft-Windows-Deduplication%4Operational.evtx`
![Saved_Space](/public/images/savedspace.png)
Answer: `6805707`

### Q3: When was Data Deduplication most recently re-enabled on volume D:?

Scrolling down in artifact `Microsoft-Windows-Deduplication%4Diagnostic.evtx` show us the most recently re-enable on volume D: between  `10:31:38` - `10:34:49` (UTC+7)
![re-enable](/public/images/reenable.png)
But at that time I didn't find any event indicating the exact time, then I found change time property of config file around that time which relate to re-enable event.
![Change-time](/public/images/changetime.png)

`134028128759740533` conver to filesystem time is `2025-09-20 03:34:35`
Answer: `2025-09-20 03:34:35`

### Q4: List all file extensions that are not optimized by Data Deduplication in alphabetical order.
In `\\.\PHYSICALDRIVE:Partition 3\Data [NTFS]\System Volume Information\Dedup\Settings\dedipConfig.01.xml`
```xml title="dedupConfig.01.xml"

<?xml version="1.0"?>
<root version="1.0">
    <properties>
...
        <property
            name="excludeFileExtensions"
            type="VT_BSTR"
            value="mp4|avi|iso|bak|tif" />

        <property
            name="excludeFileExtensionsDefault"
            type="VT_BSTR"
            value="edb|jrs" />
...
</root>

```
Answer: `avi, bak, edb, iso, jrs, mp4, tif`

### Q5: How many files have been optimized by Data Deduplication?

![optimized-file](/public/images/optimized-file.png)
Answer: `168`

### Q6: When is the next Throughput Optimisation job scheduled to run?
I checked `C:\Windows\Tasks\Microsoft\Deduplication`
![tasks](/public/images/scheduletask.png)
Throughput Optimisation job scheduled was executed every `Thursday` of week starting from `2025-09-20T06:50:00`, so the next time it run is  `2025-09-25 06:50:00` <br>
Answer: `2025-09-25 06:50:00`

### Q7: What is the name of the financial report that was recently deleted in an attempt to cover up criminal activity?
Parse `$MFT` with [mftparser](https://www.mftparser.com/) then we knew `Internal Consolidated Financial Statements 2024.docx` was deleted. Or using `MFTCmd` and `Time Explorer` from Eric Zimmerman's tool.
![mft](/public/images/mft.png)
Answer: `Internal Consolidated Financial Statements 2024.docx`

### Q8: What is the MFT entry number of that report file?
Answer: `46`

### Q9: List all the FILE_ATTRIBUTE flags that are set on the report file. Submit answer in ascending order based on the hex value of each flag.

![mft](/public/images/mft_2.png)
Answer: `FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_SPARSE_FILE, FILE_ATTRIBUTE_REPARSE_POINT`


### Q10: At what offset in the $MFT file does the $REPARSE_POINT attribute of the report begin? (Answer as an 8-digit hexadecimal offset, prefixed with 0x)

![address](/public/images/reparsepoint.png)
Because MFT of that report is `46`, each record of MFT file commonly is 1024 bytes, so start address of $reparse_pointer attributes is `46 * 1024 + offset of ReparsePoint` = `b9b0`
<br>
Answer: `0x0000b9b0`

### Q11: After the report was optimized by Data Deduplication, into how many chunks was its data divided?

I found a very usefull research [Forensic analysis of deduplicated file systems](https://www.sciencedirect.com/science/article/pii/S1742287617300324) indicating how to recover optimized file with reparse point. To fully understand about concept you should read the paper carefully.

![tree](/public/images/tree.png)

> "Inside unique folder, we have the `Data` and `Stream` folders. Inside the `Data` folder, there are `.ccc` files that are chunks containers, while inside the `Stream` folder the `.ccc` files contain the hashes sequences for thededuplicated files. In the Stream folder, a .ccc file has three type of sections: “Cthr”
called file header, “Rrtl” or redirection table, “Ckhr” or stream map
element”
— Dario Lanterna & Antonio Barili, *Forensic analysis of deduplicated file systems* (2017), p. S103. [DOI](https://doi.org/10.1016/j.diin.2017.01.008)

First we need to extract reparse point of the report file by command:
```shell
$ dd if=MFT of="test.bin" bs=1 count=160 skip=$((0xb9b0))
```
![rp](/public/images/rp.png)
Then using `stream header` to find stream map of the report file in `stream container`
![sm](/public/images/sm.png)

![cata](/public/images/chunk.png)
Start address of stream map is `0x00005250`. At offset 0x70 starts the first hash (sequence 0x01), at 0x78 there is the
absolute position in the chunkstore (0x0006CE20), a nd at offset 0x88 the hash of chunk(len 32). The value at offset 0xA8 is the length of the chunk
payload (0xEEA7).
So there are two chunk:
1. Size 0xEEA7, address in `Data` container `0x0006CE20` and hash is `68e568e2f0f41373af76172d2c1648b8e95e95cef3c5125d151daa3f211e2939`
2. Size 0x733A, address in `Data` container `0x0007BD20` and hash is `5ffbe14ef8342bb7d2e8f048c38347940c423f2c5725a40b137aa6ad56c6e54c`
Answer: `2`


### Q12: What is the data length in bytes of the first deduplicated chunk belonging to the report file under investigation?
Size of first chunk is `0xEEA7` = `61095` bytes <br>
Answer: `61095`

### Q13: After recovering the file, provide the SHA-256 hash of the recovered financial report.

Go to first chunk at `0x0006CE20` in `Data` container and extract chunk start from offset 0x58.
![p1](/public/images/p1.png)
![p2](/public/images/p2.png)
```bash
$ dd if=00000001.00000001.ccc of=chunk1.bin bs=1 skip=$((0x6CE78)) count=$((0xEEA7)) 

$ dd if=00000001.00000001.ccc of=chunk2.bin bs=1 skip=$((0x7BD78)) count=$((0x733A))
```
![recover](/public/images/recover.png)
```
$ sha256sum Internal\ Consolidated\ Financial\ Statements\ 2024.docx
e51e773e5404f29cc2816cff3fbdcc8b2c28f9e8040a6e7fe926b21336b66513  Internal Consolidated Financial Statements 2024.docx
```  

Answer: `e51e773e5404f29cc2816cff3fbdcc8b2c28f9e8040a6e7fe926b21336b66513`

### Q14: The person who drafted this report must also be held legally accountable. What is their Full name?
```
$ exiftool Internal\ Consolidated\ Financial\ Statements\ 2024.docx
ExifTool Version Number         : 12.40
File Name                       : Internal Consolidated Financial Statements 2024.docx
...
Creator                         : Elaine Chua - Senior Accountant
Last Modified By                : Elaine Chua - Senior Accountant
Revision Number                 : 1
Create Date                     : 2025:09:16 15:59:00Z
Modify Date                     : 2025:09:16 16:02:00Z
```
Answer: `Elaine Chua`

### Q15: How much was the profit for the year overstated in the audited report compared to the actual one?

Compare the audit report with actual report which is `Audited Consolidated Financial Statements 2024.docx`. Do the same thing to recover the file and got the answers is `2,672,196 − (−1,647,555) = 4,319,751`
![cp](/public/images/diff.png)
Answer: `4319751`<br>
And yeah we finished this sherlock
![archive](/public/images/cert.png)