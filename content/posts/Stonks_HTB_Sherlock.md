---
title: "Stonks"
description: "A major real estate and development corporation is under investigation for large-scale financial fraud. The company allegedly inflated revenues and concealed massive debt in order to secure bank loans and push through a stock exchange listing. Public reports painted a picture of strong growth, but the truth tells otherwise. Law enforcement has seized a corporate server believed to store critical documents. However, investigators suspect that the original financial statements reflecting the company’s real losses were deleted in an attempt to cover up the fraud. As a digital forensics specialist, your mission is to recover the missing file and bring the hidden truth to light."
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

I worked through this challenge on a quiet day and learned a lot about Windows Data Deduplication, NTFS metadata analysis, and the recovery of deleted, deduplicated files. <br>
We are given `evidence.ad1` containing data from two NTFS partitions.
![evidence_tree](/images/evidenttree.png)

This Sherlock focuses on Windows Data Deduplication and its forensic implications. Before examining the evidence, I reviewed the following resources to understand the optimization process and the underlying storage structures. [Data-deduplication](https://learn.microsoft.com/en-us/windows-server/storage/data-deduplication/overview), [How-it-work](https://learn.microsoft.com/en-us/windows-server/storage/data-deduplication/understand)<br>
:::note[Explanation]
The idea behind data deduplication is to store only one copy of repeated data.<br>
For example:<br>
File 1: [chunk A] [chunk B] [chunk C] <br>
File 2: [chunk A] [chunk B] [chunk E] [chunk D]<br>
Without deduplication, the system stores seven chunks for the two files. With deduplication, it stores only five unique chunks, along with references indicating which chunks each file needs.
The original file stream is replaced with a reparse point that allows the system to locate its data in the chunk store. When you open the file, the system follows these references and reconstructs its contents automatically.
:::


### Q1: When was the Windows Data Deduplication feature first installed on the system?
I found an informative article discussing the forensic artifacts associated with Windows Data Deduplication.
[window data deduplication](https://blog.1234n6.com/windows-server-data-dedupliction-and-forensic-analysis/) 
The article identifies several service registry keys associated with the Data Deduplication feature.

```
HKLM\SYSTEM\CurrentControlSet\Services\ddpsvc
HKLM\SYSTEM\CurrentControlSet\Services\ddpvssvc
HKLM\SYSTEM\CurrentControlSet\Services\Dedup
```

![Registry](/images/registry.png)
Another way to check this is to examine `System.evtx` for Service Control Manager Event ID `7045`, which records the installation of the Data Deduplication Service.
![evtx](/images/evtx.png)
Answer: `2025-09-18 09:56:40`



### Q2: How many bytes of disk space were saved after the first optimization job was completed by Data Deduplication?
I examined `Microsoft-Windows-Deduplication%4Operational.evtx` and located the Event ID `6153` record associated with the first optimization job. Its `SavedSpace` field reports `6,805,707 bytes`.
![Saved_Space](/images/savedspace.png)
Answer: `6805707`

### Q3: When was Data Deduplication most recently re-enabled on volume D:?

Scrolling through `Microsoft-Windows-Deduplication%4Diagnostic.evtx` suggested that Data Deduplication was most recently re-enabled on volume `D:` between `10:31:38` and `10:34:49` (UTC+7).
![re-enable](/images/reenable.png)
I couldn't find an event showing the exact time, so I checked the `changeTime` property in `dedupConfig.01.xml`. Its timestamp falls within this window and likely corresponds to when deduplication was re-enabled.
![Change-time](/images/changetime.png)

Converting `134028128759740533` from Windows FILETIME gives `2025-09-20 03:34:35` UTC.
Answer: `2025-09-20 03:34:35`

### Q4: List all file extensions that are not optimized by Data Deduplication in alphabetical order.
In `\\.\PHYSICALDRIVE:Partition 3\Data [NTFS]\System Volume Information\Dedup\Settings\dedupConfig.01.xml`
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

![optimized-file](/images/optimized-file.png)
Answer: `168`

### Q6: When is the next Throughput Optimisation job scheduled to run?
I checked `C:\Windows\System32\Tasks\Microsoft\Windows\Deduplication`
![tasks](/images/scheduletask.png)
I inspected the XML configuration of the `ThroughputOptimization` scheduled task. Its enabled `CalendarTrigger` specifies a `StartBoundary` of `2025-09-20T06:50:00`, a `WeeksInterval` of `1`, and `Thursday` as the scheduled day. The next occurrence matching this schedule is therefore `2025-09-25 06:50:00`. <br>
Answer: `2025-09-25 06:50:00`

### Q7: What is the name of the financial report that was recently deleted in an attempt to cover up criminal activity?
I parsed the NTFS Master File Table (`$MFT`) and identified a deleted record for `Internal Consolidated Financial Statements 2024.docx`. The parser associates the file with MFT entry `46`. The unchecked `In Use` field in the exported results is consistent with the record being marked as deleted.
![mft](/images/mft.png)
Answer: `Internal Consolidated Financial Statements 2024.docx`

### Q8: What is the MFT entry number of that report file?
Answer: `46`

### Q9: List all the FILE_ATTRIBUTE flags that are set on the report file. Submit answer in ascending order based on the hex value of each flag.
The `Si Flags` column lists `Archive`, `SparseFile`, and `ReparsePoint` for the report. These correspond to the three file attribute flags requested by the question.
![mft](/images/mft_2.png)
Answer: `FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_SPARSE_FILE, FILE_ATTRIBUTE_REPARSE_POINT`


### Q10: At what offset in the $MFT file does the $REPARSE_POINT attribute of the report begin? (Answer as an 8-digit hexadecimal offset, prefixed with 0x)

![address](/images/reparsepoint.png)
The report corresponds to MFT entry `46`. Using a record size of 1,024 bytes, the entry begins at offset `46 * 1024 = 0xB800` in the extracted `$MFT` file. The parser shows that the `$REPARSE_POINT` attribute begins at record-relative offset 0x1B0. So, the `$REPARSE_POINT` attribute starts at: `46 × 0x400 + 0x1B0 = 0x0000B9B0`. <br>
Answer: `0x0000b9b0`

### Q11: After the report was optimized by Data Deduplication, into how many chunks was its data divided?

I found a useful research paper [Forensic analysis of deduplicated file systems](https://www.sciencedirect.com/science/article/pii/S1742287617300324) indicating how to recover duplicated file with reparse-point metadata. To fully understand the underlying structures  you should read the paper carefully.

![tree](/images/tree.png)

> "Inside unique folder, we have the `Data` and `Stream` folders. Inside the `Data` folder, there are `.ccc` files that are chunks containers, while inside the `Stream` folder the `.ccc` files contain the hashes sequences for thededuplicated files. In the Stream folder, a .ccc file has three type of sections: “Cthr”
called file header, “Rrtl” or redirection table, “Ckhr” or stream map
element”
— Dario Lanterna & Antonio Barili, *Forensic analysis of deduplicated file systems* (2017), p. S103. [DOI](https://doi.org/10.1016/j.diin.2017.01.008)

I extracted the complete `160-byte` `$REPARSE_POINT` attribute, including its attribute header, from offset `0xB9B0` in the `$MFT` file using the following command:
```shell
$ dd if=MFT of="test.bin" bs=1 count=160 skip=$((0xb9b0))
```
![rp](/images/rp.png)
I then used `stream header` to locate stream map of the report file in `stream container`
![sm](/images/sm.png)

![cata](/images/chunk.png)
Start address of stream map is `0x00005260`. At offset `0x70` starts the first chunk entry (sequence 0x01), at `0x78` there is the
absolute position in the chunkstore (`0x0006CE20`), and at offset `0x88` the 32-byte chunk hash. The value at offset 0xA8 is the length of the chunk payload (`0xEEA7`).
So there are two chunks:
1. Size 0xEEA7, address in `Data` container `0x0006CE20` and hash is `68e568e2f0f41373af76172d2c1648b8e95e95cef3c5125d151daa3f211e2939`
2. Size 0x733A, address in `Data` container `0x0007BD20` and hash is `5ffbe14ef8342bb7d2e8f048c38347940c423f2c5725a40b137aa6ad56c6e54c`
Answer: `2`


### Q12: What is the data length in bytes of the first deduplicated chunk belonging to the report file under investigation?
Size of first chunk is `0xEEA7` = `61095` bytes <br>
Answer: `61095`

### Q13: After recovering the file, provide the SHA-256 hash of the recovered financial report.

The first chunk record begins at offset `0x6CE20` in the data container. Its payload begins `0x58` bytes after the start of the record, at `0x6CE78`. Applying the same offset to the second record gives a payload start of `0x7BD78`.
![p1](/images/p1.png)
![p2](/images/p2.png)
```shell
$ dd if=00000001.00000001.ccc of=chunk1.bin bs=1 skip=$((0x6CE78)) count=$((0xEEA7)) 

$ dd if=00000001.00000001.ccc of=chunk2.bin bs=1 skip=$((0x7BD78)) count=$((0x733A))

$ cat chunk1.bin chunk2.bin > "Internal Consolidated Financial Statements 2024.docx"
```
![recover](/images/recover.png)
```
$ sha256sum Internal\ Consolidated\ Financial\ Statements\ 2024.docx
e51e773e5404f29cc2816cff3fbdcc8b2c28f9e8040a6e7fe926b21336b66513  Internal Consolidated Financial Statements 2024.docx
```  

Answer: `e51e773e5404f29cc2816cff3fbdcc8b2c28f9e8040a6e7fe926b21336b66513`

### Q14: The person who drafted this report must also be held legally accountable. What is their Full name?
I examined the recovered document’s metadata with `ExifTool`. Both the `Creator` and Last Modified By fields contain `Elaine Chua` - Senior Accountant, identifying `Elaine Chua` as the person named in the document’s authorship metadata.

```shell
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
I recovered the deduplicated file `Audited Consolidated Financial Statements 2024.docx` using the procedure described above. I then compared the `Profit for the year` line item in the audited and internal reports. The audited report shows a profit of `2,672,196`, whereas the internal report records a loss of `1,647,555`. The overstatement is therefore `2,672,196 − (−1,647,555) = 4,319,751`
![cp](/images/diff.png)
Answer: `4319751`<br>
And yeah we finished this sherlock
![archive](/images/cert.png)