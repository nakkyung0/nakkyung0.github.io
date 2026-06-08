---
layout: post
title: "TryHackMe: NewHireOldArtifacts Writeup"
date: 2026-06-07
categories: [Writeups, TryHackMe]
tags: [splunk, sysmon, threat-hunting, malware-analysis, dfir]
description: "Walkthrough of the NewHireOldArtifacts room on TryHackMe a Splunk-based DFIR challenge investigating a compromised Finance01 endpoint using Sysmon event logs."
image: /assets/img/banners/NewHire.png
---

## Overview

**Room:** [NewHireOldArtifacts](https://tryhackme.com/room/newhireoldartifacts)  
**Platform:** TryHackMe  
**Category:** DFIR / Threat Hunting  
**Tools:** Splunk, Sysmon Event Logs

This room places you in the role of a SOC analyst tasked with investigating a newly onboarded employee's machine (`Finance01`) that has been flagged for suspicious activity. All investigation is performed through Splunk using Windows Sysmon (`WinEventLog:Microsoft-Windows-Sysmon/Operational`) event logs.

---

## Questions & Answers

---

### Question 1 A Web Browser Password Viewer executed on the infected machine. What is the name of the binary? Enter the full path.

**Answer:** `C:\Users\FINANC~1\AppData\Local\Temp\11111.exe`

The starting point was querying all Sysmon **EventCode=1** (Process Creation) events and inspecting the `Description` field. Clicking on the field reveals the top values among them, **Web Browser Password Viewer** with 14 occurrences immediately stands out as suspicious.

![EventCode=1 Description field showing Web Browser Password Viewer](/assets/img/TryHackMe/NewHireOldArtifacts/PasswordViewer1.png)

Filtering specifically on that description and projecting the `Image` field reveals the full executable path:

**Query:**
```
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="1" Description="Web Browser Password Viewer"
| table Image
```

![Image path for Web Browser Password Viewer binary](/assets/img/TryHackMe/NewHireOldArtifacts/PasswordViewer2.png)

All 14 events point to the same binary hidden in the user's Temp directory under the innocuous numeric name `11111.exe`.

---

### Question 2 What is listed as the company name?

**Answer:** `NirSoft`

Searching for all Sysmon events involving `11111.exe` and expanding the `Company` field confirms the binary belongs to **NirSoft** the publisher of a suite of free Windows utilities frequently abused by attackers for credential harvesting.

**Query:**
```
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational" Image="C:\\Users\\FINANC~1\\AppData\\Local\\Temp\\11111.exe"
```

![Company field showing NirSoft for 11111.exe](/assets/img/TryHackMe/NewHireOldArtifacts/Name.png)

NirSoft accounts for 96.3% (52 of 54) of all events tied to this binary confirming it is a repackaged NirSoft credential-dumping tool renamed to evade detection.

---

### Question 3 Another suspicious binary running from the same folder was executed on the workstation. What was the name of the binary? What is listed as its original filename? (format: file.xyz,file.xyz)

**Answer:** `IonicLarge.exe,PalitExplorer.exe`

First, a broad query for all EventCode=1 processes launched from the `Temp` directory was run to surface other suspicious executables:

**Query:**
```
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="1" Image="C:\\Users\\FINANC~1\\AppData\\Local\\Temp\\*"
| top Image
```

![Top images from Temp directory showing Procmon64 and other binaries](/assets/img/TryHackMe/NewHireOldArtifacts/susbinary1.png)

Beyond `11111.exe`, this surfaced `Procmon64.exe` and `updatewin.exe`. To find a binary with a mismatched `OriginalFileName` (a masquerading indicator), the query was refined to also pull the `OriginalFileName` PE header field:

**Query:**
```
index=* EventCode=1 Image="C:\\Users\\Finance01\\AppData\\Local\\Temp\\*"
| table Image OriginalFileName
```

![IonicLarge.exe mapped to OriginalFileName PalitExplorer.exe](/assets/img/TryHackMe/NewHireOldArtifacts/susbinary2.png)

The binary `IonicLarge.exe` has an `OriginalFileName` of `PalitExplorer.exe` in its PE header a classic masquerading technique where the on-disk filename is changed to avoid detection while the compiled name remains in the binary's metadata.

---

### Question 4 The binary from the previous question made two outbound connections to a malicious IP address. What was the IP address? Enter the answer in a defang format.

**Answer:** `2[.]56[.]59[.]42`

Pivoting to **EventCode=3** (Network Connection) events for `IonicLarge.exe` and inspecting the `DestinationIp` field reveals 8 unique IP addresses. The vast majority of traffic (90.8%) goes to `127.0.0.1` (loopback), but one external IP appears twice in a way that stands out:

**Query:**
```
index=* EventCode=3 Image="C:\\Users\\Finance01\\AppData\\Local\\Temp\\IonicLarge.exe"
```

![DestinationIp field showing 2.56.59.42 as external C2](/assets/img/TryHackMe/NewHireOldArtifacts/ip.png)

The IP `2.56.59.42` made **2 outbound connections** and is the malicious C2 address. Defanged: `2[.]56[.]59[.]42`.

---

### Question 5 The same binary made some change to a registry key. What was the key path?

**Answer:** `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection`

Querying **EventCode=12** (Registry Object Added or Deleted) for `IonicLarge.exe` and projecting the `TargetObject` field reveals the keys modified:

**Query:**
```
index=* EventCode=12 Image="C:\\Users\\Finance01\\AppData\\Local\\Temp\\IonicLarge.exe"
| table TargetObject
```

![Registry keys modified by IonicLarge.exe](/assets/img/TryHackMe/NewHireOldArtifacts/Registry.png)

Two keys were touched, but the answer the room is looking for is the Defender key:

```
HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection
```

Modifying this key is a well-known technique to **disable Windows Defender Real-Time Protection** via Group Policy a defence evasion tactic to prevent the AV engine from intercepting subsequent malicious activity.

---

### Question 6 Some processes were killed and the associated binaries were deleted. What were the names of the two binaries? (format: file.xyz,file.xyz)

**Answer:** `WvmIOrcfsuILdX6SNwIRmGOJ.exe,phcIAmLJMAIMSa9j9MpgJo1m.exe`

Searching for `taskkill` across all events and reviewing the `ParentCommandLine` field shows the attacker's cleanup commands:

**Query:**
```
index=* taskkill | table ParentCommandLine
```

![ParentCommandLine showing taskkill self-deletion commands](/assets/img/TryHackMe/NewHireOldArtifacts/deleted.png)

Two executables were launched from `C:\Users\Finance01\Pictures\Adobe Films\`, terminated themselves via `taskkill`, and then deleted themselves from disk:

- `WvmIOrcfsuILdX6SNwIRmGOJ.exe`
- `phcIAmLJMAIMSa9j9MpgJo1m.exe`

The second variant's cleanup command also deleted all DLLs from `C:\ProgramData\` aggressive artefact removal to hinder forensic investigation.

---

### Question 7 The attacker ran several commands within a PowerShell session to change the behaviour of Windows Defender. What was the last command executed in the series of similar commands?

**Answer:** `powershell WMIC /NAMESPACE:\\root\Microsoft\Windows\Defender PATH MSFT_MpPreference call Add ThreatIDDefaultAction_Ids=2147737003 ThreatIDDefaultAction_Actions=6 Force=True`

Searching for PowerShell events and deduplicating by `CommandLine` reveals the series of WMIC-based Defender tampering commands executed via PowerShell:

**Query:**
```
index=* powershell.exe
| table _time CommandLine
| dedup CommandLine
```

![PowerShell commands modifying Windows Defender ThreatID exclusions](/assets/img/TryHackMe/NewHireOldArtifacts/commands.png)

The attacker used `WMIC` via PowerShell to call `MSFT_MpPreference` and add `ThreatIDDefaultAction_Ids` with action `6` (Allow), effectively whitelisting specific malware detections.

---

### Question 8 Based on the previous answer, what were the four IDs set by the attacker? Enter the answer in order of execution. (format: 1st,2nd,3rd,4th)

**Answer:** `2147737394,2147737010,2147737007,2147735503`

Sorting the same results by `_time` ascending gives the execution order of the four Defender exclusion IDs:

![ThreatID values added to Windows Defender exclusions in order](/assets/img/TryHackMe/NewHireOldArtifacts/IDS.png)

In order of execution:

| Order | ThreatIDDefaultAction_Id |
|---|---|
| 1st | `2147737394` |
| 2nd | `2147737010` |
| 3rd | `2147737007` |
| 4th | `2147735503` |

Each was set with `ThreatIDDefaultAction_Actions=6` (Allow) and `Force=True`, meaning Defender would silently permit these threat detections without alerting or blocking.

---

### Question 9 Another malicious binary was executed on the infected workstation from another AppData location. What was the full path to the binary?

**Answer:** `C:\Users\Finance01\AppData\Roaming\EasyCalc\EasyCalc.exe`

Broadening the search to all processes executed from any `AppData` path and reviewing the top image values:

**Query:**
```
index=* Image="*AppData*"
```

![Top AppData images showing EasyCalc.exe as second most common](/assets/img/TryHackMe/NewHireOldArtifacts/EasyCalc.png)

`EasyCalc.exe` appears as the second most executed binary from AppData with 1,125 events (37.7%), running from:

```
C:\Users\Finance01\AppData\Roaming\EasyCalc\EasyCalc.exe
```

The name mimics a legitimate calculator application, but its high event count and AppData Roaming location are both red flags.

---

### Question 10 What were the DLLs that were loaded from the binary from the previous question? Enter the answers in alphabetical order. (format: file1.dll,file2.dll,file3.dll)

**Answer:** `ffmpeg.dll,nw.dll,nw_elf.dll`

Using **EventCode=7** (Image Loaded) to find DLLs loaded specifically by `EasyCalc.exe` from its own directory:

**Query:**
```
index=* Image="C:\\Users\\Finance01\\AppData\\Roaming\\EasyCalc\\EasyCalc.exe" ImageLoaded="*.dll"
| top ImageLoaded
```

![DLLs loaded by EasyCalc.exe including nw_elf.dll, nw.dll and ffmpeg.dll](/assets/img/TryHackMe/NewHireOldArtifacts/dlls.png)

The top DLLs loaded from the EasyCalc directory are:

- `ffmpeg.dll`
- `nw.dll`
- `nw_elf.dll`

In alphabetical order: `ffmpeg.dll,nw.dll,nw_elf.dll`

The presence of `nw.dll` and `nw_elf.dll` indicates this is an **NW.js (Node-WebKit)** application a Chromium + Node.js runtime framework that attackers sometimes abuse to package and execute JavaScript or Node.js payloads while appearing as a legitimate desktop app. `ffmpeg.dll` is a standard NW.js bundled dependency.

---

## Summary

The Finance01 machine suffered a multi-stage compromise: credential harvesting via NirSoft tools, defence evasion through Defender tampering and registry modification, C2 communication from a masqueraded binary, and an NW.js-packaged payload for persistent execution all followed by deliberate cleanup to hinder forensic recovery.
