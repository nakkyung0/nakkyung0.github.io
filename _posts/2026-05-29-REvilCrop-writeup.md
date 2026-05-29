---
layout: post
title: "TryHackMe: REvil Corp - Walkthrough"
date: 2026-05-29 12:00:00 +0000
categories: [Walkthrough, DFIR]
tags: [tryhackme, redline, REvil, ransomware, incident-response]
---

## Scenario Overview

In this challenge, we step into the shoes of an Incident Responder investigating a ransomware outbreak at Osinski Inc. A senior accountant noticed their files were suddenly encrypted, their desktop wallpaper was changed, and a ransom note was dropped. 

Using **Mandiant Redline** to parse the endpoint triage data, we will track down the initial execution, pinpoint the malware indicators, document the scope of the encryption, and map out the threat intelligence context of the adversary.

---

## Investigation Walkthrough

### Q1: What is the compromised employee's full name?
Navigating to the **System Information** tab in Redline reveals the profile details of the user operating the machine at the time of compromise.

![LoggedUser](/assets/img/TryHackMe/REvilCorp/loggeduser.png)

* **Answer:** `John Coleman`

### Q2: What is the operating system of the compromised host?
Under the same **System Information** summary, the operating system version and build are clearly documented.

![OS](/assets/img/TryHackMe/REvilCorp/os.png)

* **Answer:** `Windows 7 Home Premium 7601 Service Pack 1`

### Q3: What is the name of the malicious executable that the user opened?
Looking closely at the **File Download History**, we observe an auto-downloaded executable masquerading as a legitimate archiving utility sitting right inside the user's Downloads directory.

![exe](/assets/img/TryHackMe/REvilCorp/exe.png)

* **Answer:** `WinRAR2021.exe`

### Q4: What is the full URL that the user visited to download the malicious binary?
Examining the source URL column for the `WinRAR2021.exe` record exposes the staging IP address and path used by the threat actor.

![url](/assets/img/TryHackMe/REvilCorp/url.png)

* **Answer:** `http://192.168.75.129:4748/Documents/WinRAR2021.exe`

### Q5: What is the MD5 hash of the binary?
By shifting over to the **File System** analysis tab and inspecting the properties of the file located at `C:\Users\John Coleman\Downloads\WinRAR2021.exe`, we extract its unique cryptographic signature.

![md5](/assets/img/TryHackMe/REvilCorp/md5.png)

* **Answer:** `890a58f200dfff23165df9e1b088e58f`

### Q6: What is the size of the binary in kilobytes?
From the same file system analysis panel grid view, the file size metric is explicitly calculated for us.

* **Answer:** `164 Kilobytes`

### Q7: What is the extension to which the user's files got renamed?
Inspecting the user's `Desktop` and `Finance` folders reveals that their documents, archives, and text files have been appended with a matching, randomized alphanumeric string a signature behavior of REvil ransomware.

![extension](/assets/img/TryHackMe/REvilCorp/extension.png)

* **Answer:** `.t48s39la`

### Q8: What is the number of files that got renamed and changed to that extension?
Switching to the **Timeline** tab, applying a filter for the string `.t48s39la`, and isolating **Modified** or **Changed** events displays the total volume of impacted file records.

![Wallpaper](/assets/img/TryHackMe/REvilCorp/renamed.png)

* **Answer:** `48`

### Q9: What is the full path to the wallpaper that got changed by an attacker, including the image name?
Ransomware frequently overwrites the desktop background to ensure the victim notices the infection. Filtering the timeline for image extensions (`.bmp`) points to a freshly generated bitmap dropped into the user's local Temp directory.

![NOTE](/assets/img/TryHackMe/REvilCorp/wallpaper.png)

* **Answer:** `C:\Users\John Coleman\AppData\Local\Temp\hk8.bmp`

### Q10: The attacker left a note for the user on the Desktop; provide the name of the note with the extension.
Checking the file system artifacts dropped onto the victim's Desktop reveals a text file template matching the encryption extension format.

![favorites](/assets/img/TryHackMe/REvilCorp/note.png)

* **Answer:** `t48s39la-readme.txt`

### Q11: The attacker created a folder "Links for United States" under C:\Users\John Coleman\Favorites\ and left a file there. Provide the name of the file.
Browsing further through the user's profile configuration path under `Favorites\Links for United States` confirms another file targeted and altered by the payload.

![bytes](/assets/img/TryHackMe/REvilCorp/favorites.png)

* **Answer:** `GobiernoUSA.gov.url.t48s39la`

### Q12: There is a hidden file dropped by the attacker under C:\Users\John Coleman\Desktop\. Provide the full name of the file including the extension and the size of it in bytes.
By checking the **File System** tree under John Coleman's Desktop, we can find a zero-byte tracking/lock artifact deployed during the execution workflow.

![decryptor](/assets/img/TryHackMe/REvilCorp/bytes.png)

* **Answer:** `d60df740.lock (0 Bytes)`

### Q13: What is the MD5 hash of the decryptor executable placed on the Desktop?
The actor dropped a dedicated decryptor stub directly onto the Desktop (`d.e.c.r.y.p.tor.exe`) to allow victims to test or apply keys after paying. Selecting this file reveals its MD5 value.

![decryptor](/assets/img/TryHackMe/REvilCorp/decryptor.png)

* **Answer:** `f617af8c0d276682fdf528bb3e72560b`

### Q14: What is the full URL to the decryptor website that the attacker requested the user to visit?
Reviewing the **Browser URL History** and filtering for keywords related to the recovery process flags the external Tor gateway URL left by the binary's network or interaction routine.

![decrypturl](/assets/img/TryHackMe/REvilCorp/decrypturl.png)

* **Answer:** `http://decryptor.top/644E7C8EFA02FBB7`

### Q15: What are the other two names known for the REvil ransomware group according to MITRE ATT&CK?
Cross-referencing the threat profile on the official MITRE ATT&CK portal details the structural and historical naming overlaps for this specific Ransomware-as-a-Service (RaaS) entity.

![names](/assets/img/TryHackMe/REvilCorp/names.png)

* **Answer:** `Revil, Sodin, Sodinokibi`

---

## Conclusion & Lessons Learned

This digital forensics exercise paints a comprehensive picture of a **REvil / Sodinokibi** intrusion:
1. **Initial Access & Staging:** The user was lured into downloading a malicious clone of an application (`WinRAR2021.exe`) over unencrypted HTTP.
2. **Execution & Impact:** Upon launch, the payload dropped runtime locks (`d60df740.lock`), altered system diagnostics, and executed a swift local directory encryption sweeping up 48 files with a custom `.t48s39la` extension.
3. **Extortion Mechanism:** The attack completed its lifecycle by altering the victim's wallpaper layout (`hk8.bmp`), planting localized readme txt guides, leaving a custom decryptor executable, and directing traffic towards a Tor extortion portal (`decryptor.top`).

**Defensive Mitigations:**
* Implement robust application whitelisting / software restriction policies to block unauthorized binaries from executing out of user `Downloads` or `Temp` folders.
* Ensure corporate web filters block known adversary staging domains and flag unusual non-standard port traffic.
* Deploy endpoint detection and response (EDR) solutions configured to recognize high-volume cryptographic operations happening across short windows of time.
