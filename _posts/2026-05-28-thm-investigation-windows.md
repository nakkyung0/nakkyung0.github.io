---
layout: post
title: "TryHackMe: Investigating Windows Writeup"
date: YYYY-MM-DD HH:MM:SS +0000
categories: [Writeups, TryHackMe]
tags: [dfir, windows, incident-response, blueteam]
---

## Room Overview
* **Room Name:** Investigating Windows
* **Difficulty:** Easy
* **Category:** Digital Forensics & Incident Response (DFIR)
* **Description:** Challenge room covering basic Windows incident response, registry analysis, and log analysis on a compromised machine.

---

## Scenario
A Windows server has been compromised. As a blue team analyst, our job is to log into the machine via RDP, investigate the artifacts, and determine what the attacker did, what backdoors they left behind, and how they maintained persistence.

---

## Task Walkthrough

### Question 1: Whats the version and year of the windows machine?
To identify machine version I utilized powershell. Typing `Get-computerinfo` in powershell allowed me to see version and year of the machine.
![Get-ComputerInfo Output](/assets/img/TryHackMe/THM-investigatingWindows/systeminfo.png)

**Answer:** `Windows Server 2016`

### Quesiton 2: Which user logged in last?
To identify last logged user, there are 2 main approaches, it can be achieved via EventViwer or Powershell, since poor rdp connection, most of my actions were performed via powershell commands. To get information about last logged users, I used powershell command:
```powershell
Get-LocalUser | Sort-Object LastLogon | Select-Object Name, Enabled, SID, Lastlogon -Last 1
```
![Get-LocalUser](/assets/img/TryHackMe/THM-investigatingWindows/lastlogon.png)

**Answer:** `Administrator`

### Question 3: When did John log onto the system last?
To determine the exact timestamp of the last session for the user `John`, I targeted the specific account metadata directly from the command line. Instead of scrolling through a full user profile output, I piped the results of the `net user` command into `findstr` to isolate the specific string containing the logon timestamp. 

```cmd
net user John | findstr "Last logon"
```
![NetUserJohn](/assets/img/TryHackMe/THM-investigatingWindows/johnlogon.png)

**Answer:** `03/02/2019 5:48:32 PM`

### Question 4: What IP does the system connect to when it first starts?
To identify any persistent external network connections initiated at system boot, I investigated the standard Windows startup registry keys. Malware frequently abuses these keys to establish immediate C2 callbacks upon a reboot. I utilized PowerShell to query the local machine's standard `Run` key location:

```powershell
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Run
```
Upon analyzing the properties, an entry was discovered pointing to a malicious binary or script configured to execute an outbound connection to a specific remote IP address immediately upon startup.
![RegistryIp](/assets/img/TryHackMe/THM-investigatingWindows/ip.png)

**Answer:** `10.34.2.3`

### Question 5: What two accounts had administrative privileges (other than the Administrator user)?
To identify potential privilege escalation or unauthorized persistent access, I audited the local `Administrators` group membership. Threat actors frequently add their backdoor accounts directly to this group to maintain full control over the compromised host. I executed the following PowerShell command to list all current administrative accounts:
```powershell
Get-LocalGroupMember -Group "Administrators" | Select-Object Name, PrincipalSource, ObjectClass
```
![AdminGroup](/assets/img/TryHackMe/THM-investigatingWindows/administartors.png)

**Answer:** `Guest,Jenny`

### Question 6: Whats the name of the scheduled task that is malicous.
To identify persistence established via scheduled tasks without sifting through hundreds of benign default Windows tasks, I used PowerShell to filter out legitimate Microsoft entries. I constructed a query to exclude any task path beginning with `\Microsoft*` and dynamically pulled the actual executable path linked to the task's action:

```powershell
Get-ScheduledTask | ? {$_.TaskPath -notlike "\Microsoft*"} | Select TaskName, TaskPath, @{N="Run";E={$_.Actions.Execute}}
```
![GetTasks](/assets/img/TryHackMe/THM-investigatingWindows/getstasks.png)

**Answer:** `Clean file system`

### Question 7: What file was the task trying to run daily?
I analyzed the `Run` column output for the identified anomalous tasks. The task titled `Clean file system` was found to be pointing directly to a script located in a temporary directory:

```text
  Path: C:\TMP\nc.ps1
```
**Answer:** `nc.ps1`

### Question 8: What port did this file listen locally for?
To analyze the behavior of the `nc.ps1` file, I inspected the specific arguments of this scheduled task. Checking the runtime parameters revealed that the script was configured to listen locally on port `1348`.
```powerhsell
 (Get-ScheduledTask -Taskname "Clean file system").Actions
```
![Port](/assets/img/TryHackMe/THM-investigatingWindows/port.png)

**Answer:** `1348`

### Question 9: When did Jenny last logon?
To check last logon of 'Jenny' account, I pulled her profile details and used `findstr` to look specifically for her last login time:
```powershell
net user Jenny | findstr "Last logon"
```
![jennylogon](/assets/img/TryHackMe/THM-investigatingWindows/jennylogon.png)

**Answer:** `never`

### Question 10: At what date did the compromise take place?
Since the `Clean file system` scheduled task was a confirmed Indicator of Compromise (IoC), I targeted its underlying task file in the Windows filesystem. I checked the exact creation date of the file using PowerShell:
```powershell
(Get-Item "C:\Windows\System32\tasks\Clean file system").CreationTime
```
![GetItem](/assets/img/TryHackMe/THM-investigatingWindows/compromisetime.png)

**Answer:** `03/02/2019`

### Question 11: During the compromise, at what time did Windows first assign special privileges to a new logon?
Since I already knew the exact date of the breach from the previous step, I switched over to the Windows Event Viewer to dig into the authentication logs. I created a custom view targeting the **Security** log and filtered specifically for March 2nd, 2019, to cut down on the noise. 

To find when special privileges were assigned to a session, I discovered Security Group Management changes within that timeframe. Checking the log entry for this event revealed the exact second the elevated session was initiated.
![Event Viewer Date Filter](/assets/img/TryHackMe/THM-investigatingWindows/eventviewer.png)
![securityevent](/assets/img/TryHackMe/THM-investigatingWindows/securityevent.png)

**Answser:** `03/02/2019 4:04:49 PM`

### Question 12: What tool was used to get Windows passwords?
Since earlier questions pointed to the `C:\TMP` directory as a staging ground for the attacker's scripts, I decided to manually explore the contents of that folder. Inside, I found several highly suspicious files, including text logs. Opening a file named `mim-out` revealed the unmistakable banner of Mimikatz being used to harvest cleartext credentials and NTLM hashes from the system's memory.
![Staged Credential Dumping Artifacts](/assets/img/TryHackMe/THM-investigatingWindows/mimikatz.png)

**Answer:** `mimikatz`

### Question 12: What was the attackers external control and command servers IP?
To see if the attacker altered local DNS resolution to manipulate network traffic or block security software, I checked the Windows `hosts` file using Notepad from PowerShell:

```powershell
notepad.exe C:\Windows\System32\drivers\etc\hosts
```
![MaliciousIp](/assets/img/TryHackMe/THM-investigatingWindows/maliciusip.png)

**Answer:** `76.32.97.132`

### Question 13: What was the extension name of the shell uploaded via the servers website?
Since the server was hosting a web application, I pivoted to investigate the default IIS web root directory to check for unauthorized file uploads. 
![WebShell](/assets/img/TryHackMe/THM-investigatingWindows/jspfiles.png)
Inside the directory, I discovered two anomalous files with a .jsp extension. Threat actors frequently drop these JavaServer Pages scripts into web directories to act as web shells, granting them persistent remote command execution through the browser.

**Answer:** `.jsp`

### Question 14: What was the last port the attacker opened?
To allow remote traffic to hit their backdoors, attackers often have to punch a hole through the local security. I opened up **Windows Firewall with Advanced Security** to review the inbound rules. Knowing that legitimate Windows rules are usually neatly categorized, I sorted the list by the **Group** column to easily spot any anomalies. 

Sure enough, a rule completely lacking a group name stood out at the bottom: `"Allow outside connections for development"`. Inspecting its properties revealed that the attacker had explicitly opened up TCP port `1337`.

![Firewall Rule Analysis](/assets/img/TryHackMe/THM-investigatingWindows/portffirewall.png)

**Answer:** `1337`

### Question 15: Check for DNS poisoning, what site was targeted?
To check for local DNS poisoning, I looped back to the discoveries made while reviewing the `C:\Windows\System32\drivers\etc\hosts` file. Since the `hosts` file forces the operating system to bypass external DNS servers and look up IP mappings locally, it is a prime target for traffic hijacking. 

The file analysis clearly showed that the attacker was explicitly targeting `google.com`.

**Answer:** `google.com`
