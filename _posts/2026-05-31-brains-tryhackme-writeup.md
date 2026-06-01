---
layout: post
title: "TryHackMe: Brains Room Writeup"
date: 2026-05-31 15:00:00 +0200
categories: [Writeups, TryHackMe]
tags: [teamcity, cve-2024-27198, splunk, blue-team, red-team, purple-team, siem]
description: "A comprehensive Purple Team walkthrough of the TryHackMe 'Brains' machine, detailing both the offensive exploitation of JetBrains TeamCity and defensive log analysis using Splunk."
---

## Executive Summary

The **Brains** machine on TryHackMe provides an excellent, real-world scenario involving an outdated enterprise continuous integration and deployment server. This writeup documents the lifecycle of an incident on this machine from a **Purple Team** perspective. 

The first section outlines the offensive methodology used to gain initial access and retrieve the flag by exploiting a critical authentication bypass vulnerability in JetBrains TeamCity. The second section focuses on the defensive side, demonstrating how to track down the attacker's activities using **Splunk Enterprise** to analyze application and host-level operating system logs.

---

## Part 1: Red Team Perspective 

### Phase 1: Reconnaissance & Port Scanning

The engagement began with an active network scan using `nmap` to discover open ports, active services, and version specifications on the target host.

```bash
nmap -sC -sV -T4 10.112.153.119
```
![nmap](/assets/img/TryHackMe/Brains/nmap.png)

As documented above, the scan revealed three noteworthy entry points:
* **Port 22/tcp:** Open - `OpenSSH 8.2p1 Ubuntu 4ubuntu0.11`
* **Port 80/tcp:** Open - `Apache httpd 2.4.41`
* **Port 50000/tcp:** Open - Identified via custom HTTP response headers (`TeamCity-Node-Id: MAIN_SERVER`) as a `JetBrains TeamCity` deployment instance.

---

### Phase 2: Web Service Enumeration

#### Port 80 (Apache)
Navigating directly to the web application over port 80 loaded a standard placeholder screen, as shown.

![maintaince](/assets/img/TryHackMe/Brains/maintaince.png)

 The page indicated: *"We're currently performing some maintenance. Please check back soon."* No administrative pathways or interactive components were uncovered here.

#### Port 50000 (JetBrains TeamCity)
Directing the browser to `http://10.112.153.119:50000/login.html` loaded the primary JetBrains TeamCity authentication portal,

![login](/assets/img/TryHackMe/Brains/login.png)

Crucially, the bottom of the interface exposed the exact software build: **Version 2023.11.3**. 

---

### Phase 3: Vulnerability Analysis

Cross-referencing JetBrains TeamCity version `2023.11.3` against public vulnerability databases immediately highlighted a severe unauthenticated pathway: **CVE-2024-27198**.

![cve](/assets/img/TryHackMe/Brains/cve.png)

As outlined above:
* **Vulnerability Type:** Authentication Bypass leading to Remote Code Execution
* **CVSS v3.x Score:** `9.8 CRITICAL`
* **Impact:** An issue in the web components of JetBrains TeamCity before version 2023.11.4 allows an unauthenticated remote attacker to bypass access controls, gain administrative access, and execute arbitrary commands on the server hosting the application.

---

### Phase 4: Exploitation & Initial Access

Metasploit Framework was selected to orchestrate the initial access phase due to the availability of a highly reliable exploit module.

1. **Module Selection:** Running a quick query inside Metasploit pointed directly to the optimal exploit:

![metasploit](/assets/img/TryHackMe/Brains/metasploit.png)
   
```msf
   msf > search cve:2024-27198
   msf > use exploit/multi/http/jetbrains_teamcity_rce_cve_2024_27198
   ```

2. **Module Configuration:** Inspecting the options showed that the module targets port `8111` by default. This required a manual change to port `50000` to match our target environment:
```msf
   msf exploit(...) > set RHOSTS 10.112.153.119
   msf exploit(...) > set RPORT 50000
   ```
![metasploitOptions](/assets/img/TryHackMe/Brains/metasploitOptions.png)

![exploit](/assets/img/TryHackMe/Brains/exploit.png)

3. **Execution:** Launching the attack payload bypassed the login wall natively, generated a web session wrapper, and established a reverse `java/meterpreter/reverse_tcp` connection back to the attack station.

---

### Phase 5: Post-Exploitation & Flag Retrieval

With a functional Meterpreter session established, system navigation was initiated to collect administrative proof of concepts. Moving to the home directory of the default Linux account showed the filesystem structure:

```meterpreter
meterpreter > cd /home/ubuntu
meterpreter > ls
```

As detailed below, a `flag.txt` file was found directly inside the directory path. Reading the asset confirmed full system compromise:

```meterpreter
meterpreter > cat flag.txt
THM{xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}
```

![flag](/assets/img/TryHackMe/Brains/flag.png)

---

## Part 2: Blue Team Perspective 

To effectively analyze and remediate this incident, we transition to the defensive side using **Splunk Enterprise**. The investigation follows an incident response timeline: starting with an alert regarding unauthorized host modifications, moving through software audit logs, and finishing with root cause analysis within the application layer.

The central investigation platform used for executing queries is the Splunk **Search & Reporting** interface, as initialized below

![splunk](/assets/img/TryHackMe/Brains/splunk1.png)

---

### Phase 1: Detecting Local System Persistence

The investigation triggered after anomalous system account modifications were flagged on the underlying Ubuntu operating system. To track down potential backdoor accounts created by an adversary, Linux authentication logs (`/var/log/auth.log`) were investigated using Splunk.

#### Splunk Search Query:
```splunk
index="auth_logs" useradd
```
![useradd](/assets/img/TryHackMe/Brains/useradd.png)

#### Analysis:
As documented above, the query returned explicit evidence of malicious persistence attempts on `7/4/24` at `10:32:37 PM`:

```text
Jul  4 22:32:37 brains useradd[11207]: new group: name=eviluser, GID=1001
Jul  4 22:32:37 brains useradd[11207]: new user: name=eviluser, UID=1001, GID=1001, home=/home/eviluser, shell=/bin/bash, from=/dev/pts/0
Jul  4 22:32:56 brains useradd[11300]: failed adding user 'eviluser', data deleted
```

* **Findings:** The logs confirm that the attacker dropped into a local shell session (`/dev/pts/0`) and invoked the `useradd` binary to establish a backdoor account named `eviluser`. A separate event shortly after registers a failure state or data deletion, mapping out the precise operational window of the threat actor.

---

### Phase 2: Auditing System Modifications (Malicious Package Installation)

Following the discovery of the backdoor account, the investigation expanded to check if the attacker had installed unauthorized software, web shells, or C2 utilities to maintain their foothold. This required analyzing the package manager records (`/var/log/dpkg.log`).

#### Splunk Search Query:
```splunk
index=* source="/var/log/dpkg.log" "installed"
```
![dpkg](/assets/img/TryHackMe/Brains/dpkg.png)

#### Analysis:
The search results, identified an unapproved software deployment occurring less than 30 minutes after the backdoor account attempt:

```text
2024-07-04 22:58:25 status half-installed datacollector:amd64 1.0
2024-07-04 22:58:25 status installed datacollector:amd64 1.0
```

* **Findings:** The host system logged the installation of an external package named `datacollector:amd64 1.0`. This indicates a deliberate attempt by the adversary to deploy custom tooling, likely intended for local data harvesting, surveillance, or network beaconing.

---

### Phase 3: Root Cause Analysis 

With host compromise fully mapped, the final objective was to establish the original entry point. Since the network scan showed an exposed JetBrains TeamCity server, the investigation turned toward the application logs.

#### Architectural Research:
Before executing targeted queries, I reviewed application documentation to identify relevant log sources. As illustrated , TeamCity maintains application records within the `<TeamCity Server home>/logs` directory.

![logs](/assets/img/TryHackMe/Brains/logs.png)

#### Splunk Search Query:

```splunk
source="/opt/teamcity/TeamCity/logs/teamcity-activities.log" "plugin"
```
![plugin](/assets/img/TryHackMe/Brains/plugin.png)

#### Analysis:
The application audit records, revealed the exact initial exploitation vector that initiated the compromise:

```text
[2024-07-04 22:08:31,921] INFO - s.buildServer.ACTIVITIES.AUDIT - plugin_uploaded: Plugin "AyzzbuXY" was updated by "user with id=11" with comment "Plugin was uploaded to /home/ubuntu/.BuildServer/plugins/AyzzbuXY.zip"
```

* **Findings:** The log captures a `plugin_uploaded` action at `22:08:31`. An attacker successfully exploited **CVE-2024-27198** to bypass authentication, automatically creating an administrative user instance. This session was immediately used to upload a malicious, zip-compressed plugin file named `AyzzbuXY.zip`. This application-level execution gave the attacker the remote access required to perform the subsequent OS-level modifications discovered in Phase 1 and Phase 2.

---

## Strategic Remediation & Purple Team Takeaways

This collaborative exercise highlights how offensive actions look on defensive monitoring systems:

1. **Vulnerability Mitigation:** CI/CD frameworks are high-value targets. JetBrains TeamCity installations must be patched to version **2023.11.4** or higher immediately to block the authentication bypass loop used in this attack.
2. **Network Access Control:** Management platforms should never be exposed directly to public-facing networks. Access to port `50000` should be limited behind a secure corporate VPN or designated jump box.
