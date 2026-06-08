---
layout: post
title: "TryHackMe: InvestigatingWithSplunk"
date: 2026-06-05 09:00 +0200
categories: [Writeups, TryHackMe]
tags: [splunk, incident-response, powershell, cyberchef, forensics]
image: /assets/img/banners/InvestigatingSplunk.png
---

## Introduction

In this incident response scenario, we leverage **Splunk Enterprise** to investigate a multi-stage corporate network compromise. By correlating Windows Security event logs, Sysmon telemetry, and PowerShell operational logs, we will reconstruct the attacker's timeline from initial remote execution to persistence mechanisms and command-and-control (C2) configuration.

---

## Phase 1: Initial Log Analysis & Finding the Footprint

Our hunting workflow starts with a broad query across the default index to determine the scope of available telemetry.

```spl
index="main"
```

As captured below, our search over **All time** returns **12,256 events**, indicating a rich dataset of host log activity.

![main](/assets/img/TryHackMe/InvestigatingWithSplunk/main.png)

To discover potential persistence mechanisms, we target local user account creation. In Windows environments, this action triggers **Security Event ID 4720**.

```spl
index="main" EventID=4720
```

This narrows our search down to exactly **1 event**.

![newuser](/assets/img/TryHackMe/InvestigatingWithSplunk/newuser.png)

---

## Phase 2: Analyzing the Lookalike Backdoor Account

Drilling down into the Event ID 4720 details, we uncover the core attributes of the newly generated user:

* **Subject Account (The Creator):** `James` (Domain: `Cybertees`)
* **Target Account Name:** `Alberto`
* **SAM Account Name:** `A1berto`
* **Account Domain:** `WORKSTATION6`

![a1berto](/assets/img/TryHackMe/InvestigatingWithSplunk/a1berto.png)

> 🔍 **Security Catch:** Notice the visual spoofing technique (typosquatting). The attacker swapped the lowercase letter **'l'** for the number **'1'** (`A1berto`). This is a classic evasion tactic designed to deceive administrators reviewing user directories.

To verify how the operating system committed this account, we check Sysmon **Event ID 12** (Registry Object Added) filtered by the username:

```spl
index="main" EventID="12" a1berto | table sort TargetObject
```

Splunk returns **2 events** highlighting direct modifications inside the Security Account Manager (SAM) registry hive:
* `HKLM\SAM\SAM\Domains\Account\Users\Names\A1berto`

![registry](/assets/img/TryHackMe/InvestigatingWithSplunk/registry.png)

---

## Phase 3: Tracking the Remote Execution Vector 

Now we must determine *how* the account creation command was introduced to `WORKSTATION6`. We run a query targeting the keyword `a1berto` and tabularize the process command lines:

```spl
index="main" a1berto | table sort CommandLine
```

The query returns **14 events**. The definitive execution vector is revealed as a remote process call via the Windows Management Instrumentation Command-line (**WMIC**):

![command](/assets/img/TryHackMe/InvestigatingWithSplunk/command.png)

```cmd
"C:\windows\System32\Wbem\WMIC.exe" /node:WORKSTATION6 process call create "net user /add A1berto paw0rd1"
```

### Contextual Analysis
* **Mechanism:** Examining the logs reveals that the adversary was actively attempting to impersonate the legitimate user Alberto.
The attacker utilized an already-compromised administrative session under the identity of James to remotely instruct WORKSTATION6 to add a lookalike backdoor account. To blend in with valid corporate directory objects, they deployed a typosquatting technique registering the SAM Account Name as A1berto (swapping the lowercase "l" for the number "1").

![impersonate](/assets/img/TryHackMe/InvestigatingWithSplunk/impersonate.png)

---

## Phase 4: Auditing Backdoor Usage 

A critical scoping step is confirming whether the attacker has already established an interactive session using this backdoor. We query for successful Windows logons (**Event ID 4624**) referencing our lookalike string:

```spl
index="main" EventID="4624" "A1berto"
```

The search returns **0 events**. This indicates that while the persistence mechanism was successfully deployed, the threat actor has not yet authenticated interactively with the `A1berto` account within this log window.

![logon](/assets/img/TryHackMe/InvestigatingWithSplunk/logon.png)

---

## Phase 5: Investigating Malicious PowerShell Activity

Since the backdoor account wasn't accessed directly, the adversary is likely driving actions via alternative script pipelines. We filter specifically for the **powershell** keyword and tabularize the output by `ContextInfo`:

```spl
index="main" powershell
| table sort ContextInfo
```

Our updated search yields **198 events**. Reviewing the detailed execution fields exposes a high-severity, heavily obfuscated command launched by `Cybertees\James`:

![encoded](/assets/img/TryHackMe/InvestigatingWithSplunk/encoded.png)

```cmd
Host Application = C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -noP -sta -w 1 -enc SQBGACgAJABQAFM...
```

The execution uses aggressive stealth configurations to fly under the radar:
* `-noP` blocks user profile execution.
* `-sta` runs the engine in a single-threaded apartment.
* `-w 1` hides the console window.
* `-enc` instructs the engine to process a Base64-encoded string.

---

## Phase 6: Deep-Dive Deobfuscation via CyberChef

To thoroughly understand the payload, we extract the raw Base64 string from Splunk and walk through a multi-stage decoding process inside CyberChef.

### Step 1: Decoding the Primary Stager Layer
As illustrated, we apply a standard decoding recipe:
1. **From Base64**
2. **Decode Text** (Set to `UTF-16LE (1200)`)

![recipe](/assets/img/TryHackMe/InvestigatingWithSplunk/recipe.png)

The resulting cleartext script exposes structural logic designed to blind local defenses by using reflection to disable `ScriptBlockLogging` and forcing the Anti-Malware Scan Interface flag `amsiInitFailed` to evaluate to `$true`. 

Crucially, the stager script constructs a connection mechanism via a secondary, nested Base64 string:
```powershell
$ser=$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwAxADAALgAxADAALgAxADAALgAxAA==')));
$t='/news.php';
```

### Step 2: Isolating the Command & Control Target
To pinpoint the remote infrastructure, we isolate that specific inner Base64 token (`aAB0AHQAcAA6AC8ALwAxADAALgAxADAALgAxADAALgAxAA==`) and pass it through a new decoding instance. 

Running the text through **From Base64** and **Decode Text (UTF-16LE)** strips away the final layer of encryption, explicitly revealing the C2 root host IP address:
```text
http://10.10.10.5
```
![decoded](/assets/img/TryHackMe/InvestigatingWithSplunk/decoded.png)

### Step 3: Mapping and Defanging the Full C2 URL
By cross-referencing the host root with the directory variable `$t='/news.php'` found in Step 1, we assemble the complete C2 callback path: `http://10.10.10.5/news.php`.

For safe documentation and integration into corporate Threat Intelligence feeds, we apply a **Defang URL** operation in CyberChef. This sanitizes the malicious connection string, preventing accidental executions or malicious clicks during reporting:

![defang](/assets/img/TryHackMe/InvestigatingWithSplunk/defang.png)

```text
hxxp[://]10[.]10[.]10[.]5/news[.]php
```


---

## Conclusion & Incident Remediation

### Attack Summary Matrix
* **Lateral Pivot:** The attacker utilized compromised domain credentials (`James`) to invoke remote command lines via `WMIC.exe`.
* **Backdoor Placement:** A typosquatted local user profile (`A1berto`) was registered into the SAM database on `WORKSTATION6`.
* **Defense Evasion:** An encoded PowerShell pipeline was spawned to forcefully disable Windows AMSI and event script tracking before initializing beacon callbacks to a remote server over `/news.php`.
* **C2 Infrastructure Identified:** Threat telemetry traces back explicitly to the remote network node located at `10.10.10.5`.

### Immediate Actions
* **Containment:** Erase and delete the local profile `A1berto` from `WORKSTATION6`. Force a global password reset and active session revocation for the compromised user `James`.
* **Defensive Hardening:** Block cross-workstation WMI/WMIC process creation privileges using Group Policy Objects. Configure Endpoint Detection and Response rules to trigger alerts on PowerShell executions containing the `-enc` flag alongside window-hiding parameters.
* **Network Blocking:** Ingest `10.10.10.5` and the associated path parameter into perimeter firewalls and web proxies as an active indicator of compromise blocklist rule.
