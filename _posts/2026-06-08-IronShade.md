---
title: "TryHackMe: IronShade Writeup"
date: 2026-06-08
categories: [Writeups, TryHackMe, ]
tags: [linux, forensics, incident-response, persistence, backdoor]
image:
  path: /assets/img/banners/IronShade.png
---

## Overview

IronShade is a Linux forensics / incident response room on TryHackMe. The scenario involves a compromised Ubuntu 20.04 server where an attacker gained access, planted a backdoor user, set up persistence mechanisms, installed a malicious package, and repeatedly attempted SSH logins. Our job is to piece together what happened.

---

## Task 1 – Machine Identification

**Q: What is the Machine ID of the machine we are investigating?**

```bash
hostnametcl
```

![Machine ID](/assets/img/TryHackMe/IronShade/machineid.png)

`hostnamectl` gives us a quick summary of the system identity. The **Machine ID** is a unique, persistent identifier stored in `/etc/machine-id` and is useful for tying logs and artifacts to a specific host.

> **Answer: `dc7c8ac5c09a4bbfaf3d09d399f10d96`**

---

## Task 2 – Backdoor User

**Q: What backdoor user account was created on the server?**

```bash
grep -E '*(bash|sh|zsh)$' /etc/passwd
```

![Backdoor user](/assets/img/TryHackMe/IronShade/backdooruser.png)

Filtering `/etc/passwd` for entries that have an interactive shell (`bash`, `sh`, or `zsh`) at the end of the line quickly surfaces all accounts capable of logging in. Alongside the expected `root` and `ubuntu` accounts we can see `mircoservice` a user designed to blend in as a legitimate service account, but with a home directory under `/home` and a full bash shell.

> **Answer: `mircoservice`**

---

## Task 3 – Cron-based Persistence

**Q: What is the cronjob that was set up by the attacker for persistence?**

```bash
sudo su
crontab -l
```

![Crontab](/assets/img/TryHackMe/IronShade/crontab.png)

After escalating to root we dump the root crontab. The `@reboot` directive tells cron to run the specified command every time the machine boots, making it a classic persistence trick even if the malicious process is killed, it will restart on the next reboot.

> **Answer: `@reboot /home/mircoservice/printer_app`**

---

## Task 4 – Hidden Running Process

**Q: Examine the running processes. Can you identify the suspicious-looking hidden process from the backdoor account?**

```bash
ps aux | grep mircoservice
```

![Processes](/assets/img/TryHackMe/IronShade/process.png)

Two processes are running out of the `mircoservice` home directory:

| PID | Command |
|-----|---------|
| 581 | `/home/mircoservice/.tmp/.strokes` |
| 837 | `/home/mircoservice/printer_app` |

The `.strokes` binary is tucked inside a hidden `.tmp` directory, making it unlikely to be noticed during a casual `ls` inspection. The dot-prefixed path is a dead giveaway legitimate applications rarely hide themselves like this.

> **Answer: `/home/mircoservice/.tmp/.strokes`**

---

## Task 5 – Process Count from Backdoor Directory

**Q: How many processes are found to be running from the backdoor account's directory?**

From the same `ps aux | grep mircoservice` output above, we can count the processes originating from `/home/mircoservice/` excluding the grep command itself that shows up in results.

> **Answer: `2`**

---

## Task 6 – Hidden File in Root Directory

**Q: What is the name of the hidden file in memory from the root directory?**

```bash
sudo find / -maxdepth 1 -name ".*" ! -name "." ! -name ".."
```

![Hidden file](/assets/img/TryHackMe/IronShade/hidden.png)

By searching the root `/` with a max depth of 1 and filtering for dot-files (while excluding `.` and `..`), we surface any hidden files or directories placed directly at the filesystem root. Attackers sometimes use this location because it's outside of standard user home directories and less commonly inspected.

> **Answer: `.systmd`**

---

## Task 7 – Suspicious Services

**Q: What suspicious services were installed on the server?**

```bash
sudo systemctl list-units --type=service --all
```

![Services list 1](/assets/img/TryHackMe/IronShade/services1.png)
![Services list 2](/assets/img/TryHackMe/IronShade/services2.png)

Listing all systemd units (including inactive/dead ones) lets us audit every service registered on the system. Two entries stand out immediately:

- **`backup.service`** described simply as "updater"; the vague, misleading description is a red flag.
- **`strokes.service`** named "strokes", which aligns with the `.strokes` binary seen in the running processes.

Legitimate services are typically well-described with vendor names and purposes. These two have suspiciously generic or opaque descriptions.

> **Answer: `backup.service, strokes.service`**

---

## Task 8 – Backdoor Account Creation Time

**Q: When was the backdoor account created on this infected system?**

```bash
sudo cat /var/log/auth.log* | grep -a "useradd"
```

![Backdoor creation time](/assets/img/TryHackMe/IronShade/backdoorTime.png)
![Backdoor user log](/assets/img/TryHackMe/IronShade/backdoor2.png)

`auth.log` records all authentication-related events including user creation via `useradd`. Grepping for `useradd` across all rotated logs (`auth.log*`) gives us the full history. We can see two creation events:

- `Aug 5 22:05:33` `mircoservice` created (UID 1001)
- `Jul 2 21:40:33` `badactor` created (UID 1001, same slot, likely deleted before mircoservice was added)

The relevant backdoor account `mircoservice` was created on **Aug 5 22:05:33**.

> **Answer: `Aug 5 22:05:33`**

---

## Task 9 – SSH Source IP

**Q: From which IP address were multiple SSH connections observed against the suspicious backdoor account?**

```bash
sudo cat /var/log/auth.log* | grep -a -E "sshd.*mircoservice"
```

![SSH IP](/assets/img/TryHackMe/IronShade/ip.png)

Filtering auth logs for sshd events related to `mircoservice` shows all successful logins, session openings, and failures. Every single connection originates from the same source address.

> **Answer: `10.11.75.247`**

---

## Task 10 – Failed SSH Login Attempts

**Q: How many failed SSH login attempts were observed on the backdoor account?**

```bash
sudo cat /var/log/auth.log* | grep -a -E "sshd.*mircoservice"
```

![Failed logins](/assets/img/TryHackMe/IronShade/failed.png)

Counting the lines containing "Failed password for mircoservice" (including the "message repeated N times" entries) gives us the total failed attempt count. The repeated connection resets and PAM failures suggest the attacker may have lost or rotated credentials at some point.

> **Answer: `8`**

---

## Task 11 – Malicious Package

**Q: Which malicious package was installed on the host?**

```bash
grep " status installed " /var/log/dpkg.log* | sort
```

![Package log](/assets/img/TryHackMe/IronShade/package.png)

The `dpkg.log` records every package installation event with timestamps. Sorting chronologically and reviewing the list shows the usual system packages and then an outlier `pscanner` installed on `2024-08-06 01:10:21`. The name loosely mimics legitimate port/process scanner utilities but doesn't correspond to any known legitimate Debian/Ubuntu package.

> **Answer: `pscanner`**

---

## Task 12 – Secret Code in Package Metadata

**Q: What is the secret code found in the metadata of the suspicious package?**

```bash
dpkg -l | grep pscanner
```

![Package secret code](/assets/img/TryHackMe/IronShade/code.png)

`dpkg -l` displays the package list including the Description field from each package's metadata. The attacker embedded a secret string directly in the package description an unusual but occasionally used technique to watermark or communicate between implants.

> **Answer: `Secret_code{tRy_Hack_ME_}`**

---

### Key Takeaways

The attacker used a fairly complete playbook:

- **Initial access** via SSH with a newly created user (`mircoservice`) designed to blend in as a service account.
- **Persistence** through both a crontab `@reboot` entry and a registered systemd service (`strokes.service`, `backup.service`).
- **Stealth** via a hidden binary inside a dot-directory (`.tmp/.strokes`) and a hidden file at the root level (`.systmd`).
- **Custom malware delivery** through a fake Debian package (`pscanner`) with an embedded identifier in the description field.

Monitoring for unusual user creation in `auth.log`, auditing systemd services, and checking `/var/log/dpkg.log` for unexpected package installs are all effective detection strategies for this kind of intrusion.
