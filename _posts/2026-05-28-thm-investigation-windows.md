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
