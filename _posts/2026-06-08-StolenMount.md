---
title: "TryHackMe: Stolen Mount Writeup"
date: 2026-06-08 12:00:00
categories: [Writeups,TryHackMe,]
tags: [wireshark, nfs, pcap, network-forensics, cyberchef, hashcat, zip, qrcode]
description: "Network forensics challenge involving NFS traffic analysis, file carving from a PCAP, password cracking, and QR code decoding to uncover a stolen secret."
image:
  path: /assets/img/banners/StolenMount.png 
---

## Scenario

> An intruder has infiltrated our network and targeted the NFS server where the backup files are stored. A classified secret was accessed and stolen. The only trace left behind is a packet capture (PCAP) file recorded during the incident. Your mission, should you accept it, is to discover the contents of the stolen data.

The challenge file `challenge.pcapng` is located at `~/Desktop`. Our goal is to reconstruct the attacker's actions and ultimately recover the stolen secret.

---

## Step 1 - Filtering NFS Traffic in Wireshark

We start by opening `challenge.pcapng` in Wireshark. The capture contains a large amount of traffic, so the first thing to do is narrow it down to what matters. Since the scenario tells us the target was an **NFS (Network File System) server**, we apply a display filter:

```
nfs
```

![Wireshark NFS filter applied](/assets/img/TryHackMe/StolenMount/1.png)

_Filtering by `nfs` reveals NFS-related packets between 10.10.119.157 and 172.16.175.128_

Immediately, the traffic tells a story. We can observe repeated `LOOKUP` and `GETATTR` calls standard NFS operations used to traverse and inspect files on a remote share. The attacker is clearly enumerating the filesystem.

One packet stands out **Frame 164** a `V4 Call` with the path `0x4ffb5beb/creds.tx` highlighted in the Info column. This is a `LOOKUP` operation targeting a file named **`creds.txt`**, a strong indicator that the attacker located and accessed a credentials file.

The bottom panel confirms this is an NFS v4 `COMPOUND` call with operations: `SEQUENCE, PUTFH, LOOKUP, GETFH, GETATTR` the typical sequence used to locate and open a file on an NFS share.

---

## Step 2 - Following the TCP Stream

To reconstruct the full conversation and extract the raw data transferred, we right-click on one of the NFS packets and select:

**Follow → TCP Stream**

![Right-click context menu showing Follow > TCP Stream](/assets/img/TryHackMe/StolenMount/2.png)

_Following the TCP stream lets us see the full raw data exchanged during the NFS session_

This is a crucial step in PCAP forensics. NFS runs over TCP, which means file data is split across many individual packets. By following the stream, Wireshark reassembles all those packets into the complete byte sequence - letting us see the actual content that was transferred between the attacker and the server.

---

## Step 3 - Spotting Key Artefacts in the Stream

Inside the raw TCP stream, we can make out several interesting strings buried in the binary NFS data:

![TCP stream showing "Archive Password" label and MD5 hash value](/assets/img/TryHackMe/StolenMount/3.png)

_The stream reveals an archive password label followed immediately by what appears to be an MD5 hash_

Two things jump out:

- The string **`Archive Password`** - a plaintext label indicating that an archive password is stored nearby in the file.
- The value **`90eb7723a657b6597100aafef171d9f2`** - 32 hex characters, the length of an MD5 hash. This is almost certainly the hashed password protecting an encrypted archive.

The fact that both a password hash and what appear to be ZIP files are present in the NFS traffic means the attacker didn't just read `creds.txt` - they also pulled down an archive containing something sensitive. We need to carve those files out of the stream.

---

## Step 4 - Carving Files from the Stream with CyberChef

To extract the embedded ZIP files, we first need the raw bytes from the stream. In Wireshark's Follow TCP Stream dialog, we change the display format to **Hex Dump**:

![Wireshark "Show data as Hex Dump" dropdown](/assets/img/TryHackMe/StolenMount/6.png)

_Switching to Hex Dump gives us the offset-prefixed hex data that CyberChef can parse_

We copy the entire hex dump output and paste it into **[CyberChef](https://gchq.github.io/CyberChef/)**, then build the following recipe:

1. **From Hexdump** - converts the Wireshark-formatted hex dump back into raw bytes
2. **Extract Files** - scans the raw bytes for known file magic signatures and carves out any complete files it finds (ZIP files start with the magic bytes `PK\x03\x04`)

![CyberChef recipe showing From Hexdump and Extract Files, with 2 ZIP files in output](/assets/img/TryHackMe/StolenMount/7.png)

_CyberChef successfully carves 2 ZIP archives from the stream data_

CyberChef finds **2 files**:

| File | Size |
|------|------|
| `extracted_at_0x8e64.zip` | 806 bytes |
| `extracted_at_0x9113.zip` | 119 bytes |

We download both for further analysis.

---

## Step 5 - Attempting to Unzip - Password Required

Running `unzip` on the first archive immediately shows it is password protected:

```bash
unzip extracted_at_0x8e64.zip
```

![Terminal showing unzip prompting for a password to extract secrets.png](/assets/img/TryHackMe/StolenMount/8.png)

_The archive contains `secrets.png` but requires a password_

The archive holds a file called **`secrets.png`**. We need the password - which we strongly suspect is whatever plaintext value hashes to `90eb7723a657b6597100aafef171d9f2`.

---

## Step 6 - Cracking the MD5 Hash with Hashcat

We save the hash to a file and run **Hashcat** against the `rockyou.txt` wordlist:

```bash
echo 90eb7723a657b6597100aafef171d9f2 > hash.txt
hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

![Hashcat command running against the MD5 hash](/assets/img/TryHackMe/StolenMount/9.png)

Breaking down the flags:
- `-m 0` - hash type: MD5
- `-a 0` - attack mode: dictionary (straight wordlist)
- `hash.txt` - file containing our target hash
- `/usr/share/wordlists/rockyou.txt` - the wordlist to test against

![Hashcat result: 90eb7723a657b6597100aafef171d9f2:avengers](/assets/img/TryHackMe/StolenMount/10.png)

The password is **`avengers`**.

---

## Step 7 - Extracting the Archives

With the password, we extract the first archive successfully:

```bash
unzip extracted_at_0x8e64.zip   # password: avengers → secrets.png extracted
ls
unzip extracted_at_0x9113.zip
```

![Terminal showing secrets.png extracted, and errors on the second ZIP](/assets/img/TryHackMe/StolenMount/11.png)

_`secrets.png` extracts cleanly; the second ZIP fails with corruption errors_

The second archive (`extracted_at_0x9113.zip`) throws errors:

```
error [extracted_at_0x9113.zip]: missing 687 bytes in zipfile
error: invalid zip file with overlapped components (possible zip bomb)
```

This is likely a truncated file when carving from a network capture, a file transfer that wasn't fully completed will appear incomplete in the PCAP. It's not needed for our objective.

---

## Step 8 - Decoding the QR Code

Opening `secrets.png` reveals a **QR code**. Scanning it with any QR reader gives us the flag:

![secrets.png containing a QR code, decoded to THM{n0t_s3cur3_f1l3_sh4r1ng}](/assets/img/TryHackMe/StolenMount/12.png)

_The QR code decodes to the final flag_

---

## Flag

```
THM{n0t_s3cur3_f1l3_sh4r1ng}
```

---

## Attack Chain Summary

```
challenge.pcapng
    └─► Wireshark: filter nfs
            └─► Suspicious LOOKUP for creds.txt identified
                    └─► Follow TCP Stream → Show as Hex Dump
                            └─► CyberChef: From Hexdump + Extract Files
                                    └─► 2 ZIP archives carved from stream
                                    └─► MD5 hash spotted in stream data
                                            └─► Hashcat -m 0 rockyou.txt → "avengers"
                                                    └─► unzip extracted_at_0x8e64.zip → secrets.png
                                                            └─► Scan QR code → FLAG
```

---

## Key Takeaways

- **NFS is plaintext by default.** File contents, filenames, and access patterns are all visible in an unencrypted capture. Always use NFS over a VPN or with Kerberos (`sec=krb5p`) in production environments.
- **Wireshark's Follow TCP Stream** is one of the most powerful tools for reassembling application-layer data from packet captures - especially for protocols like NFS that span many packets.
- **CyberChef's Extract Files** recipe leverages file magic bytes (signatures) to carve known file types from raw binary streams, even when they're buried in NFS or other protocol data.
- **MD5 is cryptographically broken** for password storage. A single consumer GPU can test billions of MD5 hashes per second - common passwords from `rockyou.txt` fall in under a second.
- **Never store passwords in the same channel as the data they protect.** The hash and the archive were both transferred over the same unencrypted NFS session, making recovery trivial.
