# Certified Red Team Professional (CRTP) - Study Material

<!--
<div>
	<img src="https://assets.ine.com/certifications/badges/eWPT.png" alt="eWPT Logo" width="150" height="auto">
</div>
-->


01 ### Learning Objective

[x] **Enumerate following for the `dollarcorp` domain:**
	-  **Users**
	- **Computers**
	- **Domain Administrators**
	- **Enterprise Administrators**
[x] **Use BloodHound to identify the shortest path to Domain Admins in the `dollarcorp` domain**
[ ] **Find a file share where `studentx` has Write permissions**

02 ### Learning Objective

[x] **Enumerate following for the dollarcorp domain:**
	- **ACL for the Domain Admins group**
	- **ACLs where studentx has interesting permissions**
[x] **Analyze the permissions for studentx in BloodHound UI**

03 ### Learning Objective

[x] **Enumerate following for the `dollarcorp` domain:**
	- **List all the OUs**
	- **List all the computers in the `DevOps` OU**
	- **List the GPOs**
	- **Enumerate GPO applied on the `DevOps` OU**
	- **Enumerate ACLs for the `Applocker` and `DevOps` GPOs**

04 ### Learning Objective

[x] **Enumerate all domains in the `moneycorp.local` forest**
[x] **Map the trusts of the `dollarcorp.moneycorp.local` domain**
[x] **Map External trusts in `moneycorp.local` forest**
[x] **Identify external trusts of `dollarcorp` domain. Can you enumerate trusts for a trusting forest?**

05 ### Learning Objective

[x] **Exploit a service on `dcorp-studentx` and elevate privileges to local administrator**
[x] **Identify a machine in the domain where `studentx` has local administrative access**
[x] **Using privileges of a user on Jenkins on `172.16.3.11:8080`, get admin privileges on `172.16.3.11`, the `dcorp-ci` server**

06 ### Learning Objective

[ ] **Abuse an overly permissive Group Policy to get admin access on `dcorp-ci`**

07 ### Learning Objective

[ ] **Identify a machine in the target domain where a Domain Admin session is available**
[ ] **Compromise the machine and escalate privileges to Domain Admin by abusing reverse shell on `dcorp-ci`**
[ ] **Escalate privilege to DA by abusing derivative local admin through `dcorp-adminsrv`**. On `dcorp-adminsrv`, tackle application allow listing using:
	- Gaps in Applocker rules
	- Disable Applocker by modifying GPO applicable to `dcorp-adminsrv`

08 ### Learning Objective

[x] **Extract secrets from the domain controller of `dollarcorp`**
[x] **Using the secrets of `krbtgt` account, create a golden ticket**
[x] **Use the golden ticket to (once again) get domain admin privileges from a machine**

09 ### Learning Objective

[x] **Try to get command execution on the domain controller by creating silver ticket for:**
	- **HTTP**
	- **WMI**

10 ### Learning Objective

[x] **Use domain admin privileges obtained earlier to execute the diamond ticket attack**


---
---
