# Certified Red Team Professional (CRTP) - Study Material

<!--
<div>
	<img src="https://assets.ine.com/certifications/badges/eWPT.png" alt="eWPT Logo" width="150" height="auto">
</div>
-->

## Introduction

This repository is dedicated to documenting my preparation for the Certified Red Team Professional (CRTP) exam. It includes structured notes, technical explanations, and practical walkthroughs covering key topics in Active Directory security and exploitation, aligning with the CRTP curriculum.

The materials are organized to provide a clear understanding of each concept, with detailed examples, input commands, and corresponding outputs. This allows readers to follow along without needing to replicate every step on their own test environment.

Each section covers essential red teaming techniques, including Active Directory enumeration, privilege escalation, lateral movement, Kerberos attacks, and domain dominance strategies. The repository highlights the methodologies, tools, and best practices used by red teamers to assess and exploit AD environments.

Whether you're preparing for the CRTP certification or looking to enhance your knowledge of Active Directory security, this repository serves as both a study guide and a technical resource for anyone interested in offensive security and red teaming.

## Learning Path Topics

#### 01 [Learning Objective](./learning_objective_01.md)

- [x] **Enumerate following for the `dollarcorp` domain:**
	- [x]  **Users**
	- [x] **Computers**
	- [x] **Domain Administrators**
	- [x] **Enterprise Administrators**
- [x] **Use BloodHound to identify the shortest path to Domain Admins in the `dollarcorp` domain**
- [ ] **Find a file share where `student422` has Write permissions**

#### 02 [Learning Objective](./learning_objective_02.md)

- [x] **Enumerate following for the dollarcorp domain:**
	- [x] **ACL for the Domain Admins group**
	- [x] **ACLs where `student422` has interesting permissions**
- [x] **Analyze the permissions for `student422	 in BloodHound UI**

#### 03 [Learning Objective](./learning_objective_03.md)

- [x] **Enumerate following for the `dollarcorp` domain:**
	- [x] **List all the OUs**
	- [x] **List all the computers in the `DevOps` OU**
	- [x] **List the GPOs**
	- [x] **Enumerate GPO applied on the `DevOps` OU**
	- [x] **Enumerate ACLs for the `Applocker` and `DevOps` GPOs**

#### 04 [Learning Objective](./learning_objective_04.md)

- [x] **Enumerate all domains in the `moneycorp.local` forest**
- [x] **Map the trusts of the `dollarcorp.moneycorp.local` domain**
- [x] **Map External trusts in `moneycorp.local` forest**
- [x] **Identify external trusts of `dollarcorp` domain. Can you enumerate trusts for a trusting forest?**

#### 05 [Learning Objective](./learning_objective_05.md)

- [x] **Exploit a service on `dcorp-student422` and elevate privileges to local administrator**
- [x] **Identify a machine in the domain where `student422` has local administrative access**
- [x] **Using privileges of a user on Jenkins on `172.16.3.11:8080`, get admin privileges on `172.16.3.11`, the `dcorp-ci` server**

#### 06 [Learning Objective](./learning_objective_06.md)

- [ ] **Abuse an overly permissive Group Policy to get admin access on `dcorp-ci`**

#### 07 [Learning Objective](./learning_objective_07.md)

- [x] **Identify a machine in the target domain where a Domain Admin session is available**
- [x] **Compromise the machine and escalate privileges to Domain Admin by abusing reverse shell on `dcorp-ci`**
- [x] **Escalate privilege to DA by abusing derivative local admin through `dcorp-adminsrv`**. On `dcorp-adminsrv`, tackle application allow listing using:
	- [x] Gaps in Applocker rules
	- [x] Disable Applocker by modifying GPO applicable to `dcorp-adminsrv`

#### 08 [Learning Objective](./learning_objective_08.md)

- [x] **Extract secrets from the domain controller of `dollarcorp`**
- [x] **Using the secrets of `krbtgt` account, create a golden ticket**
- [x] **Use the golden ticket to (once again) get domain admin privileges from a machine**

#### 09 [Learning Objective](./learning_objective_09.md)

- [x] **Try to get command execution on the domain controller by creating silver ticket for:**
	- [x] **HTTP**
	- [x] **WMI**

#### 10 [Learning Objective](./learning_objective_10.md)

- [x] **Use domain admin privileges obtained earlier to execute the diamond ticket attack**

#### 11 [Learning Objective](./learning_objective_11.md)

- [x] **Use domain admin privileges obtained earlier to abuse the DSRM credential for persistence**

#### 12 [Learning Objective](./learning_objective_12.md)

- [x] **Check if `student422` has Replication (DCSync) rights**
- [x] **If yes, execute the DCSync attack to pull hashes of the `krbtgt` user**
- [x] **If no, add the replication rights for the `student422` and execute the DCSync attack to pull hashes of the `krbtgt` user**

#### 13 [Learning Objective](./learning_objective_13.md)

- [x] **Modify security descriptors on `dcorp-dc` to get access using PowerShell remoting and WMI without requiring administrator access**
- [x] **Retrieve machine account hash from `dcorp-dc` without using administrator access and use that to execute a Silver Ticket attack to get code execution with WMI**

#### 14 [Learning Objective](./learning_objective_14.md)

- [x] **Using the kerberoasting attack, crack password of a SQL server service account**

#### 15 [Learning Objective](./learning_objective_15.md)

- [ ] **Find a server in the `dcorp` domain where Unconstrained Delegation is enabled**
- [ ] **Compromise the server and escalate to Domain Admin privileges**
- [ ] **Escalate to Enterprise Admins privileges by abusing Printer Bug**

#### 16 [Learning Objective](./learning_objective_16.md)

- [ ] **Enumerate users in the domain for whom Constrained Delegation is enabled**
	- [ ] **For such a user, request a TGT from the DC and obtain a TGS for the service to which delegation is configured**
	- [ ] **Pass the ticket and access the service**
- [ ] **Enumerate computer accounts in the domain for which Constrained Delegation is enabled**
	- [ ] **For such a user, request a TGT from the DC**
	- [ ] **Obtain an alternate TGS for LDAP service on the target machine**
	- [ ] **Use the TGS for executing DCSync attack**

#### 17 [Learning Objective](./learning_objective_17.md)

- [x] **Find a computer object in `dcorp` domain where we have Write permissions**
- [x] **Abuse the Write permissions to access that computer as Domain Admin**

#### 18 [Learning Objective](./learning_objective_18.md)

- [x] **Using Domain Admin access to `dollarcorp.moneycorp.local`, escalate privileges to Enterprise Admins using the domain trust key**

#### 19 [Learning Objective](./learning_objective_19.md)

- [x] **Using DA access to `dollarcorp.moneycorp.local`, escalate privileges to Enterprise Admins using` dollarcorp`'s `krbtgt` hash**

#### 20 [Learning Objective](./learning_objective_20.md)

- [x] **With DA privileges on `dollarcorp.moneycorp.local`, get access to `SharedwithDCorp` share on the DC of `eurocorp.local` forest**

#### 21 [Learning Objective](./learning_objective_21.md)

- [x] **Check if AD CS is used by the target forest and find any vulnerable/abusable templates**
- [x] **Abuse any such template(s) to escalate to Domain Admin and Enterprise Admin**

#### 22 [Learning Objective](./learning_objective_22.md)

- [x] **Get a reverse shell on a SQL server in `eurocorp` forest by abusing database links from `dcorp-mssql`**

#### 23 [Learning Objective](./learning_objective_23.md)

- [x] **Compromise `eu-sql26` again. Use opsec friendly alternatives to bypass MDE and MDI**

---
---
