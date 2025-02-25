# Learning Objective 04 (Domain Enumeration | Forest + Trusts)

## Tasks

1. **Enumerate all domains in the `moneycorp.local` forest**
2. **Map the trusts of the `dollarcorp.moneycorp.local` domain**
3. **Map external trusts in `moneycorp.local` forest**
4. **Identify external trusts of `dollarcorp` domain. Can you enumerate trusts for a trusting forest?**

---

## Solution

We can use both PowerView and the Active Directory module to solve the tasks.

**Using PowerView**

**Note:** Remember to run PowerView from a PowerShell session started using Invisi-Shell.

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`cd \AD\Tools`

`C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat`:
```
[SNIP]
```

1. **Enumerate all domains in the `moneycorp.local` forest**

`Get-Forest`:
```
RootDomainSid         : S-1-5-21-335606122-960912869-3279953914
Name                  : moneycorp.local🏰
Sites                 : {Default-First-Site-Name}
Domains               : {dollarcorp.moneycorp.local, moneycorp.local, us.dollarcorp.moneycorp.local}
GlobalCatalogs        : {mcorp-dc.moneycorp.local, dcorp-dc.dollarcorp.moneycorp.local, us-dc.us.dollarcorp.moneycorp.local}
ApplicationPartitions : {DC=ForestDnsZones,DC=moneycorp,DC=local, DC=DomainDnsZones,DC=us,DC=dollarcorp,DC=moneycorp,DC=local,
                        DC=DomainDnsZones,DC=dollarcorp,DC=moneycorp,DC=local, DC=DomainDnsZones,DC=moneycorp,DC=local}
ForestModeLevel       : 7
ForestMode            : Unknown
RootDomain            : moneycorp.local🏛️
Schema                : CN=Schema,CN=Configuration,DC=moneycorp,DC=local
SchemaRoleOwner       : mcorp-dc.moneycorp.local
NamingRoleOwner       : mcorp-dc.moneycorp.local
```

Let’s enumerate all domains in the current forest.

`Get-ForestDomain -Verbose`:
```
Forest                  : moneycorp.local
DomainControllers       : {dcorp-dc.dollarcorp.moneycorp.local}
Children                : {us.dollarcorp.moneycorp.local}
DomainMode              : Unknown
DomainModeLevel         : 7
Parent                  : moneycorp.local
PdcRoleOwner            : dcorp-dc.dollarcorp.moneycorp.local
RidRoleOwner            : dcorp-dc.dollarcorp.moneycorp.local
InfrastructureRoleOwner : dcorp-dc.dollarcorp.moneycorp.local
Name                    : dollarcorp.moneycorp.local🏛️

Forest                  : moneycorp.local
DomainControllers       : {mcorp-dc.moneycorp.local}
Children                : {dollarcorp.moneycorp.local}
DomainMode              : Unknown
DomainModeLevel         : 7
Parent                  :
PdcRoleOwner            : mcorp-dc.moneycorp.local
RidRoleOwner            : mcorp-dc.moneycorp.local
InfrastructureRoleOwner : mcorp-dc.moneycorp.local
Name                    : moneycorp.local🏛️

Forest                  : moneycorp.local
DomainControllers       : {us-dc.us.dollarcorp.moneycorp.local}
Children                : {}
DomainMode              : Unknown
DomainModeLevel         : 7
Parent                  : dollarcorp.moneycorp.local
PdcRoleOwner            : us-dc.us.dollarcorp.moneycorp.local
RidRoleOwner            : us-dc.us.dollarcorp.moneycorp.local
InfrastructureRoleOwner : us-dc.us.dollarcorp.moneycorp.local
Name                    : us.dollarcorp.moneycorp.local🏛️
```

2. **Map the trusts of the `dollarcorp.moneycorp.local` domain**

To map all the trusts of the `dollarcorp` domain.

`Get-DomainTrust`:
```
SourceName      : dollarcorp.moneycorp.local🏛️
TargetName      : moneycorp.local🏛️
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST
TrustDirection  : Bidirectional🔗
WhenCreated     : 11/12/2022 5:59:01 AM
WhenChanged     : 2/6/2025 5:09:45 AM

SourceName      : dollarcorp.moneycorp.local🏛️
TargetName      : us.dollarcorp.moneycorp.local🏛️
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST
TrustDirection  : Bidirectional🔗
WhenCreated     : 11/12/2022 6:22:51 AM
WhenChanged     : 2/11/2025 5:17:26 AM

SourceName      : dollarcorp.moneycorp.local🏛️
TargetName      : eurocorp.local🏛️
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FILTER_SIDS📌
TrustDirection  : Bidirectional🔗
WhenCreated     : 11/12/2022 8:15:23 AM
WhenChanged     : 2/11/2025 5:17:24 AM
```

3. **Map external trusts in `moneycorp.local` forest**

Now, to list only the external trusts in the `moneycorp.local` forest.

`Get-ForestDomain | %{Get-DomainTrust -Domain $_.Name} | ?{$_.TrustAttributes -eq "FILTER_SIDS"}`:
```
SourceName      : dollarcorp.moneycorp.local🏛️
TargetName      : eurocorp.local🏛️
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FILTER_SIDS📌
TrustDirection  : Bidirectional🔗
WhenCreated     : 11/12/2022 8:15:23 AM
WhenChanged     : 2/11/2025 5:17:24 AM
```

4. **Identify external trusts of `dollarcorp` domain. Can you enumerate trusts for a trusting forest?**

To identify external trusts of the `dollarcorp` domain, we can use the below command.

`Get-DomainTrust | ?{$_.TrustAttributes -eq "FILTER_SIDS"}`:
```
SourceName      : dollarcorp.moneycorp.local🏛️
TargetName      : eurocorp.local🏛️
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FILTER_SIDS📌
TrustDirection  : Bidirectional🔗
WhenCreated     : 11/12/2022 8:15:23 AM
WhenChanged     : 2/11/2025 5:17:24 AM
```

Since the above is a bi-directional trust, we can extract information from the `eurocorp.local` forest. We either need bi-directional trust or one-way trust from `eurocorp.local` to `dollarcorp` to be able to use the below command.

Let's go for the last task and enumerate trusts for `eurocorp.local` forest.

`Get-ForestDomain -Forest eurocorp.local | %{Get-DomainTrust -Domain $_.Name}`:
```
SourceName      : eurocorp.local🏛️
TargetName      : eu.eurocorp.local🏛️
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST📌
TrustDirection  : Bidirectional🔗
WhenCreated     : 11/12/2022 5:49:08 AM
WhenChanged     : 2/11/2025 5:17:40 AM

SourceName      : eurocorp.local🏛️
TargetName      : dollarcorp.moneycorp.local🏛️
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FILTER_SIDS📌
TrustDirection  : Bidirectional🔗
WhenCreated     : 11/12/2022 8:15:23 AM
WhenChanged     : 2/11/2025 5:17:24 AM

Exception calling "FindAll" with "0" argument(s): "A referral was returned from the server.
"
At C:\AD\Tools\PowerView.ps1:23860 char:20
+             else { $Results = $Searcher.FindAll() }
+                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [], MethodInvocationException
    + FullyQualifiedErrorId : DirectoryServicesCOMException
```
❌

Notice the error above. It occurred because PowerView attempted to list trusts even for `eu.eurocorp.local`. **Because external trust is non-transitive it was not possible!**

**Using Active Directory module**

Let's import the ADModule.

**Note:** Remember to use it from a different PowerShell session started by using Invisi-Shell. **If you load PowerView and the ADModule in same PowerShell session, some functions may not work.**

![dcorp-std422 | student422](https://custom-icon-badges.demolab.com/badge/dcorp--std422-student422-64b5f6?logo=windows11&logoColor=white)

`cd \AD\Tools`

`C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat`:
```
[SNIP]
```

`Import-Module C:\AD\Tools\ADModule-master\Microsoft.ActiveDirectory.Management.dll`

`Import-Module C:\AD\Tools\ADModule-master\ActiveDirectory\ActiveDirectory.psd1`

1. **Enumerate all domains in the `moneycorp.local` forest**

Use the below command to enumerate all the domains in the current forest.

`(Get-ADForest).Domains`:
```
dollarcorp.moneycorp.local🏛️
moneycorp.local🏛️
us.dollarcorp.moneycorp.local🏛️
```
🚩

2. **Map the trusts of the `dollarcorp.moneycorp.local` domain**

To map all the trusts in the current domain, we can use the below command.

`Get-ADTrust -Filter *`:
```
Direction               : BiDirectional🔗
DisallowTransivity      : False
DistinguishedName       : CN=moneycorp.local,CN=System,DC=dollarcorp,DC=moneycorp,DC=local
ForestTransitive        : False
IntraForest             : True
IsTreeParent            : False
IsTreeRoot              : False
Name                    : moneycorp.local
ObjectClass             : trustedDomain
ObjectGUID              : 01c3b68d-520b-44d8-8e7f-4c10927c2b98
SelectiveAuthentication : False
SIDFilteringForestAware : False
SIDFilteringQuarantined : False
Source                  : DC=dollarcorp,DC=moneycorp,DC=local🏛️
Target                  : moneycorp.local🏛️
TGTDelegation           : False
TrustAttributes         : 32
TrustedPolicy           :
TrustingPolicy          :
TrustType               : Uplevel
UplevelOnly             : False
UsesAESKeys             : False
UsesRC4Encryption       : False

Direction               : BiDirectional🔗
DisallowTransivity      : False
DistinguishedName       : CN=us.dollarcorp.moneycorp.local,CN=System,DC=dollarcorp,DC=moneycorp,DC=local
ForestTransitive        : False
IntraForest             : True
IsTreeParent            : False
IsTreeRoot              : False
Name                    : us.dollarcorp.moneycorp.local
ObjectClass             : trustedDomain
ObjectGUID              : 3edb04a9-d634-4038-beed-3c057743853f
SelectiveAuthentication : False
SIDFilteringForestAware : False
SIDFilteringQuarantined : False
Source                  : DC=dollarcorp,DC=moneycorp,DC=local🏛️
Target                  : us.dollarcorp.moneycorp.local🏛️
TGTDelegation           : False
TrustAttributes         : 32
TrustedPolicy           :
TrustingPolicy          :
TrustType               : Uplevel
UplevelOnly             : False
UsesAESKeys             : False
UsesRC4Encryption       : False

Direction               : BiDirectional🔗
DisallowTransivity      : False
DistinguishedName       : CN=eurocorp.local,CN=System,DC=dollarcorp,DC=moneycorp,DC=local
ForestTransitive        : False
IntraForest             : False
IsTreeParent            : False
IsTreeRoot              : False
Name                    : eurocorp.local
ObjectClass             : trustedDomain
ObjectGUID              : d4d64a77-63be-4d77-93c2-6524e73d306d
SelectiveAuthentication : False
SIDFilteringForestAware : False
SIDFilteringQuarantined : True
Source                  : DC=dollarcorp,DC=moneycorp,DC=local🏛️
Target                  : eurocorp.local🏛️
TGTDelegation           : False
TrustAttributes         : 4
TrustedPolicy           :
TrustingPolicy          :
TrustType               : Uplevel
UplevelOnly             : False
UsesAESKeys             : False
UsesRC4Encryption       : False
```
🚩

3. **Map external trusts in `moneycorp.local` forest**

To list all the trusts in the `moneycorp.local` forest.

`Get-ADForest | %{Get-ADTrust -Filter *}`:
```
Direction               : BiDirectional🔗
DisallowTransivity      : False
DistinguishedName       : CN=moneycorp.local,CN=System,DC=dollarcorp,DC=moneycorp,DC=local
ForestTransitive        : False
IntraForest             : True
IsTreeParent            : False
IsTreeRoot              : False
Name                    : moneycorp.local
ObjectClass             : trustedDomain
ObjectGUID              : 01c3b68d-520b-44d8-8e7f-4c10927c2b98
SelectiveAuthentication : False
SIDFilteringForestAware : False
SIDFilteringQuarantined : False
Source                  : DC=dollarcorp,DC=moneycorp,DC=local🏛️
Target                  : moneycorp.local🏛️
TGTDelegation           : False
TrustAttributes         : 32
TrustedPolicy           :
TrustingPolicy          :
TrustType               : Uplevel
UplevelOnly             : False
UsesAESKeys             : False
UsesRC4Encryption       : False

Direction               : BiDirectional🔗
DisallowTransivity      : False
DistinguishedName       : CN=us.dollarcorp.moneycorp.local,CN=System,DC=dollarcorp,DC=moneycorp,DC=local
ForestTransitive        : False
IntraForest             : True
IsTreeParent            : False
IsTreeRoot              : False
Name                    : us.dollarcorp.moneycorp.local
ObjectClass             : trustedDomain
ObjectGUID              : 3edb04a9-d634-4038-beed-3c057743853f
SelectiveAuthentication : False
SIDFilteringForestAware : False
SIDFilteringQuarantined : False
Source                  : DC=dollarcorp,DC=moneycorp,DC=local🏛️
Target                  : us.dollarcorp.moneycorp.local🏛️
TGTDelegation           : False
TrustAttributes         : 32
TrustedPolicy           :
TrustingPolicy          :
TrustType               : Uplevel
UplevelOnly             : False
UsesAESKeys             : False
UsesRC4Encryption       : False

Direction               : BiDirectional🔗
DisallowTransivity      : False
DistinguishedName       : CN=eurocorp.local,CN=System,DC=dollarcorp,DC=moneycorp,DC=local
ForestTransitive        : False
IntraForest             : False
IsTreeParent            : False
IsTreeRoot              : False
Name                    : eurocorp.local
ObjectClass             : trustedDomain
ObjectGUID              : d4d64a77-63be-4d77-93c2-6524e73d306d
SelectiveAuthentication : False
SIDFilteringForestAware : False
SIDFilteringQuarantined : True
Source                  : DC=dollarcorp,DC=moneycorp,DC=local🏛️
Target                  : eurocorp.local🏛️
TGTDelegation           : False
TrustAttributes         : 4
TrustedPolicy           :
TrustingPolicy          :
TrustType               : Uplevel
UplevelOnly             : False
UsesAESKeys             : False
UsesRC4Encryption       : False
```
🚩

4. **Identify external trusts of `dollarcorp` domain. Can you enumerate trusts for a trusting forest?**

To list only the external trusts in `moneycorp.local` domain.

`(Get-ADForest).Domains | %{Get-ADTrust -Filter '(intraForest -ne $True) -and (ForestTransitive -ne $True)' -Server $_}`:
```
Direction               : BiDirectional
DisallowTransivity      : False
DistinguishedName       : CN=eurocorp.local,CN=System,DC=dollarcorp,DC=moneycorp,DC=local
ForestTransitive        : False📌
IntraForest             : False🔗
IsTreeParent            : False
IsTreeRoot              : False
Name                    : eurocorp.local
ObjectClass             : trustedDomain
ObjectGUID              : d4d64a77-63be-4d77-93c2-6524e73d306d
SelectiveAuthentication : False
SIDFilteringForestAware : False
SIDFilteringQuarantined : True
Source                  : DC=dollarcorp,DC=moneycorp,DC=local🏛️
Target                  : eurocorp.local🏛️
TGTDelegation           : False
TrustAttributes         : 4
TrustedPolicy           :
TrustingPolicy          :
TrustType               : Uplevel
UplevelOnly             : False
UsesAESKeys             : False
UsesRC4Encryption       : False
```

Finally, to identify external trusts of the `dollarcorp` domain, we can use the below command. The output is same as above because there is just one external trust in the entire forest.

`Get-ADTrust -Filter '(intraForest -ne $True) -and (ForestTransitive -ne $True)'`:
```
Direction               : BiDirectional
DisallowTransivity      : False
DistinguishedName       : CN=eurocorp.local,CN=System,DC=dollarcorp,DC=moneycorp,DC=local
ForestTransitive        : False📌
IntraForest             : False🔗
IsTreeParent            : False
IsTreeRoot              : False
Name                    : eurocorp.local
ObjectClass             : trustedDomain
ObjectGUID              : d4d64a77-63be-4d77-93c2-6524e73d306d
SelectiveAuthentication : False
SIDFilteringForestAware : False
SIDFilteringQuarantined : True
Source                  : DC=dollarcorp,DC=moneycorp,DC=local🏛️
Target                  : eurocorp.local🏛️
TGTDelegation           : False
TrustAttributes         : 4
TrustedPolicy           :
TrustingPolicy          :
TrustType               : Uplevel
UplevelOnly             : False
UsesAESKeys             : False
UsesRC4Encryption       : False
```

Because we have trust relationship with `eurocorp.local`, we can enumerate trusts for it.

`Get-ADTrust -Filter * -Server eurocorp.local`:
```
Direction               : BiDirectional
DisallowTransivity      : False
DistinguishedName       : CN=eu.eurocorp.local,CN=System,DC=eurocorp,DC=local
ForestTransitive        : False
IntraForest             : True🔗
IsTreeParent            : False
IsTreeRoot              : False
Name                    : eu.eurocorp.local
ObjectClass             : trustedDomain
ObjectGUID              : bfc7a899-cc5d-4303-8176-3b8381189fae
SelectiveAuthentication : False
SIDFilteringForestAware : False
SIDFilteringQuarantined : False
Source                  : DC=eurocorp,DC=local🏛️
Target                  : eu.eurocorp.local🏛️
TGTDelegation           : False
TrustAttributes         : 32
TrustedPolicy           :
TrustingPolicy          :
TrustType               : Uplevel
UplevelOnly             : False
UsesAESKeys             : False
UsesRC4Encryption       : False

[SNIP]
```
🚩

---
---
