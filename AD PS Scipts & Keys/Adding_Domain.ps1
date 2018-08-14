# Create secure credentials.
$User = "USON\svc_SvrAdd"
$PasswordFile = "/pstore.txt"
$KeyFile = "pstore.key"
$key = Get-Content $KeyFile
$cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $User, (Get-Content $PasswordFile | ConvertTo-SecureString -Key $key)

#Domain Join
$domain = "uson.usoncology.int"
Add-Computer -DomainName $domain -Credential $cred -OUPath "OU=Quarantined-New,OU=Servers,DC=uson,DC=usoncology,DC=int"
#Restart-Computer
