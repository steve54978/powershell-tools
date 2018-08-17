<#----------------------------INTRO-----------------------------#
Author: Steve Hudgson

Reason: Useful code snippets for Server Administration :)

#----------------------------TIPS------------------------------#

 1. Put your functions into .\SteveModules\SteveModules.psm1

#------------------------List of Functions-----------------#>

function Get-PSVersion-Steve {
    $PSVersionTable.PSVersion
}

#------------------------ScratchWork-----------------------------#

Get-Verb | Sort-Object -Property verb | Out-GridView

$env:PSModulePath -split ';'

Get-ChildItem -Path Function:\Get-*

Get-ChildItem -Path Function:\Get-PSVersion-Steve | Remove-Item

#------------------------Nagios Work-----------------------------#
Import-Module MrANagios

$nagiosAdmin = Get-Credential
Invoke-NagiosRequest -computername txaupwvxar573 -action 29 -NagiosCoreUrl http://nagios.uprd.usoncology.unx/nagiosxi/login.php -Credential $nagiosAdmin


Get-NagiosXiHostStatus -HostName txaupwvxar551
Invoke-NagiosRequest.ps1 -computername txaupwvxar573 -action 29 -NagiosCoreUrl http://nagios.uprd.usoncology.unx/nagiosxi/login.php -username nagiosadmin


#---------------------AD work Code From Dan Daley-------------------#

# import AD module
Import-Module ActiveDirectory

# Create secure credentials.
$User = "USON\svc_SvrAdd"
$PasswordFile = "/pstore.txt"
$KeyFile = "pstore.key"
$key = Get-Content $KeyFile
$cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $User, (Get-Content $PasswordFile | ConvertTo-SecureString -Key $key)

# Domain Join
$domain = "uson.usoncology.int"
Add-Computer -DomainName $domain -Credential $cred -OUPath "OU=Quarantined-New,OU=Servers,DC=uson,DC=usoncology,DC=int"
#Restart-Computer

# Edits
$servername = "usawtwvpv001";
$Destination_OU = "Steve Test";

$target = Get-ADOrganizationalUnit -LDAPFilter "(name=Steve Test)";
get-adcomputer -Server $servername | Move-ADObject -TargetPath $target.DistinguishedName

#-------------------------Editing ISO Automation---------------------------#


