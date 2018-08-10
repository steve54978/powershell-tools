<#----------------------------INTRO-----------------------------#
Author: Steve Hudgson

Reason: Useful code snippets for Server Administration :)

#-----------------------------TIPS------------------------------#

 1. Put your functions into .\SteveModules\SteveModules.psm1

#-----------------------------List of Functions-----------------#>

function Get-PSVersion-Steve {
    $PSVersionTable.PSVersion
}

#------------------------ScratchWork-----------------------------#
# This is were the magic happens ;)

Get-Verb | Sort-Object -Property verb | Out-GridView

$env:PSModulePath -split ';'

Get-ChildItem -Path Function:\Get-*

Get-ChildItem -Path Function:\Get-PSVersion-Steve | Remove-Item

# Nagios Work
Import-Module MrANagios

$nagiosAdmin = Get-Credential
Invoke-NagiosRequest -computername txaupwvxar573 -action 29 -NagiosCoreUrl http://nagios.uprd.usoncology.unx/nagiosxi/login.php -Credential $nagiosAdmin


Get-NagiosXiHostStatus -HostName txaupwvxar551
Invoke-NagiosRequest.ps1 -computername txaupwvxar573 -action 29 -NagiosCoreUrl http://nagios.uprd.usoncology.unx/nagiosxi/login.php -username nagiosadmin
