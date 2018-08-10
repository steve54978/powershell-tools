Import-Module MrANagios

$nagiosAdmin = Get-Credential
Invoke-NagiosRequest -computername txaupwvxar573 -action 29 -NagiosCoreUrl http://nagios.uprd.usoncology.unx/nagiosxi/login.php -Credential $nagiosAdmin


Get-NagiosXiHostStatus -HostName txaupwvxar551
Invoke-NagiosRequest.ps1 -computername txaupwvxar573 -action 29 -NagiosCoreUrl http://nagios.uprd.usoncology.unx/nagiosxi/login.php -username nagiosadmin
