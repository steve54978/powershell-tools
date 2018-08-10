#requires -version 4.0
<#
.Synopsis
   This script allows the user execute cgi commands to a Nagios site by using
   the Invoke-WebRequest cmdlet.
.DESCRIPTION
   The purpose of the script is to automate the process of disabling/enabling 
   nagios notifications and/or checks for Nagios hosts and their services.
   
   The script utilizes Invoke-WebRequest to post to the nagios cmd.cgi. 

   Paramaters: 
        $computername - what nagios refers to as host for which you wish to
        enable/disable checks and notifications. Hosts are case-sensitive.

        $action - integer of nagios cmd.cgi for the action you wish to take

            Disable checks of all services on this host
            $action=16

            Enable checks of all services on this host
            $action=15

            Disable notifications for all services on this host
            $action=29

            Enable notifications for all services on this host
            $action=28

            Acknowledge service problem
            $action=34

            Force service check
            $action=7

        $url - the base url of your nagios installation (i.e. http://nagios.domain.com/nagios)

        $username - the htaccess username

        $password - the htaccess password

    
    Author: Jason Wasser
    Modified: 5/19/2015
    Version: 1.8
    Currently the script only supports enabling/disabling of active checks and
    notifications.
    
    Changelog:
    version 1.8
        * Added Disable-NagiosServiceNotifications and Enable-NagiosServiceNotifications
        * Added Disable-NagiosGlobalNotifications and Enable-NagiosGlobalNotifications
    version 1.7
        * Added logic for hostgroups and service groups
    version 1.6
        * Converted to Functions and script module
    version 1.52
        * Added host problem acknowledgement.
    version 1.51
        * Added logic for user not entering a password.
    version 1.5
        * Added service problem acknowledgement.
        * Added force service check.
        * Added disabling/enabling service checks for host groups
        * Added disabling/enabling service checks for service groups.
    version 1.0
        * Initial re-write of Set-NagiosCLI.ps1 now using Invoke-WebRequest.

     
    Future developments could include scheduled downtimes.
    
    Known Issues:
        * To run the script as a scheduled task as a service account will require running 
        Internet Explorer once as the user.
    
.EXAMPLE
   .\Invoke-NagiosRequest.ps1 -computername server1 -action 29 -url http://nagios.domain.com/nagios -username nagiosadmin
   This will disable notifications for all services on host server1 including the host.
.EXAMPLE
   .\Invoke-NagiosRequest.ps1 -computername server1 -action 28 -url http://nagios.domain.com/nagios -username nagiosadmin
   This will enable notifications for all services on host server1 including the host.
.EXAMPLE
   .\Invoke-NagiosRequest.ps1 -computername server1 -action 16 -url http://nagios.domain.com/nagios -username nagiosadmin
   This will disable checks for all services on host server1 including the host.
.EXAMPLE
   .\Invoke-NagiosRequest.ps1 -computername server1 -action 15 -url http://nagios.domain.com/nagios -username nagiosadmin
   This will enable checks for all services on host server1 including the host.
.EXAMPLE
   .\Invoke-NagiosRequest.ps1 -computername (get-content c:\temp\computerlist.txt) -action 29 -url http://nagios.domain.com/nagios -username nagiosadmin
   This will disable notifications for a list of computers found in the c:\temp\computerlist.txt file.

#>
Function Invoke-NagiosRequest {
    [CmdletBinding()]
    Param
    (
        # Nagios Host
        [Parameter(Mandatory=$false,
                    ValueFromPipeline=$true,
                    ValueFromPipelineByPropertyName=$true,
                    Position=0,
                    HelpMessage = "What nagios refers to host(s) for which you wish to enable/disable checks and notifications. 
                    Nagios is case-sensitive for hosts (i.e. server01 != SERVER01).")]
        [alias('host')]
        [string[]]$ComputerName,

        # Nagios cmd.cgi action by number
        [Parameter(Mandatory=$true,Position=1,
            HelpMessage = "Integer of nagios cmd.cgi for the action you wish to take

                Disable checks of all services on this host
                action=16

                Enable checks of all services on this host
                action=15

                Disable notifications for a service on this host
                action=23

                Enable notifications for a service on this host
                action=22

                Disable notifications for all services on this host
                action=29

                Enable notifications for all services on this host
                action=28
            
                Acknowledge host alert
                action=33
            
                Acknowledge service alert
                action=34
            
                Force service check
                action=7

                Disable checks of all services on host group
                action=68

                Enable checks of all services on host group
                action=67

                Disable checks of all services in a service group
                action=114

                Enable checks of all services in a service group
                action=113
                ")]
        [ValidateSet(7,11,12,15,16,22,23,28,29,33,34,67,68,113,114)]
        [int]$action,

        [Parameter(Mandatory=$false)]
        [string]$service,

        [Parameter(Mandatory=$false)]
        [string]$servicegroup,

        [Parameter(Mandatory=$false)]
        [string]$comment,

        [Parameter(Mandatory=$false)]
        [string]$hostgroup,

        # Nagios base url
        [Parameter(Mandatory=$false,Position=2,HelpMessage="The base url of your nagios installation (i.e. http://nagios.domain.com/nagios)")]
        [string]$url="https://nagios.domain.com/nagios",

        # Nagios username
        [Parameter(Mandatory=$false,Position=3)]
        [string]$username,

        # Nagios password
        [Parameter(Mandatory=$false,Position=4)]
        [string]$password

    )

    Begin
    {
        # Function for making the actual CGI POST command.
        Function Submit-NagiosRequest {
            Param (
                # Do I need this? Clean this up later.
                )
            Write-Output "###########################################################################"
            Write-Output "Submitting cgi command to Nagios for $computer"
            $WebRequest = Invoke-WebRequest -Uri $uri -Credential $Credential -Body $formFields -Method POST -ContentType 'application/x-www-form-urlencoded'
        
            # If there was a problem with the hostname or other problem the errorMessage DIV field will be displayed. If not display the infoMessage of success.
            $Message = $WebRequest.ParsedHtml.getElementsByTagName("div") | Where-Object "classname" -Match "errorMessage|infoMessage" | select -ExpandProperty innerText
            if ($Message) {
                $Message 
                }     
            Write-Output "###########################################################################"
            }
        
        # Building URI for Nagios CGI
        $cgiurl="/cgi-bin/cmd.cgi"
        $uri = $url + $cgiurl
        
        # Credential verification
        if (!$Credential) {
            $Credential = Get-UserLogin -username $username -Password $password
            }
    }

    Process
    {
        # Here we need to separate out the Nagios commands that potential 
        # loop through a list of nagios hosts for the enabling/disabling
        # of checks and notifications from the other commands such as host 
        # groups, service groups, acknowledgements, and future development.

        switch -Regex ($action) {
             # List of action integers that are not computer/host based
            "67|68" {
                foreach ($hg in $hostgroup) {
                    switch ($action) {
                        # Enable checks of all services on host group
                        67 {
                            if (!$hg) {
                                $hg = Read-Host "Please enter the hostgroup (case-sensitive)"
                                }
                            $formFields = @{cmd_typ=$action;hostgroup=$hg;ahas=$true;cmd_mod=2}
                            }
                        # Disable checks of all services on host group
                        68 {
                            if (!$hg) {
                                $hg = Read-Host "Please enter the hostgroup (case-sensitive)"
                                }
                            $formFields = @{cmd_typ=$action;hostgroup=$hg;ahas=$true;cmd_mod=2}
                            }
                        }
                        Submit-NagiosRequest
                    }
                }
            "113|114" {
                foreach ($sg in $servicegroup) {
                    switch ($action) {
                        # Enable checks of all services in a service group
                        113 {
                            if (!$sg) {
                                $sg = Read-Host "Please enter the service group (case-sensitive)"
                                }
                            $formFields = @{cmd_typ=$action;servicegroup=$sg;ahas=$false;cmd_mod=2}
                            }
                        # Disable checks of all services in a service group
                        114 {
                            if (!$sg) {
                                $sg = Read-Host "Please enter the service group (case-sensitive)"
                                }
                            $formFields = @{cmd_typ=$action;servicegroup=$sg;ahas=$false;cmd_mod=2}
                            }
                        }
                        Submit-NagiosRequest
                    }
                }
            "11|12" {
                    Write-Verbose "Enabling/Disabling Global Nagios Notifications"
                    $formFields = @{cmd_typ=$action;cmd_mod=2}
                    Submit-NagiosRequest
                }
            default {
                # For all other host/computer commands.
                if (!$ComputerName) {
                    $ComputerName = Read-Host "Please enter a Nagios host name (case-sensitive)"
                    }
                foreach ($computer in $ComputerName) {
                    $computer = $computer.ToUpper()
                    switch -Regex ($action) {
                        # Acknowledge Host Problesm
                        33 {
                            if (!$comment){
                                $comment = Read-Host "Please enter a comment for acknowledgement"
                                }
                            $formFields = @{cmd_typ=$action;host=$computer;service=$service;cmd_mod=2;com_data=$comment;sticky_ack=$true;send_notification=$true}
                            }
                        # Acknowledge Service Problem
                        34 {
                            if (!$service) {
                                $service = Read-Host "Please enter the service name (case-sensitive)"
                                }
                            if (!$comment){
                                $comment = Read-Host "Please enter a comment for acknowledgement"
                                }
                            $formFields = @{cmd_typ=$action;host=$computer;service=$service;cmd_mod=2;com_data=$comment;sticky_ack=$true;send_notification=$true}
                            }
                        # Force service check
                        7 {
                            if (!$service) {
                                $service = Read-Host "Please enter the service name (case-sensitive)"
                                }
                            $formFields = @{cmd_typ=$action;host=$computer;service=$service;cmd_mod=2;start_time=(Get-Date -Format "MM-dd-yyyy HH:mm:ss");force_check=$true}
                            }
                        "22|23" {
                            if (!$service) {
                                $service = Read-Host "Please enter the service name (case-sensitive)"
                                }
                            $formFields = @{cmd_typ=$action;host=$computer;service=$service;cmd_mod=2}
                            }
                
                        # All other commands for enabling/disabling checks or notifications for hosts
                        default {
                            $formFields = @{cmd_typ=$action;host=$computer;ahas=$true;cmd_mod=2}
                            }
                        }
                    Submit-NagiosRequest
                    }
                }
            }
        }
    End
    {
    }
}
# End of Invoke-NagiosRequest Function
########################################################################################################


<#
.Synopsis
   Disables Nagios Host checks for a specified host.
.DESCRIPTION
   This function is a shortcut to Invoke-Nagios to automatically choose
   to disable nagios checks for a specified host.
.EXAMPLE
   Disable-NagiosHostChecks -ComputerName SERVER01
.EXAMPLE
   Disable-NagiosHostChecks -ComputerName SERVER01 -username jdoe
.EXAMPLE
   Disable-NagiosHostChecks -ComputerName SERVER01 -username svcnagiosadmin -password Password!
.EXAMPLE
   Disable-NagiosHostChecks -ComputerName SERVER01 -username svcnagiosadmin -password Password! -url https://nagiosdev.domain.com/nagios
#>
Function Disable-NagiosHostChecks {
    Param (
        # Nagios Host
        [Parameter(Mandatory=$true,
                    ValueFromPipeline=$true,
                    ValueFromPipelineByPropertyName=$true,
                    Position=0,
                    HelpMessage = "What nagios refers to host(s) for which you wish to enable/disable checks and notifications. Nagios is case-sensitive for hosts (i.e. server01 != SERVER01).")]
        [alias('host')]
        [string[]]$ComputerName=$env:COMPUTERNAME,
        
        # Nagios base url
        [Parameter(Mandatory=$false,Position=2,HelpMessage="The base url of your nagios installation (i.e. http://nagios.domain.com/nagios)")]
        [string]$url="https://nagios.domain.com/nagios",

        # Nagios username
        [Parameter(Mandatory=$false,Position=3)]
        [string]$username,

        # Nagios password
        [Parameter(Mandatory=$false,Position=4)]
        [string]$password
    )
    begin {
        $Credential = Get-UserLogin -username $username -Password $password
        }
    process {
        foreach ($Computer in $ComputerName) {
            Write-Verbose "Disabling Nagios Host Checks for $Computer"
            Invoke-NagiosRequest -ComputerName $Computer -action 16 -username $username -password $password -url $url
            }
        }
    end {}
    }

<#
.Synopsis
   Disables Nagios Host notifications for a specified host.
.DESCRIPTION
   This function is a shortcut to Invoke-Nagios to automatically choose
   to disable nagios notifications for a specified host.
.EXAMPLE
   Disable-NagiosHostNotifications -ComputerName SERVER01
.EXAMPLE
   Disable-NagiosHostNotifications -ComputerName SERVER01 -username jdoe
.EXAMPLE
   Disable-NagiosHostNotifications -ComputerName SERVER01 -username svcnagiosadmin -password Password!
.EXAMPLE
   Disable-NagiosHostNotifications -ComputerName SERVER01 -username svcnagiosadmin -password Password! -url https://nagiosdev.domain.com/nagios
#>
Function Disable-NagiosHostNotifications {
    Param (
        # Nagios Host
        [Parameter(Mandatory=$true,
                    ValueFromPipeline=$true,
                    ValueFromPipelineByPropertyName=$true,
                    Position=0,
                    HelpMessage = "What nagios refers to host(s) for which you wish to enable/disable checks and notifications. Nagios is case-sensitive for hosts (i.e. server01 != SERVER01).")]
        [alias('host')]
        [string[]]$ComputerName=$env:COMPUTERNAME,
        
        # Nagios base url
        [Parameter(Mandatory=$false,Position=2,HelpMessage="The base url of your nagios installation (i.e. http://nagios.domain.com/nagios)")]
        [string]$url="https://nagios.domain.com/nagios",

        # Nagios username
        [Parameter(Mandatory=$false,Position=3)]
        [string]$username,

        # Nagios password
        [Parameter(Mandatory=$false,Position=4)]
        [string]$password

    )
    begin {
        $Credential = Get-UserLogin -username $username -Password $password
        }
    process {    
        foreach ($Computer in $ComputerName) {
            Write-Verbose "Disabling Nagios Host Notifications for $Computer"
            Invoke-NagiosRequest -ComputerName $Computer -action 29 -username $username -password $password -url $url
            }
        }
    end {}
    }

<#
.Synopsis
   Enables Nagios Host checks for a specified host.
.DESCRIPTION
   This function is a shortcut to Invoke-Nagios to automatically choose
   to enable nagios checks for a specified host.
.EXAMPLE
   Enable-NagiosHostChecks -ComputerName SERVER01
.EXAMPLE
   Enable-NagiosHostChecks -ComputerName SERVER01 -username jdoe
.EXAMPLE
   Enable-NagiosHostChecks -ComputerName SERVER01 -username svcnagiosadmin -password Password!
.EXAMPLE
   Enable-NagiosHostChecks -ComputerName SERVER01 -username svcnagiosadmin -password Password! -url https://nagiosdev.domain.com/nagios
#>
Function Enable-NagiosHostChecks {
    Param (
        # Nagios Host
        [Parameter(Mandatory=$true,
                    ValueFromPipeline=$true,
                    ValueFromPipelineByPropertyName=$true,
                    Position=0,
                    HelpMessage = "What nagios refers to host(s) for which you wish to enable/disable checks and notifications. Nagios is case-sensitive for hosts (i.e. server01 != SERVER01).")]
        [alias('host')]
        [string[]]$ComputerName=$env:COMPUTERNAME,
        
        # Nagios base url
        [Parameter(Mandatory=$false,Position=2,HelpMessage="The base url of your nagios installation (i.e. http://nagios.domain.com/nagios)")]
        [string]$url="https://nagios.domain.com/nagios",

        # Nagios username
        [Parameter(Mandatory=$false,Position=3)]
        [string]$username,

        # Nagios password
        [Parameter(Mandatory=$false,Position=4)]
        [string]$password
    )
    begin {
        $Credential = Get-UserLogin -username $username -Password $password
        }
    process {
        foreach ($Computer in $ComputerName) {
            Write-Verbose "Enabling Nagios Host Checks for $Computer"
            Invoke-NagiosRequest -ComputerName $Computer -action 15 -username $username -password $password -url $url
            }
        }
    end {}
    }

<#
.Synopsis
   Enables Nagios Host notifications for a specified host.
.DESCRIPTION
   This function is a shortcut to Invoke-Nagios to automatically choose
   to enable nagios notifications for a specified host.
.EXAMPLE
   Enable-NagiosHostNotifications -ComputerName SERVER01
.EXAMPLE
   Enable-NagiosHostNotifications -ComputerName SERVER01 -username jdoe
.EXAMPLE
   Enable-NagiosHostNotifications -ComputerName SERVER01 -username svcnagiosadmin -password Password!
.EXAMPLE
   Enable-NagiosHostNotifications -ComputerName SERVER01 -username svcnagiosadmin -password Password! -url https://nagiosdev.domain.com/nagios
#>
Function Enable-NagiosHostNotifications {
    Param (
        # Nagios Host
        [Parameter(Mandatory=$true,
                    ValueFromPipeline=$true,
                    ValueFromPipelineByPropertyName=$true,
                    Position=0,
                    HelpMessage = "What nagios refers to host(s) for which you wish to enable/disable checks and notifications. Nagios is case-sensitive for hosts (i.e. server01 != SERVER01).")]
        [alias('host')]
        [string[]]$ComputerName=$env:COMPUTERNAME,
        
        # Nagios base url
        [Parameter(Mandatory=$false,Position=2,HelpMessage="The base url of your nagios installation (i.e. http://nagios.domain.com/nagios)")]
        [string]$url="https://nagios.domain.com/nagios",

        # Nagios username
        [Parameter(Mandatory=$false,Position=3)]
        [string]$username,

        # Nagios password
        [Parameter(Mandatory=$false,Position=4)]
        [string]$password
    )
    begin {
        $Credential = Get-UserLogin -username $username -Password $password
        }
    process {
        foreach ($Computer in $ComputerName) {
            Write-Verbose "Enabling Nagios Host Notifications for $Computer"
            Invoke-NagiosRequest -ComputerName $Computer -action 28 -username $username -password $password -url $url
            }
        }
    end {}
    }

<#
.Synopsis
   Acknowledge Nagios Host problem for a specified host.
.DESCRIPTION
   This function is a shortcut to Invoke-Nagios to automatically choose
   to acknowledge nagios host problem for a specified host.
.EXAMPLE
   Submit-NagiosHostAcknowledgement -ComputerName SERVER01
.EXAMPLE
   Submit-NagiosHostAcknowledgement -ComputerName SERVER01 -username jdoe
.EXAMPLE
   Submit-NagiosHostAcknowledgement -ComputerName SERVER01 -username svcnagiosadmin -password Password!
.EXAMPLE
   Submit-NagiosHostAcknowledgement -ComputerName SERVER01 -username svcnagiosadmin -password Password! -url https://nagiosdev.domain.com/nagios
#>
Function Submit-NagiosHostAcknowledgement {
    Param (
        # Nagios Host
        [Parameter(Mandatory=$true,
                    ValueFromPipeline=$true,
                    ValueFromPipelineByPropertyName=$true,
                    Position=0,
                    HelpMessage = "What nagios refers to host(s) for which you wish to enable/disable checks and notifications. Nagios is case-sensitive for hosts (i.e. server01 != SERVER01).")]
        [alias('host')]
        [string[]]$ComputerName=$env:COMPUTERNAME,
        
        # Nagios base url
        [Parameter(Mandatory=$false,Position=2,HelpMessage="The base url of your nagios installation (i.e. http://nagios.domain.com/nagios)")]
        [string]$url="https://nagios.domain.com/nagios",

        # Nagios username
        [Parameter(Mandatory=$false,Position=3)]
        [string]$username,

        # Nagios password
        [Parameter(Mandatory=$false,Position=4)]
        [string]$password,

        [Parameter(Mandatory=$false)]
        [string]$comment
    )
    begin {
        $Credential = Get-UserLogin -username $username -Password $password
        }
    process {
        foreach ($Computer in $ComputerName) {
            Write-Verbose "Enabling Nagios Host Notifications for $Computer"
            Invoke-NagiosRequest -ComputerName $Computer -action 33 -username $username -password $password -url $url -comment $comment
            }
        }
    end {}
    }

<#
.Synopsis
   Acknowledge Nagios service problem for a specified host.
.DESCRIPTION
   This function is a shortcut to Invoke-Nagios to automatically choose
   to acknowledge nagios service problem for a specified host.
.EXAMPLE
   Submit-NagiosServiceAcknowledgement -ComputerName SERVER01 -service Uptime
.EXAMPLE
   Submit-NagiosServiceAcknowledgement -ComputerName SERVER01 -service Uptime -username jdoe
.EXAMPLE
   Submit-NagiosServiceAcknowledgement -ComputerName SERVER01 -service Uptime -username svcnagiosadmin -password Password!
.EXAMPLE
   Submit-NagiosServiceAcknowledgement -ComputerName SERVER01 -service Uptime -username svcnagiosadmin -password Password! -url https://nagiosdev.domain.com/nagios
#>
Function Submit-NagiosServiceAcknowledgement {
    Param (
        # Nagios Host
        [Parameter(Mandatory=$true,
                    ValueFromPipeline=$true,
                    ValueFromPipelineByPropertyName=$true,
                    Position=0,
                    HelpMessage = "What nagios refers to host(s) for which you wish to enable/disable checks and notifications. Nagios is case-sensitive for hosts (i.e. server01 != SERVER01).")]
        [alias('host')]
        [string[]]$ComputerName=$env:COMPUTERNAME,

        [Parameter(Mandatory=$false,Position=1)]
        [string]$service,

        [Parameter(Mandatory=$false,Position=2)]
        [string]$comment,
        
        # Nagios base url
        [Parameter(Mandatory=$false,Position=3,HelpMessage="The base url of your nagios installation (i.e. http://nagios.domain.com/nagios)")]
        [string]$url="https://nagios.domain.com/nagios",

        # Nagios username
        [Parameter(Mandatory=$false,Position=4)]
        [string]$username,

        # Nagios password
        [Parameter(Mandatory=$false,Position=5)]
        [string]$password

    )
    begin {
        $Credential = Get-UserLogin -username $username -Password $password
        }
    process {
        foreach ($Computer in $ComputerName) {
            Write-Verbose "Enabling Nagios Host Notifications for $Computer"
            Invoke-NagiosRequest -ComputerName $Computer -action 34 -service $service -username $username -password $password -url $url -comment $comment
            }
        }
    end {}
    }

<#
.Synopsis
   Disables Nagios Host checks for a specified hostgroup.
.DESCRIPTION
   This function is a shortcut to Invoke-Nagios to automatically choose
   to disable nagios checks for a specified hostgroup.
.EXAMPLE
   Disable-NagiosHostGroupChecks -HostGroup HostgroupName
.EXAMPLE
   Disable-NagiosHostGrouptChecks -HostGroup HostgroupName -username jdoe
.EXAMPLE
   Disable-NagiosHostGroupChecks -HostGroup HostgroupName -username svcnagiosadmin -password Password!
.EXAMPLE
   Disable-NagiosHostGroupChecks -HostGroup HostgroupName -username svcnagiosadmin -password Password! -url https://nagiosdev.domain.com/nagios
#>
Function Disable-NagiosHostGroupChecks {
    Param (
        # Nagios Host
        [Parameter(Mandatory=$true,
                    ValueFromPipeline=$true,
                    ValueFromPipelineByPropertyName=$true,
                    Position=0,
                    HelpMessage = "What nagios refers to host(s) for which you wish to enable/disable checks and notifications. Nagios is case-sensitive for hosts (i.e. server01 != SERVER01).")]
        [alias('host')]
        [string[]]$HostGroup,
        
        # Nagios base url
        [Parameter(Mandatory=$false,Position=2,HelpMessage="The base url of your nagios installation (i.e. http://nagios.domain.com/nagios)")]
        [string]$url="https://nagios.domain.com/nagios",

        # Nagios username
        [Parameter(Mandatory=$false,Position=3)]
        [string]$username,

        # Nagios password
        [Parameter(Mandatory=$false,Position=4)]
        [string]$password
    )
    begin {
        $Credential = Get-UserLogin -username $username -Password $password
        }
    process {
        foreach ($hg in $HostGroup) {
            Write-Verbose "Disabling Nagios Hostgroup Checks for $hg"
            Invoke-NagiosRequest -hostgroup $hg -action 68 -username $username -password $password -url $url
            }
        }
    end {}
    }

<#
.Synopsis
   Enables Nagios Host checks for a specified hostgroup.
.DESCRIPTION
   This function is a shortcut to Invoke-Nagios to automatically choose
   to enable nagios checks for a specified hostgroup.
.EXAMPLE
   Enable-NagiosHostGroupChecks -HostGroup HostgroupName
.EXAMPLE
   Enable-NagiosHostGrouptChecks -HostGroup HostgroupName -username jdoe
.EXAMPLE
   Enable-NagiosHostGroupChecks -HostGroup HostgroupName -username svcnagiosadmin -password Password!
.EXAMPLE
   Enable-NagiosHostGroupChecks -HostGroup HostgroupName -username svcnagiosadmin -password Password! -url https://nagiosdev.domain.com/nagios
#>
Function Enable-NagiosHostGroupChecks {
    Param (
        # Nagios Host
        [Parameter(Mandatory=$true,
                    ValueFromPipeline=$true,
                    ValueFromPipelineByPropertyName=$true,
                    Position=0,
                    HelpMessage = "What nagios refers to host(s) for which you wish to enable/disable checks and notifications. Nagios is case-sensitive for hosts (i.e. server01 != SERVER01).")]
        [alias('host')]
        [string[]]$HostGroup,
        
        # Nagios base url
        [Parameter(Mandatory=$false,Position=2,HelpMessage="The base url of your nagios installation (i.e. http://nagios.domain.com/nagios)")]
        [string]$url="https://nagios.domain.com/nagios",

        # Nagios username
        [Parameter(Mandatory=$false,Position=3)]
        [string]$username,

        # Nagios password
        [Parameter(Mandatory=$false,Position=4)]
        [string]$password
    )
    begin {
        $Credential = Get-UserLogin -username $username -Password $password
        }
    process {
        foreach ($hg in $HostGroup) {
            Write-Verbose "Enabling Nagios Hostgroup Checks for $hg"
            Invoke-NagiosRequest -hostgroup $hg -action 67 -username $username -password $password -url $url
            }
        }
    end {}
    }

<#
.Synopsis
   Disables Nagios services checks for a specified servicegroup.
.DESCRIPTION
   This function is a shortcut to Invoke-Nagios to automatically choose
   to disable nagios checks for a specified servicegroup.
.EXAMPLE
   Disable-NagiosServiceGroupChecks -ServiceGroup ServiceGroupName
.EXAMPLE
   Disable-NagiosServiceGroupChecks -ServiceGroup ServiceGroupName -username jdoe
.EXAMPLE
   Disable-NagiosServiceGroupChecks -ServiceGroup ServiceGroupName -username svcnagiosadmin -password Password!
.EXAMPLE
   Disable-NagiosServiceGroupChecks -ServiceGroup ServiceGroupName -username svcnagiosadmin -password Password! -url https://nagiosdev.domain.com/nagios
#>
Function Disable-NagiosServiceGroupChecks {
    Param (
        # Nagios Host
        [Parameter(Mandatory=$true,
                    ValueFromPipeline=$true,
                    ValueFromPipelineByPropertyName=$true,
                    Position=0,
                    HelpMessage = "What nagios refers to host(s) for which you wish to enable/disable checks and notifications. Nagios is case-sensitive for hosts (i.e. server01 != SERVER01).")]
        [alias('host')]
        [string[]]$ServiceGroup,
        
        # Nagios base url
        [Parameter(Mandatory=$false,Position=2,HelpMessage="The base url of your nagios installation (i.e. http://nagios.domain.com/nagios)")]
        [string]$url="https://nagios.domain.com/nagios",

        # Nagios username
        [Parameter(Mandatory=$false,Position=3)]
        [string]$username,

        # Nagios password
        [Parameter(Mandatory=$false,Position=4)]
        [string]$password
    )
    begin {
        $Credential = Get-UserLogin -username $username -Password $password
        }
    process {
        foreach ($sg in $ServiceGroup) {
            Write-Verbose "Disabling Nagios Hostgroup Checks for $hg"
            Invoke-NagiosRequest -ServiceGroup $sg -action 114 -username $username -password $password -url $url
            }
        }
    end {}
    }

<#
.Synopsis
   Enables Nagios services checks for a specified servicegroup.
.DESCRIPTION
   This function is a shortcut to Invoke-Nagios to automatically choose
   to enable nagios checks for a specified servicegroup.
.EXAMPLE
   Enable-NagiosServiceGroupChecks -ServiceGroup ServiceGroupName
.EXAMPLE
   Enable-NagiosServiceGroupChecks -ServiceGroup ServiceGroupName -username jdoe
.EXAMPLE
   Enable-NagiosServiceGroupChecks -ServiceGroup ServiceGroupName -username svcnagiosadmin -password Password!
.EXAMPLE
   Enable-NagiosServiceGroupChecks -ServiceGroup ServiceGroupName -username svcnagiosadmin -password Password! -url https://nagiosdev.domain.com/nagios
#>
Function Enable-NagiosServiceGroupChecks {
    Param (
        # Nagios Host
        [Parameter(Mandatory=$true,
                    ValueFromPipeline=$true,
                    ValueFromPipelineByPropertyName=$true,
                    Position=0,
                    HelpMessage = "What nagios refers to host(s) for which you wish to enable/disable checks and notifications. Nagios is case-sensitive for hosts (i.e. server01 != SERVER01).")]
        [alias('host')]
        [string[]]$ServiceGroup,
        
        # Nagios base url
        [Parameter(Mandatory=$false,Position=2,HelpMessage="The base url of your nagios installation (i.e. http://nagios.domain.com/nagios)")]
        [string]$url="https://nagios.domain.com/nagios",

        # Nagios username
        [Parameter(Mandatory=$false,Position=3)]
        [string]$username,

        # Nagios password
        [Parameter(Mandatory=$false,Position=4)]
        [string]$password
    )
    begin {
        $Credential = Get-UserLogin -username $username -Password $password
        }
    process {
        foreach ($sg in $ServiceGroup) {
            Write-Verbose "Disabling Nagios Hostgroup Checks for $hg"
            Invoke-NagiosRequest -ServiceGroup $sg -action 113 -username $username -password $password -url $url
            }
        }
    end {}
    }


# If a username and password is provided as parameters we need to 
# encrypt the credentials into a Credential object for use with Invoke-WebRequest.
Function Encrypt-Password {
    param (
        # Nagios username
        [Parameter(Mandatory=$false,Position=0)]
        [string]$username,
        [Parameter(ValueFromPipeline=$true,Mandatory=$false,Position=1)]
        [String]$Password
        )

    begin {}
    process {
        $securepassword = ConvertTo-SecureString -String $password -AsPlainText -Force
        $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username,$securepassword
        $Credential
        }
    end {}
    }

Function Get-UserLogin {
    param (
        # Nagios username
        [Parameter(Mandatory=$false,Position=0)]
        [string]$username,
        # Nagios password
        [Parameter(Mandatory=$false,Position=1)]
        [String]$Password
        )

    begin {}
    process {    
        # Verifying if a username and/or password was entered.
        # If no username was entered, we can assume no password was entered.
        
        if (!$username) {
            $Credential = Get-Credential -ErrorAction Stop
            if (!$Credential) {
                Write-Error "No password was entered. Exiting."
                break
                }
            else {
                return $Credential
                }
            }
        else {
            # If a username was supplied but no password, prompt for it.
            if (!$password) {
                $Credential = Get-Credential -Credential $username -ErrorAction Stop
                if (!$Credential) {
                    Write-Error "No password was entered. Exiting."
                    break
                    }
                else {
                    return $Credential
                    }
                }
            else {
                $Credential = Encrypt-Password -username $username -Password $password
                return $Credential
                }
            }
        
        # End of username/password section
        }
    end {}
    }

<#
.Synopsis
   Disables Nagios service notifications for a specified host.
.DESCRIPTION
   This function is a shortcut to Invoke-Nagios to automatically choose
   to disable nagios notifications for a specified service on a host.
.EXAMPLE
   Disable-NagiosServiceNotifications -ComputerName SERVER01 -Service sqlserver
.EXAMPLE
   Disable-NagiosServiceNotifications -ComputerName SERVER01 -Service sqlserver -username jdoe
.EXAMPLE
   Disable-NagiosServiceNotifications -ComputerName SERVER01 -Service sqlserver -username svcnagiosadmin -password Password!
.EXAMPLE
   Disable-NagiosServiceNotifications -ComputerName SERVER01 -Service sqlserver -username svcnagiosadmin -password Password! -url https://nagiosdev.domain.com/nagios
#>
Function Disable-NagiosServiceNotifications {
    Param (
        # Nagios Host
        [Parameter(Mandatory=$true,
                    ValueFromPipeline=$true,
                    ValueFromPipelineByPropertyName=$true,
                    Position=0,
                    HelpMessage = "What nagios refers to host(s) for which you wish to enable/disable checks and notifications. Nagios is case-sensitive for hosts (i.e. server01 != SERVER01).")]
        [alias('host')]
        [string[]]$ComputerName=$env:COMPUTERNAME,

        # Service name (Case-Sensitive)
        [Parameter(Mandatory=$false,Position=1,HelpMessage="Service name (case-sensitive)")]
        [string]$Service,
        
        # Nagios base url
        [Parameter(Mandatory=$false,Position=2,HelpMessage="The base url of your nagios installation (i.e. http://nagios.domain.com/nagios)")]
        [string]$url="https://nagios.domain.com/nagios",

        # Nagios username
        [Parameter(Mandatory=$false,Position=3)]
        [string]$username,

        # Nagios password
        [Parameter(Mandatory=$false,Position=4)]
        [string]$password

    )
    begin {
        $Credential = Get-UserLogin -username $username -Password $password
        }
    process {    
        foreach ($Computer in $ComputerName) {
            Write-Verbose "Disabling Nagios service Notifications for $Service on $Computer"
            Invoke-NagiosRequest -ComputerName $Computer -Service $Service -action 23 -username $username -password $password -url $url
            }
        }
    end {}
    }

<#
.Synopsis
   Enables Nagios service notifications for a specified host.
.DESCRIPTION
   This function is a shortcut to Invoke-Nagios to automatically choose
   to enable nagios notifications for a specified service on a host.
.EXAMPLE
   Enable-NagiosServiceNotifications -ComputerName SERVER01 -Service sqlserver
.EXAMPLE
   Enable-NagiosServiceNotifications -ComputerName SERVER01 -Service sqlserver -username jdoe
.EXAMPLE
   Enable-NagiosServiceNotifications -ComputerName SERVER01 -Service sqlserver -username svcnagiosadmin -password Password!
.EXAMPLE
   Enable-NagiosServiceNotifications -ComputerName SERVER01 -Service sqlserver -username svcnagiosadmin -password Password! -url https://nagiosdev.domain.com/nagios
#>
Function Enable-NagiosServiceNotifications {
    Param (
        # Nagios Host
        [Parameter(Mandatory=$true,
                    ValueFromPipeline=$true,
                    ValueFromPipelineByPropertyName=$true,
                    Position=0,
                    HelpMessage = "What nagios refers to host(s) for which you wish to enable/disable checks and notifications. Nagios is case-sensitive for hosts (i.e. server01 != SERVER01).")]
        [alias('host')]
        [string[]]$ComputerName=$env:COMPUTERNAME,
        
        # Service name (Case-Sensitive)
        [Parameter(Mandatory=$false,Position=1,HelpMessage="Service name (case-sensitive)")]
        [string]$Service,

        # Nagios base url
        [Parameter(Mandatory=$false,Position=2,HelpMessage="The base url of your nagios installation (i.e. http://nagios.domain.com/nagios)")]
        [string]$url="https://nagios.domain.com/nagios",

        # Nagios username
        [Parameter(Mandatory=$false,Position=3)]
        [string]$username,

        # Nagios password
        [Parameter(Mandatory=$false,Position=4)]
        [string]$password

    )
    begin {
        $Credential = Get-UserLogin -username $username -Password $password
        }
    process {    
        foreach ($Computer in $ComputerName) {
            Write-Verbose "Disabling Nagios service Notifications for $Service on $Computer"
            Invoke-NagiosRequest -ComputerName $Computer -Service $Service -action 22 -username $username -password $password -url $url
            }
        }
    end {}
    }

<#
.Synopsis
   Disables Nagios global notifications.
.DESCRIPTION
   This function is a shortcut to Invoke-Nagios to automatically choose
   to disable nagios global notifications.
.EXAMPLE
   Disable-NagiosGlobalNotifications 
.EXAMPLE
   Disable-NagiosGlobalNotifications -username jdoe
.EXAMPLE
   Disable-NagiosGlobalNotifications -username svcnagiosadmin -password Password!
.EXAMPLE
   Disable-NagiosGlobalNotifications -username svcnagiosadmin -password Password! -url https://nagiosdev.domain.com/nagios
#>
Function Disable-NagiosGlobalNotifications {
    Param (
        # Nagios base url
        [Parameter(Mandatory=$false,Position=2,HelpMessage="The base url of your nagios installation (i.e. http://nagios.domain.com/nagios)")]
        [string]$url="https://nagios.domain.com/nagios",

        # Nagios username
        [Parameter(Mandatory=$false,Position=3)]
        [string]$username,

        # Nagios password
        [Parameter(Mandatory=$false,Position=4)]
        [string]$password

    )
    begin {
        $Credential = Get-UserLogin -username $username -Password $password
        }
    process {    
            Write-Verbose "Disabling Nagios global notifications"
            Invoke-NagiosRequest -action 11 -username $username -password $password -url $url
        }
    end {}
    }

<#
.Synopsis
   Enables Nagios global notifications.
.DESCRIPTION
   This function is a shortcut to Invoke-Nagios to automatically choose
   to enable nagios global notifications.
.EXAMPLE
   Enable-NagiosGlobalNotifications 
.EXAMPLE
   Enable-NagiosGlobalNotifications -username jdoe
.EXAMPLE
   Enable-NagiosGlobalNotifications -username svcnagiosadmin -password Password!
.EXAMPLE
   Enable-NagiosGlobalNotifications -username svcnagiosadmin -password Password! -url https://nagiosdev.domain.com/nagios
#>
Function Enable-NagiosGlobalNotifications {
    Param (
        # Nagios base url
        [Parameter(Mandatory=$false,Position=2,HelpMessage="The base url of your nagios installation (i.e. http://nagios.domain.com/nagios)")]
        [string]$url="https://nagios.domain.com/nagios",

        # Nagios username
        [Parameter(Mandatory=$false,Position=3)]
        [string]$username,

        # Nagios password
        [Parameter(Mandatory=$false,Position=4)]
        [string]$password

    )
    begin {
        $Credential = Get-UserLogin -username $username -Password $password
        }
    process {    
            Write-Verbose "Disabling Nagios global notifications"
            Invoke-NagiosRequest -action 12 -username $username -password $password -url $url
        }
    end {}
    }