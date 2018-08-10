[CmdletBinding()] 
Param( 
 [Parameter(Mandatory=$False)] 
 [ValidateNotNull()] 
 [String]$ComputerName, 
  
 [Parameter(Mandatory=$False)] 
 [ValidateNotNull()] 
 [String]$OU, 
  
 [Parameter(Mandatory=$False)] 
 [ValidateNotNull()] 
 [String]$File 
 ) 
$ErrorLog = @() 
$Report = @() 
$ErrorsCount = @().Count 
$SuccessCount = @().Count 
if ($ComputerName) {$Computers = Get-ADComputer $ComputerName | where {$_.enabled} | select –expand Name} 
if ($OU) {Write-Host "Getting list of computers in $OU Organizational Unit"; $Computers = Get-ADComputer -filter * -SearchBase $OU | where {$_.enabled} | select –expand Name} 
elseif (!$ComputerName -and !$OU) {Write-Host "Getting all computers in AD domain"; $Computers = Get-ADComputer -filter * | where {$_.enabled} | select –expand Name} 
 
foreach ($Computer in $Computers) { 
    $getNet = Get-WmiObject Win32_NetworkAdapterConfiguration -comp $Computer -ErrorAction SilentlyContinue -ErrorVariable ERR | where {$_.IPAddress} | select DNSHostName,Description,@{Name=’IPAddress‘;Expression={[string]::join(“;”, ($_.IPAddress))}},@{Name=’IpSubnet‘;Expression={[string]::join(“;”, ($_.IpSubnet))}},MACAddress,@{Name=’DefaultIPGateway‘;Expression={[string]::join(“;”, ($_.DefaultIPGateway))}},@{Name=’DNSServerSearchOrder‘;Expression={[string]::join(“;”, ($_.DNSServerSearchOrder))}} 
        if ($ERR) {Write-Host "Connecting to $Computer - Fail"; $ErrorLog += "Can't connect to $Computer"; $ErrorsCount += +1} 
        else {Write-Host "Connecting to $Computer - Success"; $Report += $getNet; $SuccessCount += +1} 
     
} 
$Report | ft -Wrap 
$ErrorLog 
Write-Host "### Script Summary ### 
# Errors: $ErrorsCount 
# Success: $SuccessCount 
" 
if ($File) {$Report | Export-Csv $File}