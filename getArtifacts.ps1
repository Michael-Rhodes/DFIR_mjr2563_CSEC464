Param (
    [string[]]$RemoteHost,
    [string]$CSV = $null,
    [string]$email
)

# check if admin
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (! $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
  echo "This script requires Administrator privileges"
  exit
}

function printTableName ($tablename) {
    echo "`n`n###############################################################################"
    echo "### $tablename"
    echo "#######################"
}


# time: current, time zone, uptime
$time = @{}
$time.CurrentTime = Get-Date
$time.Timezone = (Get-TimeZone).Id
$time.Uptime = (((get-date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime).TotalHours)

# OS version: numerical, name
$os = @{}
$os.Version = (Get-WmiObject Win32_OperatingSystem).Version
$os.OSName = (Get-WmiObject -class Win32_OperatingSystem).Caption


# system hardware: CPU brand and type, RAM, HDD (list HDD and filesystems)
$hardware = @{}
$hardware.CPU = (Get-WmiObject win32_processor).Name #possibly use Description for version number
$hardware.RAM = (Get-WmiObject Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum #/1000000000
$hardware.HDD = gwmi win32_diskdrive | ft name, Size
$hardware.Volumes = Get-WmiObject Win32_Volume | Select-Object Name, Label, Capacity


##################
# domain controller info: IP of DC, hostname of DC, DNS servers for domain
##################

# hostname and domain
$name = @{}
$name.Hostname = (Get-WmiObject Win32_ComputerSystem).Name
$name.DomainName = (Get-WmiObject Win32_ComputerSystem).Domain

# list of users: local/domain/system, SID, creation date, last login
#              service users, user login history
$users = Get-LocalUser | Select-Object Name,LastLogon,SID
##TODO domain/system/service users


# start at boot: services, Programs (registry location, command, user runs as)
$StartAtBoot = @{}
$StartAtBoot.Services = (Get-WmiObject Win32_Service | Where-Object { $_.StartMode -eq "Auto"}).Name
$StartAtBoot.Programs = Get-CimInstance Win32_StartupCommand | Select-Object Name, command , User, Location



# list of scheduled tasks
$tasks = Get-ScheduledTask


# Network
$network = @{}
$network.ipconfig = (ipconfig /all)
$network.interfaces = Get-NetAdapter
$network.arpTable = Get-NetNeighbor
$network.routeTable = Get-NetRoute
$network.listeningTCP = Get-NetTCPConnection | Where-Object {($_.State -eq "Listen")}
$network.establishedTCP = Get-NetTCPConnection | Where-Object {($_.State -eq "Established")}
$network.listeningUDP = Get-NetUDPEndpoint
$network.DHCPServer = (Get-WmiObject Win32_NetworkAdapterConfiguration | ? {$_.DHCPEnabled -eq $true -and $_.DHCPServer -ne $null}).DHCPServer
$network.DNSServer = Get-DnsClientServerAddress
$network.DNScache = Get-DnsClientCache

# Network shares, printers, and wifi access profiles
$network.shares = Get-SmbShare
$network.printers = Get-Printer
$network.wifiProfiles = (netsh wlan show profiles)

# installed software
$software = Get-WmiObject -Class Win32_Product

# process list
$processes = Get-Service

# drivers:
$drivers = Get-WindowsDriver -Online -All | Select-Object Driver, BootCritical, OriginalFileName, Version, Date, ProviderName

# Downloads and Documents
$files = @{}
foreach($dir in Get-ChildItem -Path 'C:\Users'){
    if(Test-Path "C:\Users\$($dir.Name)\Documents"){
        $files.Documents += Get-ChildItem -Path "C:\Users\$($dir.Name)\Documents" -Recurse -File
    }
}
foreach($dir in Get-ChildItem -Path 'C:\Users'){
    if(Test-Path "C:\Users\$($dir.Name)\Downloads"){
        $files.Downloads += Get-ChildItem -Path "C:\Users\$($dir.Name)\Downloads" -Recurse -File
    }
}


# Prefetch files
$prefetch = Get-ChildItem -Path "C:\Windows\Prefetch" -Recurse -File

# Security log from past 12 hours
$securityLog = Get-EventLog -LogName Security -After (Get-Date).AddHours(-12) -ErrorAction SilentlyContinue

# hosts file
$hosts = Get-Content $env:SystemRoot\System32\Drivers\etc\hosts


###############################################################################
# Output tables

printTableName "System Time"
$time | Format-Table -AutoSize

printTableName "OS Version"
$os | Format-Table -AutoSize

printTableName "Hardware"
echo "`n### CPU ##"
$hardware.CPU | Format-Table -AutoSize
echo "`n### RAM ##"
$hardware.RAM | Format-Table -AutoSize
echo "`n### HDD ##"
$hardware.HDD | Format-Table -AutoSize
echo "`n### Volumes ##"
$hardware.Volumes | Format-Table -AutoSize

printTableName "Host and domain name"
$name | Format-Table -AutoSize

printTableName "Users"
$users | Format-Table -AutoSize

printTableName "Network" 
echo "`n### ipconfig ##"
$network.ipconfig | Format-Table -AutoSize
echo "`n### Interfaces ##"
$network.interfaces | Format-Table -AutoSize
echo "`n### ARP Table ##"
$network.arpTable | Format-Table -AutoSize
echo "`n### Routing Table ##"
$network.routeTable | Format-Table -AutoSize
echo "`n### Listening TCP ##"
$network.listeningTCP | Format-Table -AutoSize
echo "`n### Established TCP ##"
$network.establishedTCP | Format-Table -AutoSize
echo "`n### Listening UDP ##"
$network.listeningUDP | Format-Table -AutoSize
echo "`n### DHCP Server ##"
$network.DHCPServer | Format-Table -AutoSize
echo "`n### DNS Server ##"
$network.DNSServer | Format-Table -AutoSize
echo "`n### DNS cache ##"
$network.DNScache | Format-Table -AutoSize
echo "`n### Shares ##"
$network.shares | Format-Table -AutoSize
echo "`n### Printers ##"
$network.printers | Format-Table -AutoSize
echo "`n### WiFi Profiles ##"
$network.wifiProfiles | Format-Table -AutoSize

printTableName "Installed Software"
$software | Format-Table -AutoSize

printTableName "Running Processes"
$processes | Format-Table -AutoSize

printTableName "Drivers"
$drivers | Format-Table -AutoSize

printTableName "User Files"
echo "`n### Documents ##"
$files.Documents | Format-Table -AutoSize
echo "`n### Downloads ##"
$files.Downloads | Format-Table -AutoSize

printTableName "Prefetch files"
$prefetch | Format-Table -AutoSize

printTableName "Security Log: Past 12 hours"
$securityLog | Format-Table -AutoSize

printTableName "Hosts File"
$hosts | Format-Table -AutoSize

if($CSV -ne $null){
    $time | Export-Csv -NoTypeInformation -Path ./tmp.csv
    Get-Content ./tmp.csv >> $CSV
    Remove-Item ./tmp.csv

    $os | Export-Csv -NoTypeInformation -Path ./tmp.csv
    Get-Content ./tmp.csv >> $CSV
    Remove-Item ./tmp.csv

    $hardware.CPU | Export-Csv -NoTypeInformation -Path ./tmp.csv
    Get-Content ./tmp.csv >> $CSV
    Remove-Item ./tmp.csv
    $hardware.RAM| Export-Csv -NoTypeInformation -Path ./tmp.csv
    Get-Content ./tmp.csv >> $CSV
    Remove-Item ./tmp.csv
    $hardware.HDD| Export-Csv -NoTypeInformation -Path ./tmp.csv
    Get-Content ./tmp.csv >> $CSV
    Remove-Item ./tmp.csv
    $hardware.Volumes| Export-Csv -NoTypeInformation -Path ./tmp.csv
    Get-Content ./tmp.csv >> $CSV
    Remove-Item ./tmp.csv

    $name | Export-Csv -NoTypeInformation -Path ./tmp.csv
    Get-Content ./tmp.csv >> $CSV
    Remove-Item ./tmp.csv

    $users | Export-Csv -NoTypeInformation -Path ./tmp.csv
    Get-Content ./tmp.csv >> $CSV
    Remove-Item ./tmp.csv


    $network.interfaces | Export-Csv -NoTypeInformation -Path ./tmp.csv
    Get-Content ./tmp.csv >> $CSV
    Remove-Item ./tmp.csv
    $network.arpTable | Export-Csv -NoTypeInformation -Path ./tmp.csv
    Get-Content ./tmp.csv >> $CSV
    Remove-Item ./tmp.csv
    $network.routeTable | Export-Csv -NoTypeInformation -Path ./tmp.csv
    Get-Content ./tmp.csv >> $CSV
    Remove-Item ./tmp.csv
    $network.listeningTCP | Export-Csv -NoTypeInformation -Path ./tmp.csv
    Get-Content ./tmp.csv >> $CSV
    Remove-Item ./tmp.csv
    $network.establishedTCP | Export-Csv -NoTypeInformation -Path ./tmp.csv
    Get-Content ./tmp.csv >> $CSV
    Remove-Item ./tmp.csv
    $network.listeningUDP | Export-Csv -NoTypeInformation -Path ./tmp.csv
    Get-Content ./tmp.csv >> $CSV
    Remove-Item ./tmp.csv
    $network.DHCPServer | Export-Csv -NoTypeInformation -Path ./tmp.csv
    Get-Content ./tmp.csv >> $CSV
    Remove-Item ./tmp.csv
    $network.DNSServer | Export-Csv -NoTypeInformation -Path ./tmp.csv
    Get-Content ./tmp.csv >> $CSV
    Remove-Item ./tmp.csv
    $network.DNScache | Export-Csv -NoTypeInformation -Path ./tmp.csv
    Get-Content ./tmp.csv >> $CSV
    Remove-Item ./tmp.csv
    $network.shares | Export-Csv -NoTypeInformation -Path ./tmp.csv
    Get-Content ./tmp.csv >> $CSV
    Remove-Item ./tmp.csv
    $network.printers | Export-Csv -NoTypeInformation -Path ./tmp.csv
    Get-Content ./tmp.csv >> $CSV
    Remove-Item ./tmp.csv
    
    $software | Export-Csv -NoTypeInformation -Path ./tmp.csv
    Get-Content ./tmp.csv >> $CSV
    Remove-Item ./tmp.csv

    $processes | Export-Csv -NoTypeInformation -Path ./tmp.csv
    Get-Content ./tmp.csv >> $CSV
    Remove-Item ./tmp.csv
    
    $drivers | Export-Csv -NoTypeInformation -Path ./tmp.csv
    Get-Content ./tmp.csv >> $CSV
    Remove-Item ./tmp.csv
    
    $files.Documents | Export-Csv -NoTypeInformation -Path ./tmp.csv
    Get-Content ./tmp.csv >> $CSV
    Remove-Item ./tmp.csv
    $files.Downloads | Export-Csv -NoTypeInformation -Path ./tmp.csv
    Get-Content ./tmp.csv >> $CSV
    Remove-Item ./tmp.csv
    
    $prefetch | Export-Csv -NoTypeInformation -Path ./tmp.csv
    Get-Content ./tmp.csv >> $CSV
    Remove-Item ./tmp.csv
    
    $securityLog | Export-Csv -NoTypeInformation -Path ./tmp.csv
    Get-Content ./tmp.csv >> $CSV
    Remove-Item ./tmp.csv

    $hosts | Export-Csv -NoTypeInformation -Path ./tmp.csv
    Get-Content ./tmp.csv >> $CSV
    Remove-Item ./tmp.csv
}

<#

##### IGNORE ######

$NICs = Get-WMIObject Win32_NetworkAdapterConfiguration -computername . | where{$_.IPEnabled -eq $
true -and $_.DHCPEnabled -eq $true}
>> Foreach($NIC in $NICs) {
>>     $ip = $NIC.IPAddress
>>     $gateway = $NIC.DefaultIPGateway
>>     $subnet = $NIC.IPSubnet[0]
>>     echo $ip $gateway $subnet
>>     echo $NIC
>> }
#>
#>
