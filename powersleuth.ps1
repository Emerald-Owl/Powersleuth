param(
    [Alias("h")][switch] $help,
    [string] $startDate = "01/01/1980",
    [string] $endDate = ((Get-Date).AddDays(1)).ToString("MM/dd/yyyy"),
    [int] $maxEvents = 999999,
    [switch] $sysmon,
    [switch] $extended,
    [string] $csv,
    [Alias("q")][switch] $quiet
)

# Check for MM/dd/yyyy formatting of the start date param
try {
    $startDateFormatted = [datetime]::ParseExact($startDate, "MM/dd/yyyy", $null)
    $endDateFormatted = [datetime]::ParseExact($endDate, "MM/dd/yyyy", $null)
} 
catch {
    Write-Host "Invalid date format. Please use MM/dd/yyyy." -ForegroundColor Red
    return
}

function Get-Help {
    Write-Output "NEEDS UPDATING
        Usage: 
            .\powersleuth.ps1 -d <num> [options]
    
        Options:
            -h, -help                  Prints help information
            -s, -search <string>       Conduct a search for a string. Not case sensitive. String or regex 
            -d, -days <num>            Specify how many days back to search
            -c, -csv <directory>       Export results as a csv file 
            -o, -offline <directory>   Parse offline EVTX files, will use local logs otherwise
            -p, -poll                  Look at account logins statistics
            -l, -logins                Shows only login/logoff events (security and terminalservices)
            -x, -xsearch <string>      Search for keyword across ALL event logs. Requires CSV. String or regex
            -i, -ids <numbers>         Search by ID. Accepts a single ID or Regex, can be used with -s 
            -q, -quiet                 Does not print results to terminal. Requires CSV output. 
    
        Examples:
            .\powersleuth.ps1 -d 30 -p
            .\powersleuth.ps1 -d 5 -l
            .\powersleuth.ps1 -d 10 -s 'Administrator'
            .\powersleuth.ps1 -d 10 -o 'E:\C\Windows\system32\winevt\Logs' -c '..\output\'
            .\powersleuth.ps1 -d 60 -x 'psexe|anonymous' -o 'D:\C\Windows\System32\winevt\logs' -csv '..\Desktop\'
        "
}

function Get-OutputPreCheck($CSV){
    # Appends training backslash if it wasnt provided 
    if ($CSV -notmatch "\\$"){
        $CSV_fixed = "$CSV\"
    }else{
        $CSV_fixed = "$CSV"}
    
    # Check if the path exists, quits if not 
    if ((Test-Path -Path $CSV_fixed) -eq $false){
        write-host "The provided file path is not valid. Exiting."
        Exit}
    
    # Checks if the path is a directory. If its a file, it quits 
    if ((Get-Item $CSV_fixed) -isnot [System.IO.DirectoryInfo]){
        write-host "The -csv parameter must be a directory. Exiting."
        Exit}
    
    # Grabs a current timestamp to use as the filename. Then creates the file. 
    $OutputFileName = Get-Date -Format "MM-dd-yy@HH-mm-ss"

    #$OutputFile = "$CSV_fixed$OutputFileName.csv"
    try{
        New-Item -Path $CSV_fixed -Name "$OutputFileName.csv" -type "file"}
    catch [Exception]{
        write-host "Something went wrong creating the file! Exiting."
        Exit }
}

function Get-UserSessions{
    # Collect params, start/end date, and how many events to grab. 
    # Defaults to 99999 events and anything from 01/01/1980 to the day after execution 
    param(
        [Parameter(Mandatory=$true)]    
        [datetime]
        $startDate,

        [Parameter(Mandatory=$true)]
        [datetime]
        $endDate,

        [Parameter(Mandatory=$true)]
        [int]
        $maxEvents
    )
    
    # Common accounts to ignore
    $ignoreAccounts = @('SYSTEM', 'DWM-1', 'DWM-2', 'DWM-3', 'UMFD-0', 'UMFD-1', 'UMFD-2', 'UMFD-3', 'ANONYMOUS LOGON', 'LOCAL SERVICE', 'NETWORK SERVICE')
    $results = New-Object System.Collections.Generic.List[PSCustomObject]

    $startDateUniversal = $startDate.ToUniversalTime().ToString('o')
    $endDateUniversal = $endDate.ToUniversalTime().ToString('o')

    $LoginpropertyMap = @{
        AccountName = 5
        AccountDomain = 6
        LogonID = 7
        LogonType = 8
        ProcessName = 17
        WorkstationName = 11
        SourceAddress = 18
        SourcePort = 19
        ElevatedTokenRaw = -1  # Last property
    }
    
    $xpath =    
@"
*[System
    [TimeCreated
        [@SystemTime>='$startDateUniversal' and 
        @SystemTime<='$endDateUniversal']]
    [EventID=4624]]
"@

    try{
        $logonEvents = Get-WinEvent -LogName Security -FilterXPath $xpath -MaxEvents $maxEvents -ErrorAction SilentlyContinue
    } catch {
        if ($_.Exception.Message -eq "Attempted to perform an unauthorized operation.") {
            Write-Warning "Access Denied: Please run the script as an Administrator for Security Event Logs (ID 4624/4634)."
        }
        else{
            Write-Warning "An error occurred: $($_.Exception.Message)"
        }
        return
    }
    
    foreach($event in $logonEvents) {
        $accountName = $event.Properties[$LoginpropertyMap.AccountName].Value
        $accountDomain = $event.Properties[$LoginpropertyMap.AccountDomain].Value
        $logonID = '0x{0:X}' -f [int64]$event.Properties[$LoginpropertyMap.LogonID].Value
        $logonType = $event.Properties[$LoginpropertyMap.LogonType].Value
        $processName = $event.Properties[$LoginpropertyMap.ProcessName].Value
        $workstationName = $event.Properties[$LoginpropertyMap.WorkstationName].Value
        $sourceAddress = $event.Properties[$LoginpropertyMap.SourceAddress].Value
        $sourcePort = $event.Properties[$LoginpropertyMap.SourcePort].Value
        $elevatedTokenRaw = $event.Properties[$LoginpropertyMap.ElevatedTokenRaw].Value

        # Skip this iteration if the account name is in the ignore list
        if ($ignoreAccounts -contains $accountName) {
            continue
        }

        $elevatedToken = switch ($elevatedTokenRaw) {
            "%%1843" { "No" }
            "%%1842" { "Yes" } 
            default { $elevatedTokenRaw } 
        }

        $result = [PSCustomObject]@{
            "Time Created (UTC)"     = $event.TimeCreated.ToUniversalTime()
            'User'               = $event.UserId
            'LogName'            = $event.LogName
            'Event ID'           = $event.Id
            'Message'            = "$accountName logged in from $sourceAddress"
            'Details'            = 
@"
Account Name: $accountName
Domain: $accountDomain
Logon ID: $logonID
Logon Type: $logonType
Process Name: $processName
Workstation Name: $workstationName
Source Network Address: $sourceAddress
Source Port: $sourcePort
Elevated Token: $elevatedToken
"@
        } 
        $results.add($result)
    }

# ----------------------------------------------------------------------------

    $LogoffpropertyMap = @{
        AccountName = 1
        AccountDomain = 2
        LogonID = 3
        LogonType = 4
    }

$xpath =    
@"
*[System
[TimeCreated
    [@SystemTime>='$startDateUniversal' and 
    @SystemTime<='$endDateUniversal']]
[EventID=4634]]
"@

    try{
    $logoffEvents = Get-WinEvent -LogName Security -FilterXPath $xpath -MaxEvents $maxEvents -ErrorAction SilentlyContinue
    } catch {
        if ($_.Exception.Message -eq "Attempted to perform an unauthorized operation.") {
            Write-Warning "Access Denied: Please run the script as an Administrator for Security Event Logs (ID 4624/4634)."
        }
        else{
            Write-Warning "An error occurred: $($_.Exception.Message)"
        }
        return
    }


    foreach($event in $logoffEvents) {
        $accountName = $event.Properties[$LogoffpropertyMap.AccountName].Value
        $accountDomain = $event.Properties[$LogoffpropertyMap.AccountDomain].Value
        $logonID = '0x{0:X}' -f [int64]$event.Properties[$LogoffpropertyMap.LogonID].Value
        $logonType = $event.Properties[$LogoffpropertyMap.LogonType].Value

        # Skip this iteration if the account name is in the ignore list
        if ($ignoreAccounts -contains $accountName) {
            continue
        }

        $result = [PSCustomObject]@{
            'Time Created (UTC)' = $event.TimeCreated.ToUniversalTime()
            'User'               = $event.UserId
            'LogName'            = $event.LogName
            'Event ID'           = $event.Id
            'Message'            = "$accountName logged off"
            'Details'            = 
@"
Account Name: $accountName
Domain: $accountDomain
Logon ID: $logonID
Logon Type: $logonType

"@
        }
        $results.add($result)
    }
    return $results
}

function Get-OutboundRDPAttempt{
    # Collect params, start/end date, and how many events to grab. 
    # Defaults to 99999 events and anything from 01/01/1980 to the day after execution 
    param(
        [Parameter(Mandatory=$true)]    
        [datetime]
        $startDate,

        [Parameter(Mandatory=$true)]
        [datetime]
        $endDate,

        [Parameter(Mandatory=$true)]
        [int]
        $maxEvents
    )
    
    $startDateUniversal = $startDate.ToUniversalTime().ToString('o')
    $endDateUniversal = $endDate.ToUniversalTime().ToString('o')
    $results = New-Object System.Collections.Generic.List[PSCustomObject]

    $outboundRDPpropertyMap = @{
        remoteSystemName = 1
    }

    $xpath =    
@"
*[System
    [TimeCreated
        [@SystemTime>='$startDateUniversal' and 
        @SystemTime<='$endDateUniversal']]
    [EventID=1024]]
"@

    $events = Get-WinEvent -LogName 'Microsoft-Windows-TerminalServices-RDPClient/Operational' -FilterXPath $xpath -MaxEvents $maxEvents -ErrorAction SilentlyContinue

    foreach ($event in $events) {
        $systemName = $event.Properties[$outboundRDPpropertyMap.remoteSystemName].Value
        $result = [PSCustomObject]@{
            'Time Created (UTC)' = $event.TimeCreated.ToUniversalTime()
            'User'               = $event.UserId
            'LogName'            = $event.LogName
            'Event ID'           = $event.Id
            'Message'            = "Attempted RDP Connection to $systemName"
            'Details'            = $null
        }
        $results.Add($result)
    }
    return $results 
}

function Get-ServicesInstalled{
    param(
        [Parameter(Mandatory=$true)]    
        [datetime]
        $startDate,

        [Parameter(Mandatory=$true)]
        [datetime]
        $endDate,

        [Parameter(Mandatory=$true)]
        [int]
        $maxEvents
    )

    $startDateUniversal = $startDate.ToUniversalTime().ToString('o')
    $endDateUniversal = $endDate.ToUniversalTime().ToString('o')
    $results = New-Object System.Collections.Generic.List[PSCustomObject]

    $servicePropertyMap = @{
        serviceName = 0
        serviceFilePath = 1
        accountName = 4
    }

    $xpath =    
@"
*[System
    [TimeCreated
        [@SystemTime>='$startDateUniversal' and 
        @SystemTime<='$endDateUniversal']]
    [EventID=7045]]
"@

    $events = Get-WinEvent -LogName "System" -FilterXPath $xpath -MaxEvents $maxEvents -ErrorAction SilentlyContinue

    foreach($event in $events) {
        $serviceName = $event.Properties[$servicePropertyMap.serviceName].Value
        $serviceFilePath = $event.Properties[$servicePropertyMap.serviceFilePath].Value
        $accountName = $event.Properties[$servicePropertyMap.accountName].Value

        if ($serviceFilePath -like "*MpKslDrv.sys*"){
            continue
        }

        $userIdUpdated = switch ($event.UserId) {
            "S-1-5-18" { "System" }
            default { $event.UserId } 
        }

        $result = [PSCustomObject]@{
            'Time Created (UTC)' = $event.TimeCreated.ToUniversalTime()
            'User'               = $userIdUpdated
            'LogName'            = $event.LogName
            'Event ID'           = $event.Id
            'Message'            = "Service Installed: $serviceName"
            'Details'            =
@"
Service Name: $serviceName
Account Name: $accountName
Service File Path: $serviceFilePath
"@ 
        }
        $results.Add($result)
    }
    return $results
}

function Get-SystemStartup{
    # Collect params, start/end date, and how many events to grab. 
    # Defaults to 99999 events and anything from 01/01/1980 to the day after execution 
    param(
        [Parameter(Mandatory=$true)]    
        [datetime]
        $startDate,

        [Parameter(Mandatory=$true)]
        [datetime]
        $endDate,

        [Parameter(Mandatory=$true)]
        [int]
        $maxEvents
    )

    $startDateUniversal = $startDate.ToUniversalTime().ToString('o')
    $endDateUniversal = $endDate.ToUniversalTime().ToString('o')
    $results = New-Object System.Collections.Generic.List[PSCustomObject]

    $xpath =    
@"
*[System
    [TimeCreated
        [@SystemTime>='$startDateUniversal' and 
        @SystemTime<='$endDateUniversal']]
    [EventID=4608]]
"@

$events = Get-WinEvent -LogName "System" -FilterXPath $xpath -MaxEvents $maxEvents -ErrorAction SilentlyContinue

    foreach($event in $events) {
        $result = [PSCustomObject]@{
            'Time Created (UTC)' = $event.TimeCreated.ToUniversalTime()
            'User'               = $event.UserId
            'LogName'            = $event.LogName
            'Event ID'           = $event.Id
            'Message'            = "System Startup"
            'Details'             = $null
        }
        results.Add($result)
    }
return $results
}

function Get-SystemShutdown{
    # Collect params, start/end date, and how many events to grab. 
    # Defaults to 99999 events and anything from 01/01/1980 to the day after execution 
    param(
        [Parameter(Mandatory=$true)]    
        [datetime]
        $startDate,

        [Parameter(Mandatory=$true)]
        [datetime]
        $endDate,

        [Parameter(Mandatory=$true)]
        [int]
        $maxEvents
    )

    $startDateUniversal = $startDate.ToUniversalTime().ToString('o')
    $endDateUniversal = $endDate.ToUniversalTime().ToString('o')
    $results = New-Object System.Collections.Generic.List[PSCustomObject]

    $xpath =    
@"
*[System
    [TimeCreated
        [@SystemTime>='$startDateUniversal' and 
        @SystemTime<='$endDateUniversal']]
    [EventID=4609]]
"@

    $events = Get-WinEvent -LogName "System" -FilterXPath $xpath -MaxEvents $maxEvents -ErrorAction SilentlyContinue 

    foreach($event in $events) {
        $result = [PSCustomObject]@{
            'Time Created (UTC)' = $event.TimeCreated.ToUniversalTime()
            'User'               = $event.UserId
            'LogName'            = $event.LogName
            'Event ID'           = $event.Id
            'Message'            = "System Startup"
            'Details'             = $null
        }
        $results.Add($result)
    }
    $results
}

function Get-TermServSessions{
    # Collect params, start/end date, and how many events to grab. 
    # Defaults to 99999 events and anything from 01/01/1980 to the day after execution 
    param(
        [Parameter(Mandatory=$true)]    
        [datetime]
        $startDate,

        [Parameter(Mandatory=$true)]
        [datetime]
        $endDate,

        [Parameter(Mandatory=$true)]
        [int]
        $maxEvents
    )
    
    $startDateUniversal = $startDate.ToUniversalTime().ToString('o')
    $endDateUniversal = $endDate.ToUniversalTime().ToString('o')
    $results = New-Object System.Collections.Generic.List[PSCustomObject]

    $RDPLoginPropertyMap = @{
        User = 0
        sessionID = 1
        sourceNetworkAddress = 2
    }

    $xpath =    
@"
*[System
    [TimeCreated
        [@SystemTime>='$startDateUniversal' and 
        @SystemTime<='$endDateUniversal']]
    [EventID=21]]
"@

    $logonEvents = Get-WinEvent -LogName 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' -FilterXPath $xpath -MaxEvents $maxEvents -ErrorAction SilentlyContinue
    
    foreach($event in $logonEvents) {
        $user = $event.Properties[$RDPLoginPropertyMap.User].Value
        $sessionID = $event.Properties[$RDPLoginPropertyMap.sessionID].Value
        $sourceNetworkAddress = $event.Properties[$RDPLoginPropertyMap.sourceNetworkAddress].Value

        $result = [PSCustomObject]@{
            'Time Created (UTC)'    = $event.TimeCreated.ToUniversalTime()
            'User'                  = $user
            'LogName'               = $event.LogName
            'Event ID'              = $event.Id
            'Message'               = "Remote login by $user from $sourceNetworkAddress"
            'Details'               = 
@"
User: $user
Session ID: $sessionID
Source Network Address: $sourceNetworkAddress
"@ 
        }
        $results.Add($result)
    }


    $RDPLogoffPropertyMap = @{
        User = 0
        sessionID = 1
    }

    $xpath =    
@"
*[System
    [TimeCreated
        [@SystemTime>='$startDateUniversal' and 
        @SystemTime<='$endDateUniversal']]
    [EventID=23]]
"@

    $logoffEvents = Get-WinEvent -LogName 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' -FilterXPath $xpath -MaxEvents $maxEvents -ErrorAction SilentlyContinue

    foreach($event in $logoffEvents) {
        $user = $event.Properties[$RDPLogoffPropertyMap.User].Value
        $sessionID = $event.Properties[$RDPLogoffPropertyMap.sessionID].Value

        $result = [PSCustomObject]@{
            'Time Created (UTC)' = $event.TimeCreated.ToUniversalTime()
            'User'               = $user
            'LogName'            = $event.LogName
            'Event ID'           = $event.Id
            'Message'            = "$user's remote session logged off"
            'Details'            =
@"
User: $user
Session ID: $sessionID
"@ 
        }
        $results.Add($result)
    }
    return $results
}

function Get-FailedLogons{
    # Collect params, start/end date, and how many events to grab. 
    # Defaults to 99999 events and anything from 01/01/1980 to the day after execution 
    param(
        [Parameter(Mandatory=$true)]    
        [datetime]
        $startDate,

        [Parameter(Mandatory=$true)]
        [datetime]
        $endDate,

        [Parameter(Mandatory=$true)]
        [int]
        $maxEvents
    )

    $startDateUniversal = $startDate.ToUniversalTime().ToString('o')
    $endDateUniversal = $endDate.ToUniversalTime().ToString('o')
    $results = New-Object System.Collections.Generic.List[PSCustomObject]

    $failedLoginPropertyMap = @{
        TargetSid = 4
        AccountName = 5
        AccountDomain = 6
        Status = 7
        FailureReason = 8
        SubStatus = 9
        LogonType = 10
        LogonProcessName = 11
        WorkstationName = 13
        ProcessId = 17
        ProcessName = 18
        IpAddress = 19
        IpPort = 20
    }

    $xpath =    
@"
*[System
    [TimeCreated
        [@SystemTime>='$startDateUniversal' and 
        @SystemTime<='$endDateUniversal']]
    [EventID=4625]]
"@

    try{
        $events = Get-WinEvent -LogName "Security" -FilterXPath $xpath -MaxEvents $maxEvents -ErrorAction SilentlyContinue
    } catch {
        if ($_.Exception.Message -eq "Attempted to perform an unauthorized operation.") {
            Write-Warning "Access Denied: Please run the script as an Administrator for Security Event Logs (ID 4625)."
        }
        else{
            Write-Warning "An error occurred: $($_.Exception.Message)"
        }
        return
    }

    foreach($event in $events){
        $accountName = $event.Properties[$failedLoginPropertyMap.AccountName].Value
        $accountDomain = $event.Properties[$failedLoginPropertyMap.AccountDomain].Value
        $callerProcessName = $event.Properties[$failedLoginPropertyMap.ProcessName].Value
        $workstationName = $event.Properties[$failedLoginPropertyMap.WorkstationName].Value
        $sourceNetworkAddress = $event.Properties[$failedLoginPropertyMap.IpAddress].Value
        $sourcePort = $event.Properties[$failedLoginPropertyMap.IpPort].Value
        $logonType = $event.Properties[$failedLoginPropertyMap.LogonType].Value
        $FailureReasonRaw = $event.Properties[$failedLoginPropertyMap.FailureReason].Value
        $StatusRaw = $event.Properties[$failedLoginPropertyMap.Status].Value
        $SubStatusRaw = $event.Properties[$failedLoginPropertyMap.SubStatus].Value

        $StatusRawFixed = '0x{0:X}' -f $StatusRaw
        $SubStatusRawFixed = '0x{0:X}' -f $SubStatusRaw

        $FailureReason = switch ($FailureReasonRaw) {
            "%%2305" { 'The specified user account has expired.' }
            "%%2309" { "The specified account's password has expired." }
            "%%2310" { 'Account currently disabled.' }
            "%%2311" { 'Account logon time restriction violation.' }
            "%%2312" { 'User not allowed to logon at this computer.' }
            "%%2313" { 'Unknown user name or bad password.' }
            "%%2304" { 'An Error occurred during Logon.' }
            default { $FailureReasonRaw } 
        }
        $Status = switch ($StatusRawFixed) {
            "0xC0000234" { "Account locked out" }
            "0xC0000193" { "Account expired" }
            "0xC0000133" { "Clocks out of sync" }
            "0xC0000224" { "Password change required" }
            "0xc000015b" { "User does not have logon right" }
            "0xc000006d" { "Logon failure" }
            "0xc000006e" { "Account restriction" }
            "0xc00002ee" { "An error occurred during logon" }
            "0xC0000071" { "Password expired" }
            "0xC0000072" { "Account disabled" }
            "0xC0000413" { "Authentication firewall prohibits logon" }
            default { $StatusRawFixed }
        }
        $SubStatus = switch ($SubStatusRawFixed) {
            "0xC0000234" { "Account locked out" }
            "0xC0000193" { "Account expired" }
            "0xC0000133" { "Clocks out of sync" }
            "0xC0000224" { "Password change required" }
            "0xc000015b" { "User does not have logon right" }
            "0xc000006d" { "Logon failure" }
            "0xc000006e" { "Account restriction" }
            "0xc00002ee" { "An error occurred during logon" }
            "0xC0000071" { "Password expired" }
            "0xC0000072" { "Account disabled" }
            "0xC0000413" { "Authentication firewall prohibits logon" }
            default { $SubStatusRawFixed }
        }
        $result = [PSCustomObject]@{
            'Time Created (UTC)' = $event.TimeCreated.ToUniversalTime()
            'User'               = $null
            'LogName'            = $event.LogName
            'Event ID'           = $event.Id
            'Message'            = "Failed login for $accountName from $sourceNetworkAddress"
            'Details'             =
@"
Account Name: $accountName
Account Domain: $accountDomain
Logon Type: $logonType
Caller Process Name: $callerProcessName
Workstation Name: $workstationName
Source Network Address: $sourceNetworkAddress
Source Port: $sourcePort
FailureReason: $FailureReason
Status: $Status
SubStatus: $SubStatus
"@ 
        }
        $results.Add($result)
    }
    $results
}

function Get-PowerShellEvents{
    # Collect params, start/end date, and how many events to grab. 
    # Defaults to 99999 events and anything from 01/01/1980 to the day after execution 
    param(
        [Parameter(Mandatory=$true)]    
        [datetime]
        $startDate,

        [Parameter(Mandatory=$true)]
        [datetime]
        $endDate,

        [Parameter(Mandatory=$true)]
        [int]
        $maxEvents
    )

    $startDateUniversal = $startDate.ToUniversalTime().ToString('o')
    $endDateUniversal = $endDate.ToUniversalTime().ToString('o')
    $pattern = "(?s)(?<=HostApplication=)(.*?)(?=EngineVersion=)"
    $results = New-Object System.Collections.Generic.List[PSCustomObject]

    $powershellPropertyMap = @{
        Command = 2
    }

    $xpath =    
@"
*[System
    [TimeCreated
        [@SystemTime>='$startDateUniversal' and 
        @SystemTime<='$endDateUniversal']]
    [EventID=400]]
"@

    $events = Get-WinEvent -LogName 'Windows PowerShell' -FilterXPath $xpath -MaxEvents $maxEvents -ErrorAction SilentlyContinue

    foreach ($event in $events) {
        $dataField = $event.Properties[$powershellPropertyMap.Command].Value

        if ($dataField -match $pattern) {
            $command = $Matches[0]

            # Add the extracted details to the results array
            $result = [PSCustomObject]@{
                'Time Created (UTC)' = $event.TimeCreated.ToUniversalTime()
                'User'               = $event.UserId
                'LogName'            = $event.LogName
                'Event ID'           = $event.Id
                'Message'            = $command
                'Details'            = $null
            }
        }
        $results.Add($result)
    }
    return $results
}

function Get-GenericLogClearing{
    # Collect params, start/end date, and how many events to grab. 
    # Defaults to 99999 events and anything from 01/01/1980 to the day after execution 
    param(
        [Parameter(Mandatory=$true)]    
        [datetime]
        $startDate,

        [Parameter(Mandatory=$true)]
        [datetime]
        $endDate,

        [Parameter(Mandatory=$true)]
        [int]
        $maxEvents
    )

    $startDateUniversal = $startDate.ToUniversalTime().ToString('o')
    $endDateUniversal = $endDate.ToUniversalTime().ToString('o')
    $ProviderName = "Microsoft-Windows-Eventlog"
    $results = New-Object System.Collections.Generic.List[PSCustomObject]

    $104PropertyMap = @{
        userName = 0
        channel = 2
    }
    
    $xpath =    
@"
*[System
    [TimeCreated
        [@SystemTime>='$startDateUniversal' and 
        @SystemTime<='$endDateUniversal']]
    [Provider[@Name='$ProviderName']]
    [EventID=104]]
"@

    $events = Get-WinEvent -LogName "System" -FilterXPath $xpath -MaxEvents $maxEvents -ErrorAction SilentlyContinue

    # Loop through each event
    foreach ($event in $events) {
        $userName = $event.Properties[$104PropertyMap.userName].Value
        $channel = $event.Properties[$104PropertyMap.channel].Value

        # Add the extracted details to the results array
        $result = [PSCustomObject]@{
            'Time Created (UTC)' = $event.TimeCreated.ToUniversalTime()
            'User'               = $userName
            'LogName'            = $event.LogName
            'Event ID'           = $event.Id
            'Message'            = "The $channel log was cleared by $userName."
            'Details'            = $null
        }
        $results.Add($result)
    }
    return $results
}

function Get-SecurityLogClearing{
    # Collect params, start/end date, and how many events to grab. 
    # Defaults to 99999 events and anything from 01/01/1980 to the day after execution 
    param(
        [Parameter(Mandatory=$true)]    
        [datetime]
        $startDate,

        [Parameter(Mandatory=$true)]
        [datetime]
        $endDate,

        [Parameter(Mandatory=$true)]
        [int]
        $maxEvents
    )

    $startDateUniversal = $startDate.ToUniversalTime().ToString('o')
    $endDateUniversal = $endDate.ToUniversalTime().ToString('o')
    $results = New-Object System.Collections.Generic.List[PSCustomObject]

    $LoginpropertyMap = @{
        AccountName = 1
        logonID = 3
    }

    $xpath =    
@"
*[System
    [TimeCreated
        [@SystemTime>='$startDateUniversal' and 
        @SystemTime<='$endDateUniversal']]
    [EventID=1102]]
"@

    $events = Get-WinEvent -LogName "Security" -FilterXPath $xpath -MaxEvents $maxEvents -ErrorAction SilentlyContinue

    # Loop through each event
    foreach ($event in $events) {
        $accountName = $event.Properties[$LoginpropertyMap.AccountName].Value
        $logonID = $event.Properties[$LoginpropertyMap.LogonID].Valued 
        $logonIDFixed = '0x{0:X}' -f $logonID

        # Add the extracted details to the results array
        $result = [PSCustomObject]@{
            'Time Created (UTC)' = $event.TimeCreated.ToUniversalTime()
            'User'               = $event.UserId
            'LogName'            = $event.LogName
            'Event ID'           = $event.Id
            'Message'            = "Security Event Log cleared by $accountName"
            'Details'            = 
@"
Account Name: $accountName
LogonID: $logonIDFixed
"@ 
        }
        $results.Add($result)  
    }

    return $clearLogs
}

function Get-DefenderDetections{
    # Collect params, start/end date, and how many events to grab. 
    # Defaults to 99999 events and anything from 01/01/1980 to the day after execution 
    param(
        [Parameter(Mandatory=$true)]    
        [datetime]
        $startDate,

        [Parameter(Mandatory=$true)]
        [datetime]
        $endDate,

        [Parameter(Mandatory=$true)]
        [int]
        $maxEvents
    )
    
    $startDateUniversal = $startDate.ToUniversalTime().ToString('o')
    $endDateUniversal = $endDate.ToUniversalTime().ToString('o')
    $results = New-Object System.Collections.Generic.List[PSCustomObject]

    $LoginpropertyMap = @{
        AccountName = 19
        ThreatName = 7
        Path = 21
    }

    $xpath =    
@"
*[System
    [TimeCreated
        [@SystemTime>='$startDateUniversal' and 
        @SystemTime<='$endDateUniversal']]
    [EventID=1116]]
"@

    $events = Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" -FilterXPath $xpath -MaxEvents $maxEvents -ErrorAction SilentlyContinue

    # Loop through each event
    foreach ($event in $events) {
        $user = $event.Properties[$LoginpropertyMap.AccountName].Value
        $threatName = $event.Properties[$LoginpropertyMap.ThreatName].Value
        $path = $event.Properties[$LoginpropertyMap.Path].Value

        # Add the extracted details to the results array
        $result = [PSCustomObject]@{
            'Time Created (UTC)' = $event.TimeCreated.ToUniversalTime()
            'User'               = $event.UserId
            'LogName'            = $event.LogName
            'Event ID'           = $event.Id
            'Message'            = "$threatName detected at $path"
            'Details'            =
@"
Account Name: $user
Threat Name: $threatName
File Path: $path
"@ 
        }
        $results.Add($result)
    }
    return $results 
}

function Get-SysmonProcessCreate{
    # Collect params, start/end date, and how many events to grab. 
    # Defaults to 99999 events and anything from 01/01/1980 to the day after execution 
    param(
        [Parameter(Mandatory=$true)]    
        [datetime]
        $startDate,

        [Parameter(Mandatory=$true)]
        [datetime]
        $endDate,

        [Parameter(Mandatory=$true)]
        [int]
        $maxEvents
    )
    
    $startDateUniversal = $startDate.ToUniversalTime().ToString('o')
    $endDateUniversal = $endDate.ToUniversalTime().ToString('o')
    $results = New-Object System.Collections.Generic.List[PSCustomObject]

    $LoginpropertyMap = @{
        AccountName = 12
        ProcessID = 3
        OriginalFileName = 9
        commandLine = 10
        ParentCommandLine = 21
    }

    $xpath =    
@"
*[System
    [TimeCreated
        [@SystemTime>='$startDateUniversal' and 
        @SystemTime<='$endDateUniversal']]
    [EventID=1]]
"@

    $events = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath $xpath -MaxEvents $maxEvents -ErrorAction SilentlyContinue

    foreach ($event in $events) {
        $user = $event.Properties[$LoginpropertyMap.AccountName].Value
        $ProcessID = $event.Properties[$LoginpropertyMap.ProcessID].Value
        $OriginalFileName = $event.Properties[$LoginpropertyMap.OriginalFileName].Value
        $commandLine = $event.Properties[$LoginpropertyMap.commandLine].Value
        $ParentCommandLine = $event.Properties[$LoginpropertyMap.ParentCommandLine].Value

        # Add the extracted details to the results array
        $result = [PSCustomObject]@{
            'Time Created (UTC)' = $event.TimeCreated.ToUniversalTime()
            'User'               = $event.UserId
            'LogName'            = $event.LogName
            'Event ID'           = $event.Id
            'Message'            = "$user launched $OriginalFileName"
            'Details'            = 
@"
Account Name: $user
ProcessID: $ProcessID
File Name: $OriginalFileName
Process Command Line: $commandLine
Parent Process Command Line: $ParentCommandLine
"@ 
        }
        $results.Add($result)
    }
    return $results
}

function Get-SysmonNetCreate{
    # Collect params, start/end date, and how many events to grab. 
    # Defaults to 99999 events and anything from 01/01/1980 to the day after execution 
    param(
        [Parameter(Mandatory=$true)]    
        [datetime]
        $startDate,

        [Parameter(Mandatory=$true)]
        [datetime]
        $endDate,

        [Parameter(Mandatory=$true)]
        [int]
        $maxEvents
    )

    $startDateUniversal = $startDate.ToUniversalTime().ToString('o')
    $endDateUniversal = $endDate.ToUniversalTime().ToString('o')
    $results = New-Object System.Collections.Generic.List[PSCustomObject]

    $LoginpropertyMap = @{
        AccountName = 5
        destinationIp = 14
        destinationHostname = 15
        destinationPort = 16
        processId = 3
        image = 4
    }

    $xpath =    
@"
*[System
    [TimeCreated
        [@SystemTime>='$startDateUniversal' and 
        @SystemTime<='$endDateUniversal']]
    [EventID=3]]
"@

    $events = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath $xpath -MaxEvents $maxEvents -ErrorAction SilentlyContinue  

    foreach ($event in $events) {
        $user = $event.Properties[$LoginpropertyMap.AccountName].Value
        $destinationIp = $event.Properties[$LoginpropertyMap.destinationIp].Value
        $destinationHostname = $event.Properties[$LoginpropertyMap.destinationHostname].Value
        $destinationPort = $event.Properties[$LoginpropertyMap.destinationPort].Value
        $processId = $event.Properties[$LoginpropertyMap.processId].Value
        $image = $event.Properties[$LoginpropertyMap.image].Value
        
        $result = [PSCustomObject]@{
            'Time Created (UTC)' = $event.TimeCreated.ToUniversalTime()
            'User'               = $event.UserId
            'LogName'            = $event.LogName
            'Event ID'           = $event.Id
            'Message'            = "$($image.split("\")[-1]) connected to $destinationIp ($destinationHostname) : $destinationPort"
            'Details'            = 
@"
Account Name: $user
Destination IP: $destinationIp
Destination Port: $destinationPort
Destination Hostname: $destinationHostname
Initiating Process ID: $processId
Initiating Process: $image
"@ 
        }
        $results.Add($result)
    }
    return $results
}

function Get-SysmonFileCreate{
    # Collect params, start/end date, and how many events to grab. 
    # Defaults to 99999 events and anything from 01/01/1980 to the day after execution 
    param(
        [Parameter(Mandatory=$true)]    
        [datetime]
        $startDate,

        [Parameter(Mandatory=$true)]
        [datetime]
        $endDate,

        [Parameter(Mandatory=$true)]
        [int]
        $maxEvents
    )

    $startDateUniversal = $startDate.ToUniversalTime().ToString('o')
    $endDateUniversal = $endDate.ToUniversalTime().ToString('o')
    $results = New-Object System.Collections.Generic.List[PSCustomObject]

    $LoginpropertyMap = @{
        AccountName = 7
        targetFilename = 5
        processId = 3
        image = 4
    }

    $xpath =    
@"
*[System
    [TimeCreated
        [@SystemTime>='$startDateUniversal' and 
        @SystemTime<='$endDateUniversal']]
    [EventID=11]]
"@

    $events = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath $xpath -MaxEvents $maxEvents -ErrorAction SilentlyContinue

    foreach ($event in $events) {
        $user = $event.Properties[$LoginpropertyMap.AccountName].Value
        $targetFilename = $event.Properties[$LoginpropertyMap.targetFilename].Value
        $processId = $event.Properties[$LoginpropertyMap.processId].Value
        $image = $event.Properties[$LoginpropertyMap.image].Value
        
        $result = [PSCustomObject]@{
            'Time Created (UTC)' = $event.TimeCreated.ToUniversalTime()
            'User'               = $event.UserId
            'LogName'            = $event.LogName
            'Event ID'           = $event.Id
            'Message'            = "$($image.split("\")[-1]) created file $targetFilename"
            'Details'            = 
@"
Account Name: $user
Target File Name: $targetFilename
ProcessID: $processId
Initiating Process: $image
"@ 
        }
        $results.Add($result)
    }
    return $results
}

function Get-WFPBlocked{
    # Collect params, start/end date, and how many events to grab. 
    # Defaults to 99999 events and anything from 01/01/1980 to the day after execution 
    param(
        [Parameter(Mandatory=$true)]    
        [datetime]
        $startDate,

        [Parameter(Mandatory=$true)]
        [datetime]
        $endDate,

        [Parameter(Mandatory=$true)]
        [int]
        $maxEvents
    )

    $startDateUniversal = $startDate.ToUniversalTime().ToString('o')
    $endDateUniversal = $endDate.ToUniversalTime().ToString('o')
    $results = New-Object System.Collections.Generic.List[PSCustomObject]

    $LoginpropertyMap = @{
        ProcessID = 0
        Application = 1
        DestAddress = 5
        DestPort = 6
    }

    $xpath =    
@"
*[System
    [TimeCreated
        [@SystemTime>='$startDateUniversal' and 
        @SystemTime<='$endDateUniversal']]
    [EventID=5157]]
"@

    $events = Get-WinEvent -LogName "Security" -FilterXPath $xpath -MaxEvents $maxEvents -ErrorAction SilentlyContinue
   
    # Loop through each event
    foreach ($event in $events) {
        $ProcessID = $event.Properties[$LoginpropertyMap.ProcessID].Value
        $Application = $event.Properties[$LoginpropertyMap.Application].Value
        $DestAddress = $event.Properties[$LoginpropertyMap.DestAddress].Value
        $DestPort = $event.Properties[$LoginpropertyMap.DestPort].Value

        # Add the extracted details to the results array
        $result = [PSCustomObject]@{
            'Time Created (UTC)' = $event.TimeCreated.ToUniversalTime()
            'User'               = $event.UserId
            'LogName'            = $event.LogName
            'Event ID'           = $event.Id
            'Message'            = "WFP blocked $($Application.split("\")[-1]) attempting connection to $DestAddress : $DestPort"
            'Details'            =
@"
Destination IP: $DestAddress
Destination Port: $DestPort
Application: $Application
ProcessID: $ProcessID
"@ 
        }
        $results.Add($result)
    }
    return $results 
}

function Get-WFPApproved{
    # Collect params, start/end date, and how many events to grab. 
    # Defaults to 99999 events and anything from 01/01/1980 to the day after execution 
    param(
        [Parameter(Mandatory=$true)]    
        [datetime]
        $startDate,

        [Parameter(Mandatory=$true)]
        [datetime]
        $endDate,

        [Parameter(Mandatory=$true)]
        [int]
        $maxEvents
    )

    $startDateUniversal = $startDate.ToUniversalTime().ToString('o')
    $endDateUniversal = $endDate.ToUniversalTime().ToString('o')
    $results = New-Object System.Collections.Generic.List[PSCustomObject]

    $LoginpropertyMap = @{
        ProcessID = 0
        Application = 1
        DestAddress = 5
        DestPort = 6
    }

    $xpath =    
@"
*[System
    [TimeCreated
        [@SystemTime>='$startDateUniversal' and 
        @SystemTime<='$endDateUniversal']]
    [EventID=5156]]
"@

    $events = Get-WinEvent -LogName "Security" -FilterXPath $xpath -MaxEvents $maxEvents -ErrorAction SilentlyContinue
   
    # Loop through each event
    foreach ($event in $events) {
        $ProcessID = $event.Properties[$LoginpropertyMap.ProcessID].Value
        $Application = $event.Properties[$LoginpropertyMap.Application].Value
        $DestAddress = $event.Properties[$LoginpropertyMap.DestAddress].Value
        $DestPort = $event.Properties[$LoginpropertyMap.DestPort].Value

        # Add the extracted details to the results array
        $result = [PSCustomObject]@{
            'Time Created (UTC)' = $event.TimeCreated.ToUniversalTime()
            'User'               = $event.UserId
            'LogName'            = $event.LogName
            'Event ID'           = $event.Id
            'Message'            = "WFP allowed $($Application.split("\")[-1]) connection to $DestAddress : $DestPort"
            'Details'            =
@"
Destination IP: $DestAddress
Destination Port: $DestPort
Application: $Application
ProcessID: $ProcessID
"@ 
        }
        $results.Add($result)
    }
    return $results 
}

function Get-TaskScheduleRegister{
    # Collect params, start/end date, and how many events to grab. 
    # Defaults to 99999 events and anything from 01/01/1980 to the day after execution 
    param(
        [Parameter(Mandatory=$true)]    
        [datetime]
        $startDate,

        [Parameter(Mandatory=$true)]
        [datetime]
        $endDate,

        [Parameter(Mandatory=$true)]
        [int]
        $maxEvents
    )

    $startDateUniversal = $startDate.ToUniversalTime().ToString('o')
    $endDateUniversal = $endDate.ToUniversalTime().ToString('o')
    $results = New-Object System.Collections.Generic.List[PSCustomObject]

    $LoginpropertyMap = @{
        TaskName = 0
        AccountName = 1
    }

    $xpath =    
@"
*[System
    [TimeCreated
        [@SystemTime>='$startDateUniversal' and 
        @SystemTime<='$endDateUniversal']]
    [EventID=106]]
"@

    $events = Get-WinEvent -LogName "Microsoft-Windows-TaskScheduler/Operational" -FilterXPath $xpath -MaxEvents $maxEvents -ErrorAction SilentlyContinue
   
    # Loop through each event
    foreach ($event in $events) {
        $TaskName = $event.Properties[$LoginpropertyMap.TaskName].Value
        $AccountName = $event.Properties[$LoginpropertyMap.AccountName].Value

        # Add the extracted details to the results array
        $result = [PSCustomObject]@{
            'Time Created (UTC)' = $event.TimeCreated.ToUniversalTime()
            'User'               = $event.UserId
            'LogName'            = $event.LogName
            'Event ID'           = $event.Id
            'Message'            = "$AccountName scheduled task $TaskName"
            'Details'            = $null
        }
        $results.Add($result)
    }
    return $results 
}

$allResultsList = New-Object System.Collections.Generic.List[PSCustomObject]

switch ($PSBoundParameters){
    {$_.ContainsKey("help")}{
        Get-Help
        exit
    }
    {$true}{
        $text = 
@"
 ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ____           
||P |||o |||w |||e |||r |||S |||l |||e |||u |||t |||h ||          
||__|||__|||__|||__|||__|||__|||__|||__|||__|||__|||__||          
|/__\|/__\|/__\|/__\|/__\|/__\|/__\|/__\|/__\|/__\|/__\|                                                                                                                                                                                                                                                         
"@    
        Write-Output $text
        
        $functionCalls = @{
            "Get-UserSessions"         = "No login/logout events (4264/4634) found!"
            "Get-OutboundRDPAttempt"   = "No Outbound RDP events (1024) found!"
            "Get-ServicesInstalled"    = "No service install events (7045) found!"
            "Get-DefenderDetections"   = "No Defender events (1116) found!"
            "Get-GenericLogClearing"   = "No log clearing events (104) found!"
            "Get-SystemStartup"        = "No system startup events (4608) found!"
            "Get-SystemShutdown"       = "No system startup events (4609) found!"
            "Get-TermServSessions"     = "No system RDP login/logoff events (21/23) found!"
            "Get-FailedLogons"         = "No failed login events (4625) found!"
            "Get-PowerShellEvents"     = "No PowerShell events (400) found!"
            "Get-SecurityLogClearing"  = "No log clearing events (1102) found!"
            "Get-TaskScheduleRegister" = "No task schedule registration events (106) found!"
        }
        
        if ($sysmon){
            $functionCalls.Add("Get-SysmonProcessCreate", "No Sysmon process creation events (1)")
            $functionCalls.Add("Get-SysmonNetCreate", "No Sysmon network creation events (3)")
            $functionCalls.Add("Get-SysmonFileCreate", "No Sysmon File creation events (11)")
        }
        
        if ($extended){
            $functionCalls.Add("Get-WFPBlocked", "No WFP network connection blocked events (5157)")
            $functionCalls.Add("Get-WFPApproved", "No WFP network connection approved events (5156)")
        }
        
        foreach ($functionCall in $functionCalls.GetEnumerator()) {
            # Dynamically calling the function
            write-host "Running $($functionCall.Name)..."

            $result = Invoke-Expression "$($functionCall.Name) -startDate '$startDateFormatted' -endDate '$endDateFormatted' -maxEvents $maxEvents"

            if ($result.Count -eq 0) {
                Write-Host "    $($functionCall.Value)" -ForegroundColor Yellow
            } else {
                write-host "    $($result.count) results recorded!" -ForegroundColor Green
                foreach ($item in $result){
                    $allResultsList.Add($item)}
            }
        }   
    } 
    {$_.ContainsKey("csv")}{
        write-host "Output to CSV selected..."
        $OutputFile = Get-OutputPreCheck $CSV
        write-host "Validated output directory. File will be $OutputFile"
        $allResultsList | Export-Csv -NoTypeInformation -Path $OutputFile
    }
    {$_.ContainsKey("quiet") -eq $false}{
        $allResultsList | Select-Object 'Time Created (UTC)', 'Message'
    }       
}

