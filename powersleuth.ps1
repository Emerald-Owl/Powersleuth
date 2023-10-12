param(
    [string]
    $startDate = "01/01/1980",
    [string]
    $endDate = ((Get-Date).AddDays(1)).ToString("MM/dd/yyyy"),
    [int]
    $maxEvents = 999999
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
            'Detail'             = $null
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
            'Detail'             = $null
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
            'Detail'             =
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

$allResultsList = New-Object System.Collections.Generic.List[PSCustomObject]

# Get login events
$result_UserSessions = Get-UserSessions -startDate $startDateFormatted -endDate $endDateFormatted -maxEvents $maxEvents
if ($result_UserSessions.count -eq 0){
    Write-Host "No login/logout events (4264/4634) found." -ForegroundColor Yellow
} else {
    $allResultsList.Add($result_UserSessions)
}

# Get outbound RDP attempts
$result_OutboundRDPAttempt = Get-OutboundRDPAttempt -startDate $startDateFormatted -endDate $endDateFormatted -maxEvents $maxEvents
if ($result_OutboundRDPAttempt.count -eq 0){
    Write-Host "No Outbound RDP events (1024) found." -ForegroundColor Yellow
} else {
    $allResultsList.Add($result_OutboundRDPAttempt)
}

# Get Service install events
$result_ServicesInstalled = Get-ServicesInstalled -startDate $startDateFormatted -endDate $endDateFormatted -maxEvents $maxEvents
if ($result_ServicesInstalled.count -eq 0){
    Write-Host "No service install events (7045) found." -ForegroundColor Yellow
} else {
    $allResultsList.Add($result_ServicesInstalled)
}

# Get System Startup events
$result_SystemStartup = Get-SystemStartup -startDate $startDateFormatted -endDate $endDateFormatted -maxEvents $maxEvents
if ($result_SystemStartup.count -eq 0){
    Write-Host "No system startup events (4608) found." -ForegroundColor Yellow
} else {
    $allResultsList.Add($result_SystemStartup)
}

# Get System shutdown events
$result_SystemShutdown = Get-SystemShutdown -startDate $startDateFormatted -endDate $endDateFormatted -maxEvents $maxEvents
if ($result_SystemShutdown.count -eq 0){
    Write-Host "No system startup events (4609) found." -ForegroundColor Yellow
} else {
    $allResultsList.Add($result_SystemShutdown)
}

# Get RDP events
$result_TermServSessions = Get-TermServSessions -startDate $startDateFormatted -endDate $endDateFormatted -maxEvents $maxEvents
if ($result_TermServSessions.count -eq 0){
    Write-Host "No system RDP login/logoff events (21/23) found." -ForegroundColor Yellow
} else {
    $allResultsList.Add($result_TermServSessions)
}

# Get Failed Login events
$result_FailedLogons = Get-FailedLogons -startDate $startDateFormatted -endDate $endDateFormatted -maxEvents $maxEvents
if ($result_FailedLogons.count -eq 0){
    Write-Host "No failed login events (4625) found." -ForegroundColor Yellow
} else {
    $allResultsList.Add($result_FailedLogons)
}

# Get Failed Login events
$result_PowerShellEvents = Get-PowerShellEvents -startDate $startDateFormatted -endDate $endDateFormatted -maxEvents $maxEvents
if ($result_PowerShellEvents.count -eq 0){
    Write-Host "No PowerShell events (400) found." -ForegroundColor Yellow
} else {
    $allResultsList.Add($result_PowerShellEvents)
}

# Get Failed Login events
$result_GenericLogClearing = Get-GenericLogClearing -startDate $startDateFormatted -endDate $endDateFormatted -maxEvents $maxEvents
if ($result_GenericLogClearing.count -eq 0){
    Write-Host "No log clearing events (104) found." -ForegroundColor Yellow
} else {
    $allResultsList.Add($result_GenericLogClearing)
}


$allResultsList | format-table


