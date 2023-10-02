# -----------------------------------------
# PowerSleuth v0.7
# 4/4/23
# Aaron Zaleski
#
# Needs: 
# Any way to speed up 4624 processing? 
# Expand Task Scheduler parser to support XML 
# Make better comments 
# Add vendor specific alerts (sophos, CS, etc)
# -----------------------------------------
# Supported Events:
#     Security: 1100 (Event Logger Shutdown), 1102 (Security EVTX cleared),
#         4608 (System Startup), 4609 (System Shutdown),
#         4624 (Login), 4648 (Explicit Login), 4672 (Special Login)
#         4720 (Account Creation), 4723 (Accnt Pass Rst),
#         4724 (Accnt Pass Rst by Admin), 4726 (Acct Deleted)
#     System: 104 (Log Clearing), 7045 (Service Creation)
#     TermServLocalSessMan: 21 (Logon), 23 (Logoff), 25 (Reconnect)
#     Windows PowerShell: 400 (Execution)
#     Task Scheduler: 106 (Task Registered)
#     Defender: 1116 (Malware Identified)
#     RDPClient: 1024 (Outbound RDP)


param ([Alias("h")][switch]$Help,
    [Alias("s")][string]$Search,
    [Alias("d")][int]$Days,
    [Alias("c")][string]$CSV,
    [Alias("o")][string]$Offline,
    [Alias("p")][switch]$Poll,
    [Alias("x")][string]$xsearch,
    [Alias("l")][switch]$logins,
    [Alias("i")][string]$ids,
    [Alias("q")][switch]$quiet)


function Get-Help {
Write-Output "PowerSleuth v0.7

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


# \-----------------------------------------------------\
# Lookup events using the provided ID and event log name
# Passes the events for parsers to create standardized output 
# \-----------------------------------------------------\
function Get-Events($eventlog, $id){
    $Date = (Get-Date).AddDays(-$Days)
    if ($Offline){

        # Appends a trailing backslash if none were provided 
        if ($Offline -notmatch "\\$"){$Offline_fixed = "$Offline\"}else{$Offline_fixed = "$Offline"}
        $eventlog = $eventlog.Replace("/", "%4")
        # Gather events by ID from offline EVTX files
        try{
            $Events = Get-WinEvent -FilterHashtable @{
                Path ="$Offline_fixed$eventlog.evtx";
                #ProviderName='Microsoft-Windows-Security-Auditing';
                ID = $id;
                StartTime=$Date} -ErrorAction Stop}
        catch [Exception] {
            if ($_.Exception -match "No events were found that match the specified selection criteria") {
                Write-Host "`tNo events found for ID $id";
            }
        }
    } else {
        # Gather events by ID from live system
        try{
            $Events = Get-WinEvent -FilterHashtable @{
                LogName = $eventlog;
                #ProviderName='Microsoft-Windows-Security-Auditing';
                ID = $id;
                StartTime=$Date } -ErrorAction Stop}
        catch [Exception] {
            if ($_.Exception -match "No events were found that match the specified selection criteria") {
                Write-Host "`tNo events found for ID $id";
            }
        }
    }

    
    # Send to parsing function based on provided event id number
    if($null -ne $Events){
        switch($id){
            4624 { 
                Convert-Sec4624 $Events}
            7045 {
                Convert-Sys7045 $Events}
            400 {
                Convert-PS400 $Events}
            {($id -eq 21) -or ($id -eq 23) -or ($id -eq 24) -or ($id -eq 25)}{
                Convert-TermServ20s $Events}
            4672 {
                Convert-Sec4672 $Events}
            {(1100, 1102, 4608, 4609, 4720, 4723, 4725, 4726, 4616, 4634, 4625) -contains $id}{
                Convert-GenericSecEvent $Events $id}
            104 {
                Convert-GenericSysEvent $Events $id}
            1116{
                Convert-Def1116 $Events}
            106{
                Convert-TaskSched106 $Events}
            4104{ 
                Convert-GenericPowEvent $Events}
            1024{
                Convert-RDPClientEvent $Events
            }
        }
    }
}


# \-----------------------------------------------------\
# Validate the CSV output directory, creates output file 
# Uses current time/date for output filename 
# \-----------------------------------------------------\
function Get-OutputPreCheck($CSV){
    # Appends training backslash if it wasnt provided 
    if ($CSV -notmatch "\\$"){$CSV_fixed = "$CSV\"}else{$CSV_fixed = "$CSV"}
    
    # Check if the path exists, quits if not 
    if ((Test-Path -Path $CSV_fixed) -eq $false){
        write-host "The provided file path is not valid. Exiting."
        Exit}
    
    # Checks if the path is a directory. If its a file, it quits 
    if ((Get-Item $CSV_fixed) -isnot [System.IO.DirectoryInfo]){
        write-host "The -o parameter can only be a directory. Exiting."
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


# \-----------------------------------------------------\
# Write the generated logs to a CSV
# \-----------------------------------------------------\
function Write-Logs($outputs, $OutputFile, $append){
    if ($append) {
        export-csv -NoTypeInformation -path $OutputFile
    }
    if (($xsearch -ne "") -or ($ids -ne "")){
        $outputs | select-object -property TimeCreated, UserID, Id, LogName, Message | 
        sort-object -property TimeCreated | export-csv -NoTypeInformation -path $OutputFile

    }else{
        $outputs | select-object -property TimeCreated, UserID, Artifact, Message | 
        sort-object -property TimeCreated | export-csv -NoTypeInformation -path $OutputFile
}}

# \-----------------------------------------------------\
# Conduct a search against ALL event logs for a keyword in
# the message field 
# \-----------------------------------------------------\
function Get-TheBigSearch(){
    $outputs_bigsearch = @()
	$Date = (Get-Date).AddDays(-$Days)
    if ($Offline){
        if ($Offline -notmatch "\\$"){$Offline_fixed = "$Offline\"}else{$Offline_fixed = "$Offline"}
        if ((Test-Path -Path $Offline_fixed) -eq $false){
            write-host "Invalid Path. Exiting."
            break}
        $AllLogs = Get-ChildItem -Path $Offline_fixed
        foreach ($Log in $AllLogs.Name){
            $event_search = Get-WinEvent -Oldest -FilterHashtable @{
            Path = ($Offline_fixed + $Log);
            StartTime = $Date } -ErrorAction SilentlyContinue | 
            Where-Object{($_.Message -like "*$xsearch*") -or ($_.Message -match "$xsearch")} |
            Select-Object @{label="TimeCreated";expression={([DateTime]$_.TimeCreated).ToUniversalTime()}}, UserID, Id, LogName, Message
            $outputs_bigsearch += $event_search}
    } else {
        $AllLogs = (Get-WinEvent -ListLog * -ErrorAction SilentlyContinue).LogName
        foreach ($Log in $AllLogs){
            $event_search = Get-WinEvent -Oldest -FilterHashtable @{
            LogName = $Log;
            StartTime=$Date } -ErrorAction SilentlyContinue | 
            Where-Object{($_.Message -like "*$xsearch*") -or ($_.Message -match "$xsearch")} |
            Select-Object @{label="TimeCreated";expression={([DateTime]$_.TimeCreated).ToUniversalTime()}}, UserID, Id, LogName, Message
            $outputs_bigsearch += $event_search 
        }}
    return $outputs_bigsearch
}

# \-----------------------------------------------------\
# Conduct search by ID
# \-----------------------------------------------------\
function Get-TheIDSearch(){
    $outputs_idsearch = @()
	$Date = (Get-Date).AddDays(-$Days)
    if ($Offline){
        if ($Offline -notmatch "\\$"){$Offline_fixed = "$Offline\"}else{$Offline_fixed = "$Offline"}
        if ((Test-Path -Path $Offline_fixed) -eq $false){
            write-host "Invalid Path. Exiting."
            break}
        $AllLogs = Get-ChildItem -Path $Offline_fixed
        foreach ($Log in $AllLogs.Name){
            $event_search = Get-WinEvent -Oldest -FilterHashtable @{
            Path = ($Offline_fixed + $Log);
            StartTime = $Date } -ErrorAction SilentlyContinue | 
            Where-Object{($_.Id -eq $ids) -or ($_.Id -match $Ids)} |
            Select-Object @{label="TimeCreated";expression={([DateTime]$_.TimeCreated).ToUniversalTime()}}, UserID, Id, LogName, Message
            $outputs_idsearch += $event_search}
    } else {
        $AllLogs = (Get-WinEvent -ListLog * -ErrorAction SilentlyContinue).LogName
        foreach ($Log in $AllLogs){
            $event_search = Get-WinEvent -Oldest -FilterHashtable @{
            LogName = $Log;
            StartTime=$Date } -ErrorAction SilentlyContinue | 
            Where-Object{($_.Id -eq $ids) -or ($_.Id -match $Ids)} |
            Select-Object @{label="TimeCreated";expression={([DateTime]$_.TimeCreated).ToUniversalTime()}}, UserID, Id, LogName, Message
            $outputs_idsearch += $event_search 
        }}
    return $outputs_idsearch
}

# \-----------------------------------------------------\
# Generate login statistics, runs if -p is selected 
# \-----------------------------------------------------\
function Get-LoginStats(){
    $Date = (Get-Date).AddDays(-$Days)
    if ($Offline){
        if ($Offline -notmatch "\\$"){$Offline_fixed = "$Offline\"}else{$Offline_fixed = "$Offline"}
        $eventlog = "Security"
        Get-WinEvent -Oldest -FilterHashtable @{
            Path ="$Offline_fixed$eventlog.evtx";
            ID = 4624;
            StartTime=$Date }|
            ForEach-Object {
                $eventXml = ([xml]$_.ToXml()).Event
                $eventXml.EventData.Data[5]."#text"} |
            Group-Object | sort-object -property Count -Descending | format-list Count, Name}
    else{
        Get-WinEvent -Oldest -FilterHashtable @{
            LogName = 'Security';
            ID = 4624;
            StartTime=$Date }|
            ForEach-Object {
                $eventXml = ([xml]$_.ToXml()).Event
                $eventXml.EventData.Data[5]."#text"} |
            Group-Object | sort-object -property Count -Descending | format-list Count, Name}
}


# \-----------------------------------------------------\
# Formats Security events that dont need XML parsing 
# \-----------------------------------------------------\
function Convert-GenericSecEvent($GenericSecEvent, $id) {
	$GenericSecEvent | ForEach-Object{$_ | 
        Add-Member -MemberType NoteProperty -Name "Artifact" -Value "Security EVTX, $id"}
	$GenericSecEvent | Select-Object Artifact, Id, Message, UserID,
	    @{label="TimeCreated";expression={([DateTime]$_.TimeCreated).ToUniversalTime()}}
}


# \-----------------------------------------------------\
# Formats PowerShell events that dont need XML parsing 
# \-----------------------------------------------------\
function Convert-GenericPowEvent($GenericSecEvent, $id) {
	$GenericSecEvent | ForEach-Object{$_ | 
        Add-Member -MemberType NoteProperty -Name "Artifact" -Value "PowerShellOp EVTX, $id"}
	$GenericSecEvent | Select-Object Artifact, Id, Message, UserID,
	    @{label="TimeCreated";expression={([DateTime]$_.TimeCreated).ToUniversalTime()}}
}


# \-----------------------------------------------------\
# Formats System events that dont need XML parsing 
# \-----------------------------------------------------\
function Convert-GenericSysEvent($GenericSecEvent, $id) {
	$GenericSecEvent | ForEach-Object{$_ | 
        Add-Member -MemberType NoteProperty -Name "Artifact" -Value "System EVTX, $id"}
	$GenericSecEvent | Select-Object Artifact, Message, Id, UserID,
	    @{label="TimeCreated";expression={([DateTime]$_.TimeCreated).ToUniversalTime()}}
}


# \-----------------------------------------------------\
# Formats RDP Client event
# \-----------------------------------------------------\
function Convert-RDPClientEvent($GenericRDPClientEvent, $id) {
	$GenericRDPClientEvent | ForEach-Object{$_ | 
        Add-Member -MemberType NoteProperty -Name "Artifact" -Value "RDP Client EVTX, $id"}
    $GenericRDPClientEvent | Select-Object Artifact, Message, Id, UserID,
	    @{label="TimeCreated";expression={([DateTime]$_.TimeCreated).ToUniversalTime()}}
}


# \-----------------------------------------------------\
# Parses the 4624 events into somethine easier to read
# \-----------------------------------------------------\
function Convert-Sec4624($Events4624) {
    $parsed_Events = $Events4624 | ForEach-Object {
        $eventXml = ([xml]$_.ToXml()).Event
        $TimeCreated = ([DateTime]$eventXml.System.TimeCreated.SystemTime).ToUniversalTime()
        #$TargetUserSID = $eventXml.EventData.Data[4]."#text" 
        $TargetUserName = $eventXml.EventData.Data[5]."#text" 
        $TargetDomainName = $eventXml.EventData.Data[6]."#text" 
        #$TargetLogonID = $eventXml.EventData.Data[7]."#text"
        $LogonType = $eventXml.EventData.Data[8]."#text"
        $LogonProcessName = $eventXml.EventData.Data[9]."#text"
        $WorkstationName = $eventXml.EventData.Data[11]."#text"
        #$ProcessName = $eventXml.EventData.Data[17]."#text"
        $IpAddress = $eventXml.EventData.Data[18]."#text"
        if (($LogonType -ne 5) -and
            ($TargetUserName -notlike "*SYSTEM") -and
            ($TargetUserName -notlike "*DWM*") -and
            ($TargetUserName -notlike "*UMFD*")){
            [PSCustomObject]@{
                TimeCreated = $TimeCreated
                UserID = "$TargetDomainName\$TargetUserName"
                Id = 4624
                Artifact = "Security, $id"
                Message = 
@"
User Login
UserID: $TargetDomainName\$TargetUserName
LogonType: $LogonType
Logon Process: $LogonProcessName
IP: $IpAddress
Workstation: $WorkstationName`n
"@
            }
        }
    }
    $parsed_Events | Select-Object TimeCreated, UserID, Id, Artifact, Message
}


# \-----------------------------------------------------\
# Parses the 7045 events into somethine easier to read
# \-----------------------------------------------------\
function Convert-Sys7045($Events7045) {
    $parsed_Events = $Events7045 | ForEach-Object {
        $eventXml = ([xml]$_.ToXml()).Event
        $TimeCreated = ([DateTime]$eventXml.System.TimeCreated.SystemTime).ToUniversalTime()
        $ServiceName = $eventXml.EventData.Data[0]."#text"
        $ImagePath = $eventXml.EventData.Data[1]."#text"  
        #$ServiceType = $eventXml.EventData.Data[2]."#text" 
        #$StartType = $eventXml.EventData.Data[3]."#text" 
        $AccountName = $eventXml.EventData.Data[4]."#text" 
        if ($ImagePath -notlike "*Defender*"){
            [PSCustomObject]@{
                TimeCreated = $TimeCreated
                UserID = $AccountName
                Id = 7045
                Artifact = "System, $Id"
                Message = 
@"
Service Creation
Service Name: $ServiceName
Service Path: $ImagePath
Created By: $AccountName`n
"@
            }
        }
    }
    $parsed_Events | Select-Object TimeCreated, UserID, Id, Artifact, Message
}


# \-----------------------------------------------------\
# Parses the 400 events into somethine easier to read
# \-----------------------------------------------------\
function Convert-PS400($Events400) {
    $pattern = "(?s)(?<=HostApplication=)(.*?)(?=EngineVersion=)"
    $Events400 | ForEach-Object{$_ | Add-Member -MemberType NoteProperty -Name "Artifact" -Value "Powershell EVTX, $id"}
    $Events400 | Select-Object Artifact, Id, UserID,
    @{label="TimeCreated";expression={([DateTime]$_.TimeCreated).ToUniversalTime()}}, 
    @{label="Message";expression={[regex]::Match($_.Message,$pattern).Groups[0].Value}}
}


# \-----------------------------------------------------\
# Parses the 21, 23, 24, 25 events into somethine easier to read
# \-----------------------------------------------------\
function Convert-TermServ20s($Events20) {
    $parsed_Events = $Events20 | ForEach-Object {
        $eventXml = ([xml]$_.ToXml()).Event
        $TimeCreated = ([DateTime]$eventXml.System.TimeCreated.SystemTime).ToUniversalTime()
        $EventID = $eventXml.System.EventID
        $User = $eventXml.UserData.EventXML.User
        $SessionID = $eventXml.UserData.EventXML.SessionID
        $Address = $eventXml.UserData.EventXML.Address
        
        switch($EventID){
            21 {
                [PSCustomObject]@{
                    TimeCreated = $TimeCreated
                    UserID = $User
                    Id = 21
                    Artifact = "TermServ, $Id"
                    Message = 
@"
Interactive Login
UserID: $User
Source IP: $Address
Session ID: $SessionID`n
"@
                }
            }
            23 {
                [PSCustomObject]@{
                    TimeCreated = $TimeCreated
                    UserID = $User
                    Id = 23
                    Artifact = "TermServ, $Id"
                    Message = 
@"
Session Logoff
UserID: $User
Session ID: $SessionID`n
"@

                }
            }
            24 {
                [PSCustomObject]@{
                    TimeCreated = $TimeCreated
                    UserID = $User
                    Id = 24
                    Artifact = "TermServ, $Id"
                    Message = 
@"
Session Disconnected
UserID: $User
Source IP: $Address
Session ID: $SessionID`n
"@
                }
            }
            25 {
                [PSCustomObject]@{
                    TimeCreated = $TimeCreated
                    UserID = $User
                    Id = 25
                    Artifact = "TermServ, $Id"
                    Message = 
@"
Session Reconnected
UserID: $User
Source IP: $Address
Session ID: $SessionID`n
"@
                }
            }
        }
    }
    $parsed_Events | Select-Object TimeCreated, UserID, Id, Artifact, Message
}


# \-----------------------------------------------------\
# Parses the 4672 events into somethine easier to read
# \-----------------------------------------------------\
function Convert-Sec4672($Events4672) {
	$parsed_Events = $Events4672 | ForEach-Object {
	    $eventXml = ([xml]$_.ToXml()).Event
        $TimeCreated = ([DateTime]$eventXml.System.TimeCreated.SystemTime).ToUniversalTime()
        #$SubjectUserSid = $eventXml.EventData.Data[0]."#text"
        $SubjectUserName = $eventXml.EventData.Data[1]."#text"
        $SubjectDomainName = $eventXml.EventData.Data[2]."#text"
        $SubjectLogonId = $eventXml.EventData.Data[3]."#text"
        #$PrivilegeList = $eventXml.EventData.Data[4]."#text"
        if(($SubjectUserName -notlike "*SYSTEM") -and
        ($SubjectUserName -notlike "*DWM*") -and 
        ($SubjectUserName -notlike "*UMFD*") -and 
        ($SubjectUserName -notlike "*LOCAL SERVICE*") -and 
        ($SubjectUserName -notlike "*NETWORK SERVICE*")){
	    	[PSCustomObject]@{
	    	    TimeCreated = $TimeCreated
	    	    UserID = $SubjectUserName
                Id = 4672
	    	    Artifact = "Security, $Id"
	    	    Message = 
@"
Privledged Logon: $SubjectDomainName\$SubjectUserName
Logon ID: $SubjectLogonId`n
"@
            }
        }
    }
	 $parsed_Events | Select-Object TimeCreated, UserID, Id, Artifact, Message
}


# \-----------------------------------------------------\
# Parses the 106 events into somethine easier to read
# \-----------------------------------------------------\
function Convert-TaskSched106($Event106) {
	$Event106 | ForEach-Object{$_ | Add-Member -MemberType NoteProperty -Name "Artifact" -Value ("TaskSheduler EVTX, $id")}
	$Event106_fixed = $Event106 | Select-Object Artifact, Message, Id, UserID,
    @{label="TimeCreated";expression={([DateTime]$_.TimeCreated).ToUniversalTime()}}
    return $Event106_fixed 
}

# \-----------------------------------------------------\
# Parses the 1116 events into somethine easier to read
# \-----------------------------------------------------\
function Convert-Def1116($Events1116) {
    $parsed_Events = $Events1116 | ForEach-Object {
        $eventXml = ([xml]$_.ToXml()).Event
        $TimeCreated = ([DateTime]$eventXml.System.TimeCreated.SystemTime).ToUniversalTime()
        #$ThreatID = $eventXml.EventData.Data[6]."#text"
        $ThreatName = $eventXml.EventData.Data[7]."#text"
        #$SeverityID = $eventXml.EventData.Data[8]."#text"
        #$SeverityName = $eventXml.EventData.Data[9]."#text"
        #$CategoryID = $eventXml.EventData.Data[10]."#text"
        #$CategoryName = $eventXml.EventData.Data[11]."#text"
        #$FWLink = $eventXml.EventData.Data[12]."#text"
        #$SourceID = $eventXml.EventData.Data[16]."#text"
        #$SourceName = $eventXml.EventData.Data[17]."#text"
        $ProcessName = $eventXml.EventData.Data[19]."#text"
        $DetectionUser = $eventXml.EventData.Data[20]."#text"
        $Path = $eventXml.EventData.Data[21]."#text"
        $ExecutionName = $eventXml.EventData.Data[25]."#text"
        #$ErrorDescription = $eventXml.EventData.Data[33]."#text"
        [PSCustomObject]@{
            TimeCreated = $TimeCreated
            UserID = $DetectionUser
            Id = 1116
            Artifact = "Defender, $Id"
            Message = 
@"
Defender Alert: $ThreatName
User: $DetectionUser
Process: $ProcessName
Path: $Path
Action: $ExecutionName
"@
        }
    }
    $parsed_Events | Select-Object TimeCreated, UserID, Id, Artifact, Message
}


# \-----------------------------------------------------\
# Generates that lovely statistic at the end 
# \-----------------------------------------------------\
function Get-CountStats($outputs_raw){

    $counts = @{}
    if ($outputs_raw.length -eq 0){
        write-host "`nThere are no results.`nExiting..."
        break
    }
    $outputs_raw | ForEach-Object {
        if ($counts.Keys -contains $_.Id){
            $counts[$_.Id] ++}
        else{
            $counts.add($_.Id, 1)
        }
    }

    $services_count = $counts[7045]
    $powershell_count = $counts[400]
    $login_count = $counts[4624]
    $loginspec_count = $counts[4672]
    $termserv_count = $counts[21] + $counts[23] + $counts[25]
    $schedtask_count = $counts[106]
    $EventLogging_count = $counts[1100] + $counts[1102] + $counts[104]
    $SystemStartup_count = $counts[4608] + $counts[4609]
    $Defender_count = $counts[1116]
    $Accts_count = $counts[4720] + $counts[4723] + $counts[4724] + $counts[4726]
    $badlogin_count = $counts[4625]
    $outboundrdp_count = $counts[1024]
    $count_total = $outputs.length

    Write-Output "Script Complete! Statistics for $Days days:"
    switch($true){
        {$services_count}{
            Write-Output ("Services Created:          $services_count")
        }{$powershell_count}{
            Write-Output ("PowerShell Execution:      $powershell_count")
        }{$login_count}{
            Write-Output ("Logins:                    $login_count")
        }{$loginspec_count}{
            Write-Output ("Privledged Logins:         $loginspec_count")
        }{$termserv_count}{
            Write-Output ("Interactive Sessions:      $termserv_count")
        }{$schedtask_count}{
            Write-Output ("Scheduled Tasks:           $schedtask_count")
        }{$EventLogging_count}{
            Write-Output ("Event Log Manipulation:    $EventLogging_count")
        }{$SystemStartup_count}{
            Write-Output ("System Start/Stop Entries: $SystemStartup_count")
        }{$Defender_count}{
            Write-Output ("Defender Alerts:           $Defender_count")
        }{$Accts_count}{
            Write-Output ("Account Activity Entries:  $Accts_count")
        }{$badlogin_count}{
            Write-Output ("Failed Logins:             $badlogin_count")
        }{$outboundrdp_count}{
            Write-Output ("Outbound RDP:              $outboundrdp_count")
        }{$count_total}{
            Write-Output ("Total:                     $count_total")
        }
    }
}

$outputs = @()
switch ($PSBoundParameters){

    {$true}{
        $text = @"

 ____ ____ ____ ____ ____ ____ ____ _________ ____ ____ ____ ____ 
||M |||S |||- |||I |||S |||A |||C |||       |||C |||I |||R |||T ||
||__|||__|||__|||__|||__|||__|||__|||_______|||__|||__|||__|||__||
|/__\|/__\|/__\|/__\|/__\|/__\|/__\|/_______\|/__\|/__\|/__\|/__\|
 ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ____           
||P |||o |||w |||e |||r |||S |||l |||e |||u |||t |||h ||          
||__|||__|||__|||__|||__|||__|||__|||__|||__|||__|||__||          
|/__\|/__\|/__\|/__\|/__\|/__\|/__\|/__\|/__\|/__\|/__\|                                                                                                                                                                                                                                                         
"@
        Write-Output $text}

    {$_.ContainsKey("Help") -or ($PSBoundParameters.Values.Count -eq 0)}{
        Get-Help
        break}

    {$_.ContainsKey("Days") -eq $false}{
        Write-Output "Use -d or -days switch to specify timeframe!`nExiting..."
        break}

    {$_.ContainsKey("CSV")}{
        write-host "Output to CSV selected..."
        $OutputFile = Get-OutputPreCheck $CSV
        write-host "Validated output directory. File will be $OutputFile"
        }

    {$_.ContainsKey("Poll")}{
        Write-Output "Polling login events..."
        Get-LoginStats
        break}

    {$_.ContainsKey("quiet") -and -not ($_.ContainsKey("csv"))}{
        Write-Output "Quiet mode requires the CSV option!`nExiting..."
        break}

    {$_.ContainsKey("ids") -and -not ($_.ContainsKey("xsearch"))}{
        Write-Output "`nWARNING: May return the same ID from numerous different logs"
        Write-Output "`nConducting search for $ids...`n"
        $outputs += Get-TheIDSearch
        $outputs | sort-object -property TimeCreated | 
        Format-table -AutoSize -wrap -property TimeCreated, UserID, Id, Logname, Message
        Get-CountStats $outputs
    }
    
    {($_.ContainsKey("xsearch") -eq $true) -and ($_.ContainsKey("CSV") -eq $true) -and ($_.ContainsKey("ids") -eq $false)}{
        Write-Output "`nConducting search across all logs...`n"
        $outputs += Get-TheBigSearch
        Get-CountStats $outputs}
    
    {$_.ContainsKey("xsearch") -and -not ($_.ContainsKey("CSV"))}{
        Write-Output "CSV is required for searches"
        break}

    {$_.ContainsKey("Days") -and ($_.ContainsKey("xsearch") -eq $false) -and ($_.ContainsKey("logins") -eq $true) -and ($_.ContainsKey("ids") -eq $false)}{
        Write-Output "Searching for Logins/Logoff/Failed Authentication..."
        $outputs += Get-Events "Security" 4624
        $outputs += Get-Events "Security" 4672
        $outputs += Get-Events "Security" 4634
        $outputs += Get-Events "Security" 4625
        $outputs += Get-Events 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' 21
        $outputs += Get-Events 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' 23
        $outputs += Get-Events 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' 24
        $outputs += Get-Events 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' 25
        $outputs += Get-Events 'Microsoft-Windows-TerminalServices-RDPClient/Operational' 1024
        
        if($_.ContainsKey("Search")){
            $outputs = $outputs | Where-Object{($_.Message -like "*$Search*") -or ($_.Message -match "$Search")}}

        if($_.ContainsKey("quiet") -eq $false){
            $outputs | sort-object -property TimeCreated | 
            Format-table -AutoSize -wrap -property TimeCreated, UserID, Id, Artifact, Message}
        Get-CountStats $outputs
    }
    
    {$_.ContainsKey("Days") -and ($_.ContainsKey("xsearch") -eq $false) -and ($_.ContainsKey("logins") -eq $false) -and ($_.ContainsKey("ids") -eq $false)}{ 
        Write-Output "Searching for Logins/Logoffs..."
        $outputs += Get-Events "Security" 4624
        $outputs += Get-Events "Security" 4634

        Write-Output "Searching for Services..."
        $outputs += Get-Events "System" 7045

        Write-Output "Searching for PowerShell..."
        $outputs += Get-Events "Windows PowerShell" 400
        $outputs += Get-Events "Microsoft-Windows-PowerShell/Operational" 4104

        Write-Output "Searching for Interactive Logins..."
        $outputs += Get-Events 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' 21
        $outputs += Get-Events 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' 23
        $outputs += Get-Events 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' 24
        $outputs += Get-Events 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' 25

        Write-Output "Searching for Special Logins..."
        $outputs += Get-Events "Security" 4672
        
        Write-Output "Searching for Outbund RDP..."
        $outputs += Get-Events 'Microsoft-Windows-TerminalServices-RDPClient/Operational' 1024

        Write-Output "Searching for Event Log Manipulation (security)..."
        $outputs += Get-Events "Security" 1100
        $outputs += Get-Events "Security" 1102
        $outputs += Get-Events "Security" 4616

        Write-Output "Searching for Event Log Manipulation (system)..."
        $outputs += Get-Events "System" 104

        Write-Output "Searching for System Startup/Shutdown..."
        $outputs += Get-Events "Security" 4608
        $outputs += Get-Events "Security" 4609

        Write-Output "Searching for Account Activities..."
        $outputs += Get-Events "Security" 4720
        $outputs += Get-Events "Security" 4723
        $outputs += Get-Events "Security" 4724
        $outputs += Get-Events "Security" 4726

        Write-Output "Searching for Defender Alerts..."
        $outputs += Get-Events "Microsoft-Windows-Windows Defender/Operational" 1116

        Write-Output "Searching for Scheduled Tasks..."
        $outputs += Get-Events "Microsoft-Windows-TaskScheduler/Operational" 106

        if($_.ContainsKey("Search")){
            $outputs = $outputs | Where-Object{($_.Message -like "*$Search*") -or ($_.Message -match "$Search")}}

        if($_.ContainsKey("quiet") -eq $false){
            $outputs | sort-object -property TimeCreated | 
            Format-table -AutoSize -wrap -property TimeCreated, UserID, Id, Artifact, Message}
        Get-CountStats $outputs
    }

    {$_.ContainsKey("Days") -and $_.ContainsKey("CSV")}{
        Write-Output "`nWriting to CSV...`n"
        Write-Logs $outputs $OutputFile
    }

}


