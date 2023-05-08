Function Import-STConfig {
    param(
        $Path = "$PSScriptRoot\config.json"
    )
    $ConfigList = $null
    $ConfigList = [System.Collections.Generic.List[PSObject]]@()
    $Config = (Get-Content -Path $Path -Raw -Encoding UTF8 | ConvertFrom-Json)
    
    $Config | ForEach-Object {
        $ConfigList.Add($_)
    }

    $ConfigList
}

Function Define-State {
    param(
        [bool]$Success,
        [String]$Message
    )
    [PSCustomObject]@{
        Success = $Success
        Message = $Message
    }
}

function Get-ObjectMember {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [PSCustomObject]$obj
    )
    $obj | Get-Member -MemberType NoteProperty | ForEach-Object {
        $key = $_.Name
        [PSCustomObject]@{Key = $key; Value = $obj."$key"}
    }
}

Function Validate-STConfig {
    param(
        [Parameter(ValueFromPipeline)]$ValObj,
        [Parameter(ValueFromPipelineByPropertyName)][Switch]$SetFile
    )
    if ($ValObj.Remove -eq $true) {
        $ValObj | Remove-STConfig
        Return "Successful"
    }
    try {
        $ST = Get-ScheduledTask -TaskName $ValObj.Title -ErrorAction Stop
        $State = Define-State -Success:$true -Message "Scheduled Task Found"
    }
    catch {
        Write-Error "No Scheduled Task match, creating..." -ErrorAction SilentlyContinue
        $State = Define-State -Success:$false -Message "No Scheduled Task match, creating..."
    }
    if ($State.Success -eq $true) {
        $Global:TruthArray = [System.Collections.Generic.List[PSObject]]@()
        $ValObj.TriggerType | Get-ObjectMember | ForEach-Object {
            #$TriggerType = $_.PSObject.Properties.Name
            $TriggerType = $_.Key.ToString()
            $Details = $_.Value
            #$Details = $_.PSObject.Properties.Value
            Switch($TriggerType) {
                "Daily" {
                    $DailyArray = @()
                    $StartTime = $Details.StartTime
                    $Duration = $Details.Duration
                    $Repetition = $Details.Repetition
                    $ExecutionTimeLimit = $Details.ExecutionTimeLimit
                    $RandomDelay = $Details.RandomDelay
                    $DaysInterval = $Details.DaysInterval
                    
                    $STRepetition = $ST.Triggers.Repetition.Interval | ConvertFrom-STTime
                    $STStartTime = (($ST.Triggers.StartBoundary).ToString() | Select-String -Pattern "\d{2}\:\d{2}(?=:\d{2}\-)").Matches.Value
                    $STDuration = $ST.Triggers.EndBoundary | ConvertFrom-STTime
                    $STExecutionTimeLimit = $ST.Triggers.ExecutionTimeLimit | ConvertFrom-STTime
                    $STRandomDelay = $ST.Triggers.RandomDelay | ConvertFrom-STTime
                    $STDaysInterval = $ST.Triggers.DaysInterval

                    $TruthArray.Add($($StartTime -match $STStartTime))
                    $TruthArray.Add($($Duration -match $STDuration))
                    $TruthArray.Add($($Repetition -match $STRepetition))   
                    $TruthArray.Add($($ExecutionTimeLimit -match $STExecutionTimeLimit))
                    $TruthArray.Add($($RandomDelay -match $STRandomDelay))
                    $TruthArray.Add($($DaysInterval -match $STDaysInterval))
                    $Global:DailyArray += $TruthArray
                }
                "Weekly" {
                    $WeeklyArray = @()
                    $StartTime = $Details.StartTime
                    $Duration = $Details.Duration
                    $Repetition = $Details.Repetition
                    $ExecutionTimeLimit = $Details.ExecutionTimeLimit
                    $RandomDelay = $Details.RandomDelay
                    $WeeksInterval = $Details.WeeksInterval
                    $DaysOfWeek = $Details.DaysOfWeek

                    $STRepetition = $ST.Triggers.Repetition.Interval | ConvertFrom-STTime
                    $STStartTime = (($ST.Triggers.StartBoundary).ToString() | Select-String -Pattern "\d{2}\:\d{2}(?=:\d{2}\-)").Matches.Value
                    $STDuration = $ST.Triggers.EndBoundary | ConvertFrom-STTime
                    $STExecutionTimeLimit = $ST.Triggers.ExecutionTimeLimit | ConvertFrom-STTime
                    $STRandomDelay = $ST.Triggers.RandomDelay | ConvertFrom-STTime
                    $STWeeksInterval = $ST.Triggers.WeeksInterval
                    $STDaysofWeek = $ST.Triggers.DaysOfWeek

                    $TruthArray.Add($($StartTime -match $STStartTime))
                    $TruthArray.Add($($Duration -match $STDuration))
                    $TruthArray.Add($($Repetition -match $STRepetition))   
                    $TruthArray.Add($($ExecutionTimeLimit -match $STExecutionTimeLimit))
                    $TruthArray.Add($($RandomDelay -match $STRandomDelay))
                    $Global:WeeklyArray += $TruthArray
                }
                "Once" {
                    $OnceArray = @()
                    $StartTime = $Details.StartTime
                    $Duration = $Details.Duration
                    $Repetition = $Details.Repetition
                    $ExecutionTimeLimit = $Details.ExecutionTimeLimit
                    $RandomDelay = $Details.RandomDelay
                    
                    $STRepetition = $ST.Triggers.Repetition.Interval | ConvertFrom-STTime
                    $STStartTime = (($ST.Triggers.StartBoundary).ToString() | Select-String -Pattern "\d{2}\:\d{2}(?=:\d{2}\-)").Matches.Value
                    $STDuration = $ST.Triggers.EndBoundary | ConvertFrom-STTime
                    $STExecutionTimeLimit = $ST.Triggers.ExecutionTimeLimit | ConvertFrom-STTime
                    $STRandomDelay = $ST.Triggers.RandomDelay | ConvertFrom-STTime

                    $TruthArray.Add($($StartTime -match $STStartTime))
                    $TruthArray.Add($($Duration -match $STDuration))
                    $TruthArray.Add($($Repetition -match $STRepetition))   
                    $TruthArray.Add($($ExecutionTimeLimit -match $STExecutionTimeLimit))
                    $TruthArray.Add($($RandomDelay -match $STRandomDelay))
                    $Global:OnceArray += $TruthArray
                }
                "OnLock" {}
                "OnUnlock" {}
                "AtStartup" {}
                "OnEvent" {}
                "AtLogon" {}
                "AtLogoff" {}
            }
            if ($TruthArray -contains $false) {
                $State = Define-State -Success:$false -Message "Trigger mismatch, forcing recreate..."
            }
            else {
                $State = Define-State -Success:$true -Message "Trigger match, no action required"
            }
        }
        if ($State.Success -eq $true) {
            $STActionExecute = $ST.Actions.Execute
            if (($ValObj.Pwsh -eq $true) -and ($STActionExecute -ne "pwsh.exe")) {
                $State = Define-State -Success:$false -Message "Execution mismatch, forcing recreate..."
            }
        }
    }
    $State
}


Function Remove-STConfig {
    param(
        [Parameter(ValueFromPipeline)]$RemObj,
        [Parameter(ValueFromPipelineByPropertyName)][Switch]$SetFile
    )

    if ($SetFile) {
        $TestPath = Test-Path -Path $RemObj.ScriptPath
        if ($TestPath) {
            Remove-Item -Path $RemObj.ScriptPath | Out-Null
        }
    }
    try {
        $ST = Get-ScheduledTask -TaskName $RemObj.Title -ErrorAction Stop
        $ST | Unregister-ScheduledTask -ErrorAction Continue -Confirm:$false | Out-Null
    }
    catch {Write-Output "Already Removed"}
}

Function Use-STConfig {
    param(
        [Parameter(ValueFromPipeline)]$InObj,
        [Switch]$SetFile,
        [String]$LauncherPath = "C:\ProgramData\Agentish\Launcher.ps1",
        [String]$ConfigPath = "C:\ProgramData\Agentish\config.json",
        [String]$ModulePath = "C:\ProgramData\Agentish\STManage-Main-NoScriptFile.psm1"
    )
    $InObj | ForEach-Object {
        
        $Global:CfgObj = $_
        $CfgObj.Title

        $Validation = $CfgObj | Validate-STConfig
        if (($Validation).Success -eq $False) { #Validate Config against current setup
            Write-Output $_.Exception
            $Global:Triggers = @()
            $CfgObj.TriggerType | Get-ObjectMember |ForEach-Object {
                $Type = $_.Key.ToString()
                $TriggerSettings = $_.Value
                $Global:TriggerHash = @{}
                Switch -Exact ($Type) {
                    default {
                        Write-Output "State Trigger"
                        $Global:TriggerFilter = ($TriggerSettings | Select-Object -Property * -ExcludeProperty StartTime, EventID, EventProvider, LogClass, pwsh)
                    }
                    "Daily"  {
                        Write-Output "Daily Trigger"
                        $Global:TriggerFilter = ($TriggerSettings | Select-Object -Property * -ExcludeProperty EventID, EventProvider, LogClass, pwsh)
                    }
                    "Weekly"  {
                        Write-Output "Weekly Trigger"
                        $Global:TriggerFilter = ($TriggerSettings | Select-Object -Property * -ExcludeProperty EventID, EventProvider, LogClass, pwsh)
                    }
                    "Once"  {
                        Write-Output "Once Trigger"
                        $Global:TriggerFilter = ($TriggerSettings | Select-Object -Property * -ExcludeProperty EventID, EventProvider, LogClass, pwsh)
                    }
                    "OnEvent"   {
                        Write-Output "Event Trigger"
                        $Global:TriggerFilter = ($TriggerSettings | Select-Object -Property * -ExcludeProperty Repetition, StartTime)
                    }
                }

                $TriggerFilter.PSObject.Properties | ForEach-Object {
                    $TriggerHash.Add($($_.Name),$($_.Value))
                }
                $Global:Triggers += (New-STTrigger @TriggerHash -Type $Type)
                
                $Pwsh = $CfgObj.Pwsh
                if ($pwsh -eq $true) {
                    $Action = New-ScheduledTaskAction -Execute "pwsh.exe" -Argument "-ExecutionPolicy bypass -file $LauncherPath -Title `"$($CfgObj.Title)`" -ConfigPath `"$ConfigPath`" -ModulePath `"$ModulePath`" "
                }
                else {
                    $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy bypass -file $LauncherPath -Title `"$($CfgObj.Title)`" -ConfigPath `"$ConfigPath`" -ModulePath `"$ModulePath`" "
                }
            }
            
            $DefaultSetting = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -StartWhenAvailable
            Register-ScheduledTask -Action $Action -Settings $DefaultSetting -Trigger $Triggers -TaskName $CfgObj.Title -User "System" -TaskPath '\DesktopEngineering' -Force | Out-Null
            Write-Output "Created Setup for $($CfgObj.Title)"
        
        }
        else {
            Write-Output "Completed"
        }
    }
}

Function ConvertTo-STTime {
    param (
        [Parameter(ValueFromPipeline)][String]$In
        )
    Switch -Regex ($In) {
        "\d+m|M" {$Out = "PT" + $In.trim("m|M") + "M"}
        "\d+s|S" {$Out = "PT" + $In.trim("s|S") + "S"}
        "\d+d|D" {$Out = "PT" + $In.trim("d|D") + "D"}
        "\d+h|H" {$Out = "PT" + $In.trim("h|H") + "H"}
    }
    $Out
}

Function ConvertFrom-STTime {
    param (
        [Parameter(ValueFromPipeline)][String]$In
        )
    $Out = $In.trim("PT")
    $Out
}

Function New-STTrigger {
    [CmdletBinding()]
    param (
        [ValidateSet("AtStartup","AtLogon","AtLogoff","Once","Weekly","OnEvent","OnLock","OnUnlock","Daily")][String]$Type,
        [String]$ExecutionTimeLimit = "5m", #30m, 1h, 2h
        [Switch]$Disabled,
        [String]$Repetition, #Ex. 5m, 10m, 15m, 30m, 1h
        [String]$Duration, #Ex. 30m, 1h, 2h
        [String]$Delay,
        [String]$EventProvider, #Ex. "Microsoft-Windows-AppXDeploymentServer"
        [Int]$EventId,
        [String]$RandomDelay = "10m", #5m, 10m, etc.
        [String]$LogClass, #Ex. Operational, Informational, Debug
        [DateTime]$StartTime, #Ex. 12:00
        [String]$Day, #Ex. Monday, Tuesday, etc.
        [Int]$DaysInterval = 1,
        [Bool]$pwsh
    )

    Function New-STStateChange {
        Get-CimClass MSFT_TaskSessionStateChangeTrigger root/Microsoft/Windows/TaskScheduler | New-CimInstance -ClientOnly
    }

    Function New-STTaskRepetition {
        Get-CimClass MSFT_TaskRepetitionPattern root/Microsoft/Windows/TaskScheduler | New-CimInstance -ClientOnly
    }

    Function New-STEventTrigger {
        Get-CimClass MSFT_TaskEventTrigger root/Microsoft/Windows/TaskScheduler | New-CimInstance -ClientOnly
    }

    if ($Repetition -or $Duration) {
        $RepPattern = New-STTaskRepetition
        if ($Repetition) {$RepPattern.Interval = ($Repetition | ConvertTo-STTime)}
        if ($Duration) {$RepPattern.Duration = ($Duration | ConvertTo-STTime)}
    }

    if ($RandomDelay) {
        $RandomDelay = ($RandomDelay).Trim("M|m") 
    }

    Switch($Type) {
        "AtStartup" {
            $Trigger = New-ScheduledTaskTrigger -AtStartup
        }
        "AtLogon" {
            $Trigger = New-ScheduledTaskTrigger -AtLogon
        }
        "AtLogoff" {
            $Trigger = New-ScheduledTaskTrigger -AtLogOff
        }
        "Once" {
            $Trigger = New-ScheduledTaskTrigger -Once -At $StartTime -RandomDelay (New-TimeSpan -Minutes $RandomDelay)
        }
        "Weekly" {
            $Trigger = New-ScheduledTaskTrigger -Weekly -At $StartTime -RandomDelay (New-TimeSpan -Minutes $RandomDelay) -DaysOfWeek $Day
        }
        "OnEvent" {
            $Trigger = New-STEventTrigger
            $Trigger.Subscription = "<QueryList><Query Id=`"0`" Path=`"$($EventProvider)/$($LogClass)`"><Select Path=`"$($EventProvider)/$($LogClass)`">*[System[Provider[@Name=`"$($EventProvider)`"] and EventID=$($EventID)]]</Select></Query></QueryList>"
        }
        "OnLock" {
            $Trigger = New-STStateChange
            $Trigger.StateChange = 7 #Workstation Lock
        }
        "OnUnlock" {
            $Trigger = New-STStateChange
            $Trigger.StateChange = 8 #Workstation Unlock
        }
        "Daily" {
            $Trigger = New-ScheduledTaskTrigger -Daily -At $StartTime -RandomDelay (New-TimeSpan -Minutes $RandomDelay) -DaysInterval $DaysInterval
        }
    }

    if ($Repetition -or $Duration) {$Trigger.Repetition = $RepPattern}
    #if ($Duration) {$Trigger.Duration = $Duration}
    if ($Delay) {$Trigger.Delay = ($Delay | ConvertTo-STTime)}
    Switch ($Disabled) {
        $True {$Trigger.Enabled = $False}
        $False {$Trigger.Enabled = $True}
    }
    
    $Trigger.ExecutionTimeLimit = ($ExecutionTimeLimit | ConvertTo-STTime)
    $Trigger
}

Function ConvertTo-Base64 {
    param(
        [Parameter(ValueFromPipeline)]$InObj
    )

    $ToEncBytes = [System.Text.Encoding]::UTF8.GetBytes($InObj)
    $ToEncText = [System.Convert]::ToBase64String($ToEncBytes)
    $ToEncText
}

Function ConvertFrom-Base64 {
    param(
        [Parameter(ValueFromPipeline)]$InObj
    )

    $decodedBytes = [System.Convert]::FromBase64String($InObj)
    $decodedText = [System.Text.Encoding]::Utf8.GetString($decodedBytes)
    $decodedText
}

Function New-CfgFragment {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][String]$Title,
        [Parameter(Mandatory)][String]$Action,
        [Parameter(Mandatory)][String]$ScriptPath,
        [String]$EventProvider,
        [Bool]$Disabled,
        [Int]$EventID,
        [String]$LogClass,
        [String]$Repetition,
        [String]$Duration,
        [String]$ExecutionTimeLimit = "30m",
        [String]$StartTime,
        [Bool]$Remove,
        [String]$Day,
        [ValidateSet("AtStartup","AtLogon","Once","Weekly","OnEvent","OnLock","OnUnlock","Daily")][Array]$TriggerType,
        [System.Collections.ArrayList]$Dependencies = @(),
        [String]$Delay,
        [Bool]$pwsh
    )

    $Obj = [PSCustomObject][Ordered]@{
        Title = $Title
        Action = $Action
        ScriptPath = $ScriptPath
        TriggerType = $TriggerType
        Disabled = $Disabled
        Dependencies = $Dependencies
        ExecutionTimeLimit = $ExecutionTimeLimit
    }

    if ($Remove) {
        $Obj | Add-Member -MemberType NoteProperty -Name Remove -Value $Remove
    }
    if ($Pwsh) {
        $Obj | Add-Member -MemberType NoteProperty -name Pwsh -Value $Pwsh
    }
    if ($TriggerType -contains "OnEvent") {
        try {
            $Obj | Add-Member -MemberType NoteProperty -Name EventID -Value $EventID -ErrorAction Stop
            $Obj | Add-Member -MemberType NoteProperty -Name EventProvider -Value $EventProvider -ErrorAction Stop
            $Obj | Add-Member -MemberType NoteProperty -Name LogClass -Value $LogClass -ErrorAction Stop
        }
        catch {Write-Error -Exception "Missing elements for Event"}
    }

    if (($TriggerType -contains "Daily") -or ($TriggerType -contains "Weekly") -or ($TriggerType -contains "Once")) {
        try {
            $Obj | Add-Member -MemberType NoteProperty -Name StartTime -Value $StartTime
        }
        catch {Write-Error -Exception "Missing StartTime."}
    }

    if ($TriggerType -eq "Weekly") {
        $Obj | Add-Member -MemberType NoteProperty -Name Day -Value $Day
    }

    if ($Repetition) {
        $Obj | Add-Member -MemberType NoteProperty -Name Repetition -Value $Repetition
    }

    if ($Duration) {
        $Obj | Add-Member -MemberType NoteProperty -Name Duration -Value $Duration
    }

    if ($Delay) {
        $Obj | Add-Member -MemberType NoteProperty -Name Delay -Value $Delay
    }
    $Obj
}