Get-Module *STManage* | Remove-Module
#Remove-Module "C:\Users\pry915\Documents\WindowsPowerShell\Scripts\PR_ConfigMgmt\STManage copy.psm1"
#Import-Module "C:\ProgramData\Agentish\STManage-Main-NoScriptFile.psm1"
Import-Module ""

$Script2 = (Get-Content "" -Raw -Encoding UTF8).Trim() | ConvertTo-Base64
$Script1 = (Get-Content -Path "" -Raw -Encoding UTF8).Trim() | ConvertTo-Base64
$ConfigPath = "C:\ProgramData\Agentish\config.json"
$ModulePath = "C:\ProgramData\Agentish\STManage-Main-NoScriptFile.psm1"

$Splat1 = @{
    Title = "Logging - Windows Update"
    Action = $Script1
    ScriptPath = $ConfigPath
    TriggerType = @("Daily")
    StartTime = "7am"
    #Repetition = "4h"
    #Duration = "23h"
    Disabled = $false
    #EventProvider = "Microsoft-Windows-AppXDeployment"
    #EventID = 55000
    #LogClass = "Operational"
    #Remove = $true
    Pwsh = $true
}
$ConfigTotal = @()
$ConfigTotal += (New-CfgFragment @Splat1)



$Splat2 = @{
    Title = "Backup - WUDO"
    Action = $Script2
    ScriptPath = $ConfigPath
    TriggerType = @("Daily")
    StartTime = "7am"
    Repetition = "4h"
    Disabled = $false
    #EventProvider = "Microsoft-Windows-AppXDeployment"
    #EventID = 55000
    #LogClass = "Operational"
    #Day = "Friday"
    #Remove = $true
    Pwsh = $true
}

$ConfigTotal += (New-CfgFragment @Splat2)
$ConfigTotal | ConvertTo-Json | Set-Content $ConfigPath -Force

(Import-STConfig -Path $ConfigPath) | ForEach-Object {
    $Conf = $_ 
    if ($Conf.Pwsh -eq $true) {$Conf | Use-STConfig -ConfigPath $ConfigPath -ModulePath $ModulePath -Pwsh:$true} 
    else {$Conf | Use-STConfig -ConfigPath $ConfigPath -ModulePath $ModulePath -pwsh:$false}
}