param (
    $Title,$ConfigPath,$ModulePath
)
#Get-Module *STManage* | Remove-Module
Import-Module $ModulePath -Force

Set-Location C:\ProgramData\Agentish
Function Start-STConfig {
    param(
        [String]$Title,
        [String]$ConfigPath,
        [Switch]$pwsh
    )
    #Start-Transcript -Path C:\ProgramData\Agentish\Transcript.txt -Append
    try {
        $Config = Import-STConfig -Path $ConfigPath -ErrorAction Stop | Where-Object {$_.Title -eq $Title}
        $ScriptAction = $($Config.Action) | ConvertFrom-Base64
        $Measure = Measure-Command -Expression {
            if ($pwsh) {
                Write-Output "Using Powershell Core"
                Start-Process -FilePath "C:\Program Files\PowerShell\7\pwsh.exe" -ArgumentList "-Command `"Invoke-Expression -Command $ScriptAction`"" -Wait -ErrorAction Stop
            }
            else {
                Write-Output "Using Windows Powershell"
                Invoke-Expression -Command $ScriptAction -ErrorAction Stop
            }
        }
    }
    catch {

    }
    finally {
        if (!(Test-Path C:\ProgramData\Agentish\Logs)) {
            New-Item -Path C:\ProgramData\Agentish\Logs -ItemType Directory | Out-Null
        }
        $Measure | Out-File -FilePath C:\ProgramData\Agentish\Logs\Measure_$(Get-Date -f 'MMddHHmm').txt
        #Stop-Transcript
    }
}

Start-STConfig -Title $Title -ConfigPath $ConfigPath -ModulePath $ModulePath