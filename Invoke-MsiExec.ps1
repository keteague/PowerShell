function Invoke-MsiExec {
    <#
    .SYNOPSIS
    Invokes msiexec.exe to install, uninstall, or perform administrative installations of MSI files with various options.
    
    .DESCRIPTION
    This function allows you to invoke msiexec.exe to install, uninstall, or perform administrative installations of MSI files.
    
    .PARAMETER File
    The path to the MSI file or GUID of the installed program to be processed.
    
    .PARAMETER Action
    Specifies the action to perform: Install, Uninstall, or Administrative.
    
    .PARAMETER Quiet
    Runs msiexec.exe with quiet mode. Use additional switches like NoUI, NoUIPlus, Basic, BasicPlus, Reduced, or Full to control the level of UI.
    
    .PARAMETER NoUI
    Runs msiexec.exe with no user interface (UI).
    
    .PARAMETER NoUIPlus
    Runs msiexec.exe with no UI, except for the final dialog box at the end.
    
    .PARAMETER Basic
    Runs msiexec.exe with a basic UI.
    
    .PARAMETER BasicPlus
    Runs msiexec.exe with a basic UI, including the final dialog box at the end.
    
    .PARAMETER Reduced
    Runs msiexec.exe with reduced UI.
    
    .PARAMETER Full
    Runs msiexec.exe with a full UI.
    
    .PARAMETER Restart
    Specifies the restart behavior: NoRestart, Prompt, or Force.
    
    .PARAMETER LogVerbose
    Enables verbose logging with the log file saved at the specified path.
    
    .EXAMPLE
    Invoke-MsiExec -File "C:\temp\installer.msi" -Action Install -Quiet NoUI -LogVerbose "C:\Logs\installer.log"
    Installs the MSI file with no UI and logs the installation details to "C:\Logs\installer.log".
    
    .EXAMPLE
    Invoke-MsiExec -File "{3C28BFD4-90C7-3138-87EF-418DC16E9598}" -Action Uninstall -Quiet NoUIPlus -LogVerbose "C:\Logs\uninstaller.log"
    Uninstalls the program with the specified GUID with no UI, except for the final dialog box at the end, and logs the details to "C:\Logs\uninstaller.log".
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, ParameterSetName='File')]
        [string]$File,

        [Parameter(Mandatory=$true, ParameterSetName='GUID')]
        [string]$GUID,

        [Parameter(Mandatory=$true)]
        [ValidateSet('Install', 'Uninstall', 'Administrative')]
        [string]$Action,

        [Switch]$Quiet,

        [Switch]$NoUI,

        [Switch]$NoUIPlus,

        [Switch]$Basic,

        [Switch]$BasicPlus,

        [Switch]$Reduced,

        [Switch]$Full,

        [ValidateSet('NoRestart', 'Prompt', 'Force')]
        [string]$Restart = 'NoRestart',

        [Parameter(Mandatory=$true)]
        [string]$LogVerbose
    )

    function Get-MsiExecPath {
        $msiExecPath = Join-Path $env:WINDIR 'System32\msiexec.exe'

        if (Test-Path $msiExecPath) {
            return $msiExecPath
        }

        $env:PATH.Split(';') | ForEach-Object {
            $path = Join-Path $_ 'msiexec.exe'
            if (Test-Path $path) {
                return $path
            }
        }

        Write-Warning "msiexec.exe not found in PATH or default location."
        exit
    }

    function Validate-FilePath {
        param (
            [string]$Path
        )

        if (-Not $Path) {
            $Path = Read-Host "Enter the path to the MSI file or GUID"
        }

        if (-Not $Path) {
            Write-Warning "No path or GUID provided. Exiting."
            exit
        }

        if ($Path -match '^{[A-F0-9-]+}$') {
            # Assume it's a GUID
            $GUID = $Path
        }
        else {
            # Assume it's a file path
            if ($Path -notlike '"*"' -or $Path -notlike "'*'") {
                $Path = '"' + $Path + '"'
            }
            $File = $Path
        }
    }

    function Validate-MsiFile {
        param (
            [string]$File
        )

        if (-Not $File) {
            $File = Read-Host "Enter the path to the MSI file"
        }

        if (-Not $File) {
            Write-Warning "No path to MSI file provided. Exiting."
            exit
        }

        if (-Not (Test-Path $File -PathType Leaf)) {
            Write-Warning "MSI file not found at $File. Exiting."
            exit
        }
    }

    function Get-LogFileName {
        param (
            [string]$File
        )

        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $fileName = [System.IO.Path]::GetFileNameWithoutExtension($File)
        $logFileName = "${fileName}-${timestamp}.log"
        return $logFileName
    }

    $msiExecPath = Get-MsiExecPath

    if ($Action -eq 'Install') {
        $arguments = "/i $File"
    }
    elseif ($Action -eq 'Uninstall') {
        $arguments = "/x $File"
    }
    elseif ($Action -eq 'Administrative') {
        $arguments = "/a $File"
    }

    if ($Quiet) {
        if ($NoUI) {
            $arguments += ' /qn'
        }
        elseif ($NoUIPlus) {
            $arguments += ' /qn+'
        }
        elseif ($Basic) {
            $arguments += ' /qb'
        }
        elseif ($BasicPlus) {
            $arguments += ' /qb+'
        }
        elseif ($Reduced) {
            $arguments += ' /qr'
        }
        elseif ($Full) {
            $arguments += ' /qf'
        }
        else {
            $arguments += ' /q'
        }
    }

    if ($Restart -ne 'NoRestart') {
        $arguments += " /forcerestart"
    }

    if ($LogVerbose) {
        $logPath = [System.IO.Path]::GetDirectoryName($LogVerbose)
        if (-Not $logPath) {
            $logPath = Read-Host "Enter the path to store the log file"
            if (-Not $logPath) {
                Write-Warning "No path for the log file provided. Exiting."
                exit
            }
            if ($logPath -notlike '"*"' -or $logPath -notlike "'*'") {
                $logPath = '"' + $logPath + '"'
            }
            $LogVerbose = Join-Path $logPath (Get-LogFileName -File $File)
        }
        $arguments += " /l*v `"$LogVerbose`""
    }

    $msiExecCommand = "$msiExecPath $arguments"
    Write-Host "Running: $msiExecCommand"
    Invoke-Expression $msiExecCommand
}

# Usage examples:
# Invoke-MsiExec -File "C:\temp\installer.msi" -Action Install -Quiet NoUI -LogVerbose "C:\Logs"
# Invoke-MsiExec -File "{3C28BFD4-90C7-3138-87EF-418DC16E9598}" -Action Uninstall -Quiet NoUIPlus -LogVerbose "C:\Logs"
