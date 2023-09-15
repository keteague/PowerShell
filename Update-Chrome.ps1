# Check if the OS is Windows 8 or Windows Server 2012 or above
$osVersion = [Environment]::OSVersion.Version

# Define the directories to search for chrome.exe
$chromeDirectories = @(
    "${env:ProgramFiles}\Google",
    "${env:ProgramFiles(x86)}\Google"
)

# Function to search for chrome.exe and retrieve version information
function Find-ChromeExecutable {
  param (
    [string]$directory
  )

  # Check if the directory exists before attempting to search it
  if (Test-Path $directory -PathType Container) {
    $chromeExePaths = Get-ChildItem -Path $directory -File -Recurse -Filter "chrome.exe" | ForEach-Object {
    $versionInfo = (Get-Command $_.FullName).FileVersionInfo
    [PSCustomObject]@{
      Path    = $_.FullName
      Version = $versionInfo.ProductVersion
    }
  }

  $chromeExePaths
  }
}

# Start the search in specified directories
$foundExecutables = @()

foreach ($dir in $chromeDirectories) {
  $foundExecutables += Find-ChromeExecutable -directory $dir
}

# Store the results
if ($foundExecutables.Count -gt 0) {
  $foundExecutables | ForEach-Object {
    $installedPath = $($_.Path)
    $installedVersion = $($_.Version)
  }
} else {
  Write-Host "No Chrome installations found in the specified directories."
}

# Function to install MSI files
function Install-Msi {
  param (
    [string]$File
  )

  if (-not (Test-Path $File -PathType Leaf)) {
    Write-Host "MSI installer file not found at: $File"
    return
  }

  $msiArguments = "/i `"$File`" /qn"

  try {
    Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArguments -Wait -NoNewWindow
    Write-Host "Installation completed successfully."
  } catch {
    Write-Host "Error occurred during installation: $_"
  }
}

# Function to obtain file metadata, e.g. file properties > details
function Get-FileMetaData {
  <#
  .SYNOPSIS
  Small function that gets metadata information from file providing similar output to what Explorer shows when viewing file

  .DESCRIPTION
  Small function that gets metadata information from file providing similar output to what Explorer shows when viewing file

  .PARAMETER File
  FileName or FileObject

  .EXAMPLE
  Get-ChildItem -Path $Env:USERPROFILE\Desktop -Force | Get-FileMetaData | Out-HtmlView -ScrollX -Filtering -AllProperties

  .EXAMPLE
  Get-ChildItem -Path $Env:USERPROFILE\Desktop -Force | Where-Object { $_.Attributes -like '*Hidden*' } | Get-FileMetaData | Out-HtmlView -ScrollX -Filtering -AllProperties

  .NOTES
  #>
  [CmdletBinding()]
  param (
    [Parameter(Position = 0, ValueFromPipeline)][Object] $File,
    [switch] $Signature
  )
  Process {
    foreach ($F in $File) {
      $MetaDataObject = [ordered] @{}
      if ($F -is [string]) {
        $FileInformation = Get-ItemProperty -Path $F
      } elseif ($F -is [System.IO.DirectoryInfo]) {
        #Write-Warning "Get-FileMetaData - Directories are not supported. Skipping $F."
        continue
      } elseif ($F -is [System.IO.FileInfo]) {
        $FileInformation = $F
      } else {
        Write-Warning "Get-FileMetaData - Only files are supported. Skipping $F."
        continue
      }
      $ShellApplication = New-Object -ComObject Shell.Application
      $ShellFolder = $ShellApplication.Namespace($FileInformation.Directory.FullName)
      $ShellFile = $ShellFolder.ParseName($FileInformation.Name)
      $MetaDataProperties = [ordered] @{}
      0..400 | ForEach-Object -Process {
        $DataValue = $ShellFolder.GetDetailsOf($null, $_)
        $PropertyValue = (Get-Culture).TextInfo.ToTitleCase($DataValue.Trim()).Replace(' ', '')
        if ($PropertyValue -ne '') {
          $MetaDataProperties["$_"] = $PropertyValue
        }
      }
      foreach ($Key in $MetaDataProperties.Keys) {
        $Property = $MetaDataProperties[$Key]
        $Value = $ShellFolder.GetDetailsOf($ShellFile, [int] $Key)
        if ($Property -in 'Attributes', 'Folder', 'Type', 'SpaceFree', 'TotalSize', 'SpaceUsed') {
          continue
        }
        if (($null -ne $Value) -and ($Value -ne '')) {
          $MetaDataObject["$Property"] = $Value
        }
      }
      if ($FileInformation.VersionInfo) {
        $SplitInfo = ([string] $FileInformation.VersionInfo).Split([char]13)
        foreach ($Item in $SplitInfo) {
          $Property = $Item.Split(":").Trim()
          if ($Property[0] -and $Property[1] -ne '') {
            $MetaDataObject["$($Property[0])"] = $Property[1]
          }
        }
      }
      $MetaDataObject["Attributes"] = $FileInformation.Attributes
      $MetaDataObject['IsReadOnly'] = $FileInformation.IsReadOnly
      $MetaDataObject['IsHidden'] = $FileInformation.Attributes -like '*Hidden*'
      $MetaDataObject['IsSystem'] = $FileInformation.Attributes -like '*System*'
      if ($Signature) {
        $DigitalSignature = Get-AuthenticodeSignature -FilePath $FileInformation.Fullname
        $MetaDataObject['SignatureCertificateSubject'] = $DigitalSignature.SignerCertificate.Subject
        $MetaDataObject['SignatureCertificateIssuer'] = $DigitalSignature.SignerCertificate.Issuer
        $MetaDataObject['SignatureCertificateSerialNumber'] = $DigitalSignature.SignerCertificate.SerialNumber
        $MetaDataObject['SignatureCertificateNotBefore'] = $DigitalSignature.SignerCertificate.NotBefore
        $MetaDataObject['SignatureCertificateNotAfter'] = $DigitalSignature.SignerCertificate.NotAfter
        $MetaDataObject['SignatureCertificateThumbprint'] = $DigitalSignature.SignerCertificate.Thumbprint
        $MetaDataObject['SignatureStatus'] = $DigitalSignature.Status
        $MetaDataObject['IsOSBinary'] = $DigitalSignature.IsOSBinary
      }
      [PSCustomObject] $MetaDataObject
    }
  }
}

# Run this against Windows versions that are outdated.
# Currently (2023-09-13), versions earlier than Windows 8 / 2012 are unsupported.
# Yeeeeah, this part will likely not work as the script barfs syntax errors when processing the Get-FileMetadata function because it requires PoSh v5 or greater
# Windows 7 defaults to PoSh v2 - your milage may vary.
if ($osVersion.Major -lt 6 -or ($osVersion.Major -eq 6 -and $osVersion.Minor -lt 2)) {
  Write-Warning "Your OS is no longer supported!"
  exit
}

# Run this against Windows 8 / Server 2012 only (Google has sunsetted but still providing bug fixes)
# https://support.google.com/chrome/a/thread/185534987
if ($osVersion.Major -eq 6 -and ($osVersion.Minor -eq 2 -or $osVersion.Minor -eq 3)) {
  Write-Warning "Google has sunsetted support for Chrome on Windows 8 and Windows Server 2012.  Only bug fixes are being released."
  Write-Warning "More details: https://support.google.com/chrome/a/thread/185534987"
  if (($installedPath -like "*x86*" -and [System.Environment]::Is64BitOperatingSystem) -or (![System.Environment]::Is64BitOperatingSystem)) {
    $downloadUrl = "https://edgedl.me.gvt1.com/edgedl/release2/10/windows-8/googlechromestandaloneenterprise.msi"
  } elseif ($installedPath -like "*Program Files\*" -and [System.Environment]::Is64BitOperatingSystem) {
    $downloadUrl = "https://edgedl.me.gvt1.com/edgedl/release2/10/windows-8/googlechromestandaloneenterprise64.msi"
  }
  # Download the installer file
  $installerPath = "$env:TEMP\chrome_installer.msi"
  Invoke-WebRequest $downloadUrl -OutFile $installerPath
  # Use the Get-FileMetaData function to extract the Comments section
  $installerVersion = (Get-ChildItem $installerPath -Force | Get-FileMetaData -Signature).Comments
  # Extract the version from the Comments section
  $latestVersion = [regex]::Matches($installerVersion, '\d+\.\d+\.\d+\.\d+')[0].Value
  if ($installedVersion -lt $latestVersion) {
	Write-Host "Installing Google Chrome $latestVersion..."
	Install-Msi -File "${installerPath}"
  } elseif ($installedVersion -gt $latestVersion) {
	Write-Warning "Installed version ($installedVersion) is greater than the latest version ($latestVersion)"
	# There was a time when Google supported Win8/2012 and allowed for installation of versions greater than major 109.
  # Those installations would cause the version check in this script to fail, because, at this date (2023-09-15), Win8/2012
  # are on the chopping block to be sunsetted, and they only supply major version 109 to those OS's.  As such, when 
  # performing a version check, the installed version would be greater than the latest version avilable for download.  This
  # section of the script attempts to correct this issue by removing the higher version (since it's no longer supported
  # and installs the latest supported version.
    Write-Warning "Removing unsupported verison of Chrome..."
    $search = "Google Chrome"
    $installed = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |  Select-Object DisplayName, UninstallString
    $installed += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, UninstallString
    $result =$installed | ?{ $_.DisplayName -ne $null } | Where-Object {$_.DisplayName -like $search } 

    if ($result.uninstallstring -like "msiexec*") {
      $args=(($result.UninstallString -split ' ')[1] -replace '/I','/X ') + ' /q'
      Start-Process msiexec.exe -ArgumentList $args -Wait
    } else {
      Start-Process $result.UninstallString -Wait
    }
    Write-Host "Installing Chrome ..."
    Install-Msi -File "${installerPath}"
  } elseif ($installedVersion -eq $latestVersion) {
	  Write-Host "Chrome is already up to date."
  } elseif ($installedVersion -eq $null) {
    Write-Host "Unable to determine the version of Chrome that is installed."
  } elseif ($latestVersion -eq $null) {  
    Write-Host "Unable to determine the version from the installer that was downloaded"
  } else {
    Write-Host "Something unexpected happened while comparing the Chrome installation candidate for Windows 8 / Server 2012 to the copy that is currently installed."
  }
  exit
}

# Run this against Windows 10 / Server 2016 or greater
if ($osVersion.Major -ge 10) {
	# Check the installed version of Chrome
	$latestVersionUrl = "https://chromiumdash.appspot.com/fetch_releases?channel=Stable&platform=Windows&num=1"
	$latestVersion = (Invoke-RestMethod $latestVersionUrl)[0].version
	if ($installedVersion -lt $latestVersion) {
		Write-Output "Downloading and installing Google Chrome $latestVersion..."
		$downloadUrl = "http://dl.google.com/chrome/install/latest/chrome_installer.exe"
		$installerPath = "$env:TEMP\chrome_installer.exe"
		Invoke-WebRequest $downloadUrl -OutFile $installerPath
		Start-Process -FilePath $installerPath -Args "/silent /install" -Wait
	}
	else {
		Write-Output "Google Chrome is already up to date."
		exit
	}
}
