function Set-VhdSecurityPermission {
    <#
    .SYNOPSIS
    Sets NTFS permissions for a VHD or VHDX file to allow access to a specified virtual machine (VM).

    .DESCRIPTION
    This function sets NTFS permissions on a VHD or VHDX file to grant read and write access to the specified VM.

    .PARAMETER Name
    The name of the virtual machine.

    .PARAMETER Disk
    The full path and filename of the VHD or VHDX file.

    .EXAMPLE
    Set-VhdSecurityPermission -Name "MyVM" -Disk "C:\Path\to\MyVM.vhdx"
    Grants read and write access to the VM with the name "MyVM" for the specified VHDX file.

    .NOTES
    Author: Ken Teague
    Date: September 19, 2023
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string] $Name,

        [Parameter(Mandatory=$true)]
        [string] $Disk
    )

    # Check if the user supplied the -Name parameter, if not, prompt for it
    if ([string]::IsNullOrWhiteSpace($Name)) {
        $Name = Read-Host "Enter the name of the VM"
    }

    # Check if the user supplied the -Disk parameter, if not, prompt for it
    if ([string]::IsNullOrWhiteSpace($Disk)) {
        $Disk = Read-Host "Enter the full path and filename of the VHD or VHDX file"
    }

    # Get the VMID based on the provided VM name
    $VM = Get-VM -Name $Name
    if ($VM -eq $null) {
        Write-Host "VM with name '$Name' not found."
        exit
    }

    $VMID = $VM.VMId

    # Set NTFS permissions for the VHD or VHDX file
    $Acl = Get-Acl -Path $Disk
    $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "NT VIRTUAL MACHINE\$VMID",
        "Read,Write",
        "Allow"
    )
    $Acl.AddAccessRule($Rule)
    Set-Acl -Path $Disk -AclObject $Acl

    Write-Host "Permissions for VM with ID $VMID added to the VHD/VHDX file."
}
