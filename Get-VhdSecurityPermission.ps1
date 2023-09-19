function Get-VhdSecurityPermission {
    <#
    .SYNOPSIS
    Gets NTFS security permissions for a VHD or VHDX file associated with a virtual machine (VM).

    .DESCRIPTION
    This function retrieves NTFS security permissions for a VHD or VHDX file associated with a VM.

    .PARAMETER VMName
    The name of the virtual machine.

    .PARAMETER Disk
    The full path and filename of the VHD or VHDX file.

    .EXAMPLE
    Get-VhdSecurityPermission -VMName "MyVM"
    Retrieves and displays the NTFS security permissions for the VHD associated with the VM named "MyVM".

    .NOTES
    Author: Ken Teague
    Date: September 19, 2023
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string] $VMName,

        [Parameter()]
        [string] $Disk
    )

    # Check if the user supplied the -VMName parameter, if not, prompt for it
    if ([string]::IsNullOrWhiteSpace($VMName)) {
        $VMName = Read-Host "Enter the name of the VM"
    }

    # Check if the user supplied the -Disk parameter, if not, obtain the list of VHDs attached to the VM
    if ([string]::IsNullOrWhiteSpace($Disk)) {
        $AttachedVHDs = (Get-VMHardDiskDrive -VMName $VMName | Select-Object -ExpandProperty 'Path')

        if ($AttachedVHDs.Count -eq 0) {
            Write-Host "No VHDs attached to the VM."
            exit
        }
    }

    # Check each VHD for proper permissions
    foreach ($VHDPath in $AttachedVHDs) {
        $Acl = Get-Acl -Path $VHDPath
        $VMID = (Get-VM -Name $VMName).VMId

        # Check if the VMID has read and write permissions
        $HasPermissions = $Acl.Access | Where-Object { $_.IdentityReference -eq "NT VIRTUAL MACHINE\$VMID" -and $_.FileSystemRights -eq "Read,Write,Synchronize" }

        Write-Host "VMName: $VMName"
        Write-Host "VHD: $VHDPath"

        if ($HasPermissions -eq $null) {
            Write-Host "Result: " -NoNewline
            Write-Host "Mismatch (ACL does not contain VMID)" -ForegroundColor Yellow

            $AddPermission = Read-Host "Add permissions for VM with ID $VMID to this VHD? (Y/n)"
            if ($AddPermission -eq 'Y' -or $AddPermission -eq '') {
                # Add NTFS permissions for the VHD
                $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                    "NT VIRTUAL MACHINE\$VMID",
                    "Read,Write,Synchronize",
                    "Allow"
                )
                $Acl.AddAccessRule($Rule)
                Set-Acl -Path $VHDPath -AclObject $Acl
                Write-Host "Permissions for VM with ID $VMID added to the VHD: $VHDPath." -ForegroundColor Green
            } else {
                Write-Host "No permissions added for VM with ID $VMID on the VHD: $VHDPath." -ForegroundColor Yellow
            }
        } else {
            Write-Host "Result: " -NoNewline
            Write-Host "Match (ACL contains VMID)" -ForegroundColor Green
        }
        Write-Host
    }
}
