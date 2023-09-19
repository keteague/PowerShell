<#
.SYNOPSIS
    Searches for mailboxes and distribution groups associated with a specified SMTP address.

.DESCRIPTION
    The Get-SmtpAddress function searches for mailboxes and distribution groups associated with a specified SMTP address.
    It retrieves mailboxes and distribution groups whose email addresses or primary SMTP addresses match the provided SMTP address.

.PARAMETER smtpAddress
    Specifies the SMTP address to search for within mailboxes and distribution groups.

.EXAMPLE
    Get-SmtpAddress -smtpAddress 'user@example.com'
    Searches for mailboxes and distribution groups associated with the SMTP address 'user@example.com'.
#>
function Get-SmtpAddress {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [string]$smtpAddress
    )

    # Get the mailbox with the specified SMTP address
    $mailbox = Get-Mailbox | Where-Object { ($_.EmailAddresses -eq "$smtpAddress") -or ($_.PrimarySmtpAddress -eq "$smtpAddress") }

    # Get all distribution groups and filter them by SMTP address
    $distributionGroups = Get-DistributionGroup -ResultSize Unlimited

    $matchingDistributionGroups = $distributionGroups | Where-Object {
        $_.PrimarySmtpAddress -eq "$smtpAddress"
    }

    if ($mailbox -ne $null) {
        Write-Host "Mailbox with SMTP address '$smtpAddress' found:"
        $mailbox | Select Name, Alias
    } elseif ($matchingDistributionGroups) {
        $groupCount = @($matchingDistributionGroups).Count
        if ($groupCount -gt 0) {
            Write-Host "Distribution group with SMTP address '$smtpAddress' found:"
            $matchingDistributionGroups | Select Name, DisplayName
        }
    } else {
        Write-Host "No mailbox or distribution group found with SMTP address '$smtpAddress'."
    }
}

# Prompt the user for SMTP address if not provided
if (-not $smtpAddress) {
    $smtpAddress = Read-Host -Prompt "Enter SMTP address"
}

# Call the function with the provided SMTP address
Get-SmtpAddress -smtpAddress $smtpAddress