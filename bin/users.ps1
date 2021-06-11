# Script to retrieve all AD users along with selected information about 
# their password policy. Intended to be run from the Splunk Universal
# Forwarder on a domain-joined Windows system. Should not need Domain
# Admin privileges.

$ErrorActionPreference = "Stop"

# 
function Get-ADUserPasswordPolicy {
    [CmdletBinding()]    
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        $User
    )

    $userResultantPasswordPolicy = Get-ADUserResultantPasswordPolicy -Identity $user
    if ($null -eq $userResultantPasswordPolicy) {
        $userResultantPasswordPolicy = Get-ADDefaultDomainPasswordPolicy
    } 

    return $userResultantPasswordPolicy
}

function Get-SupportedEncryptionTypesHuman {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        $SupportedEncryptionTypes
    )

    if ($SupportedEncryptionTypes -eq $null) {
        return "Probably RC4-HMAC; Depends on Domain Functional level"
    }

    # if ($SupportedEncryptionTypes -eq $null) {
    #     # according to https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/decrypting-the-selection-of-supported-kerberos-encryption-types/ba-p/1628797
    #     # "Once your domain functional level (DFL) is 2008 or higher, you KRBTGT account will always default to AES encryption.  For all other account types (user and computer) the selected encryption type is determined by the msDS-SupportedEncryptionTypes attribute on the account. "
    #     # So if this value is null we check the functional level and use that result

    #     # list of funcitonal levels here: https://docs.microsoft.com/en-us/powershell/module/activedirectory/set-addomainmode?view=windowsserver2019-ps


    # }

    if ($SupportedEncryptionTypes -eq 0) {
        return "RC4-HMAC"
    }

    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/6cfc7b50-11ed-4b4d-846d-6f08f0812919
    $bitmask = @{
        1     = "DES-CBC-CRC"                 # bit "A"
        2     = "DES-CBC-MD5"                 # bit "B"
        4     = "RC4-HMAC"                    # bit "C"
        8     = "AES128-CTS-HMAC-SHA1-96"     # bit "D"
        16    = "AES256-CTS-HMAC-SHA1-96"     # bit "E"
    }    

    $humanString = @()

    foreach ($bit in $bitmask.GetEnumerator()) {
        if ($SupportedEncryptionTypes -band $bit.Name) {
            $humanString += $bit.Value
        }
    }    

    return ($humanString -join ",")
}


$ADUsers = Get-ADUser -Filter * -Properties *
$users = @()
foreach ($ADUser in $ADUsers) {
    $userResultantPasswordPolicy = Get-ADUserPasswordPolicy -User $ADUser
    $user = [PSCustomObject]@{
        accountExpires                              = $ADUser.accountExpires
        CN                                          = $ADUser.CN
        createTimeStamp                             = $ADUser.createTimeStamp
        # Delegation                                  = 
        
        DisplayName                                 = $ADUser.DisplayName
        DistinguishedName                           = $ADUser.DistinguishedName
        lastLogon                                   = $ADUser.lastLogon
        lastLogonDate                               = $ADUser.lastLogonDate
        modifyTimeStamp                             = $ADUser.modifyTimeStamp
        Name                                        = $ADUser.Name
        ObjectCategory                              = $ADUser.ObjectCategory
        ObjectClass                                 = $ADUser.ObjectClass
        PasswordLastSet                             = $ADUser.PasswordLastSet
        PasswordNeverExpires                        = $ADUser.PasswordNeverExpires
        SamAccountName                              = $ADUser.SamAccountName
        ServicePrincipalNames                       = $ADUser.ServicePrincipalNames
        SID                                         = $ADUser.SID
        memberOfCSV                                 = $ADUser.memberOf -Join ";" 
        SupportEncryptionTypes_Raw                  = $ADUser.'msds-SupportedEncryptionTypes' 
        SupportedEncryptionTypes                    = Get-SupportedEncryptionTypesHuman $ADUser.'msds-SupportedEncryptionTypes' 
        PasswordPolicy_MaxPasswordAge               = $userResultantPasswordPolicy.MaxPasswordAge
        PasswordPolicy_MinPasswordLength            = $userResultantPasswordPolicy.MinPasswordLength
        PasswordPolicy_Name                         = $userResultantPasswordPolicy.Name
        PasswordPolicy_ComplexityEnabled            = $userResultantPasswordPolicy.ComplexityEnabled
        PasswordPolicy_ReversibleEncryptionEnabled  = $userResultantPasswordPolicy.ReversibleEncryptionEnabled
    }
    $users += $user
}

$users