# https://secframe.com/ramp/phase1/adminaccounts/tier-0-admins/builtingroups/

$ErrorActionPreference = "Stop"

$Tier0Groups = New-Object -TypeName 'System.Collections.ArrayList'
$Tier0Groups.AddRange(@(
    "Account Operators",
    "Administrators",
    "Backup Operators",
    "Domain Admins",
    "Domain Controllers",
    "Enterprise Admins",
    "Group policy creator owners",
    ## TODO: Exchange-related groups!
    ## TODO: any group that can directly manipulate GPOs
    "Print Operators",
    "Read-only Domain Controllers",
    "Remote Desktop Users",
    "Schema Admins",
    "Server Operators"   
))

$Output = @()
$groupQueue = New-Object -TypeName 'System.Collections.ArrayList'
$groupQueue.AddRange($Tier0Groups)
$groupsChecked = @()

while ($groupQueue.Count -gt 0) {
    $group = $groupQueue[0]
    $groupQueue.RemoveAt(0)
    if ($groupsChecked.Contains($group)) {
        continue
    }

    # $rootGroup = Get-ADGroup -Identity $group
    # $Output += $member

    $groupMembers = Get-ADGroup -Identity $group | Get-ADGroupMember | Select-Object SamAccountName,DistinguishedName,Name,ObjectClass,ObjectGuid
    foreach ($member in $groupMembers) {
        if ($member.ObjectClass -eq "group") {
            ## do group stuff
            # Write-Debug "adding $member.SamAccountName to group list"
            $groupQueue.Add($member.SamAccountName)
            $Tier0Groups.Add($member.SamAccountName)
            # Write-Debug "groupQueue size = $groupQueue.Count"
        }
        # # } elseif ($member.ObjectClass -eq "user") {
        #     $member | Add-Member -MemberType NoteProperty -Name 'foundInGroup' -Value $group
        #     $Output += $member
        # }
    }

    $groupsChecked += $group
}

$allGroups = Get-ADGroup -Filter * -Properties *
foreach ($group in $allGroups) {
    if ($Tier0Groups.Contains($group.SamAccountName)) {
        $group | Add-Member -MemberType NoteProperty -Name 'IsTier0' -Value $true -Force
    } else {
        $group | Add-Member -MemberType NoteProperty -Name 'IsTier0' -Value $false -Force
    }

    $Output += $group
}

$Output