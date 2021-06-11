$ErrorActionPreference = "Stop"

# T1552.006 - Group Policy Preferences
# https://adsecurity.org/?p=2288
# https://support.microsoft.com/en-us/topic/ms14-025-vulnerability-in-group-policy-preferences-could-allow-elevation-of-privilege-may-13-2014-60734e15-af79-26ca-ea53-8cd617073c30
# findstr /S /I cpassword \\wcclab.local\sysvol\wcclab.local\policies\*.xml

# Based on Get-GPPPassword.ps1 by Chris Campbell
# PowerSploit Function: Get-GPPPassword  
# Author: Chris Campbell (@obscuresec)  
# License: BSD 3-Clause  
# Required Dependencies: None  
# Optional Dependencies: None  

# helper function to parse fields from xml files
function Get-GPPInnerField {
[CmdletBinding()]
    Param (
        $File
    )

    try {
        $Filename = Split-Path $File -Leaf
        [xml] $Xml = Get-Content ($File)

        # check for the cpassword field
        if ($Xml.innerxml -match 'cpassword') {

            $Xml.GetElementsByTagName('Properties') | ForEach-Object {
                if ($_.cpassword) {
                    $Cpassword = $_.cpassword
                    if ($Cpassword -and ($Cpassword -ne '')) {
                    #    $DecryptedPassword = Get-DecryptedCpassword $Cpassword
                    #    $Password = $DecryptedPassword
                    #    Write-Verbose "[Get-GPPInnerField] Decrypted password in '$File'"
    			$Password = "[REDACTED]"
			$CPassword = "[REDACTED]"
                    }

                    if ($_.newName) {
                        $NewName = $_.newName
                    }

                    if ($_.userName) {
                        $UserName = $_.userName
                    }
                    elseif ($_.accountName) {
                        $UserName = $_.accountName
                    }
                    elseif ($_.runAs) {
                        $UserName = $_.runAs
                    }

                    try {
                        $Changed = $_.ParentNode.changed
                    }
                    catch {
                        Write-Verbose "[Get-GPPInnerField] Unable to retrieve ParentNode.changed for '$File'"
                    }

                    try {
                        $NodeName = $_.ParentNode.ParentNode.LocalName
                    }
                    catch {
                        Write-Verbose "[Get-GPPInnerField] Unable to retrieve ParentNode.ParentNode.LocalName for '$File'"
                    }

                    if (!($Password)) {$Password = '[BLANK]'}
                    if (!($UserName)) {$UserName = '[BLANK]'}
                    if (!($Changed)) {$Changed = '[BLANK]'}
                    if (!($NewName)) {$NewName = '[BLANK]'}

                    $GPPPassword = New-Object PSObject
                    $GPPPassword | Add-Member Noteproperty 'UserName' $UserName
                    $GPPPassword | Add-Member Noteproperty 'NewName' $NewName
                    $GPPPassword | Add-Member Noteproperty 'Password' $Password
                    $GPPPassword | Add-Member Noteproperty 'Changed' $Changed
                    $GPPPassword | Add-Member Noteproperty 'File' $File
                    $GPPPassword | Add-Member Noteproperty 'NodeName' $NodeName
                    $GPPPassword | Add-Member Noteproperty 'Cpassword' $Cpassword
                    $GPPPassword
                }
            }
        }
    }
    catch {
        Write-Warning "[Get-GPPInnerField] Error parsing file '$File' : $_"
    }
}
$XMLFiles += Get-ChildItem -Path $AllUsers -Recurse -Include 'Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml','Printers.xml','Drives.xml' -Force -ErrorAction SilentlyContinue

$XMLFiles = @()
$Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain() | Select-Object -ExpandProperty Name

$DomainXMLFiles = Get-ChildItem -Force -Path "\\$Domain\SYSVOL\*\Policies" -Recurse -ErrorAction SilentlyContinue -Include @('Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml','Printers.xml','Drives.xml')

if($DomainXMLFiles) {
    $XMLFiles += $DomainXMLFiles
}

$Results = @()
ForEach ($File in $XMLFiles) {
	$Results += (Get-GPPInnerField $File.Fullname)
}

$Results