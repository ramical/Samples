<# 
 .SYNOPSIS
	This script summarizes information about performance of Azure AD Connect versions 1.1.819.0 and newer

.DESCRIPTION

	Version: 1.0.0


.DISCLAIMER
	THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
	ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
	THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
	PARTICULAR PURPOSE.

	Copyright (c) Microsoft Corporation. All rights reserved.
#>
param 
(
    [Parameter(Mandatory=$true)]
    [Int]
    $DaysToReport
)

Import-Module "C:\Program Files\Microsoft Azure Active Directory Connect\Tools\AdSyncTools.psm1"
$results = Get-ADSyncToolsRunHistory -Days $DaysToReport

foreach($result in $results)
{
    $parsedResult = [Xml]($result.ReturnValue)

    $exportAdd = 0
    $exportUpdate = 0
    $exportDelete = 0

    $importAdd = 0
    $importUpdate = 0
    $importDelete = 0

    $runDetails = $parsedResult.'run-history'.'run-details'

    if ($runDetails.'step-details'.'export-counters' -ne $null)
    {
        $exportCounters = $runDetails.'step-details'.'export-counters' 
        $exportAdd = [int]$exportCounters.'export-add'.innerText
        $exportUpdate = [int]$exportCounters.'export-update'.innerText
        $exportDelete = [int]$exportCounters.'export-delete'.innerText
    }

    if ($runDetails.'step-details'.'staging-counters' -ne $null)
    {
        $importCounters = $runDetails.'step-details'.'staging-counters' 
        $importAdd = [int]$importCounters.'stage-add'.innerText
        $importUpdate = [int]$importCounters.'stage-update'.innerText
        $importDelete = [int]$importCounters.'stage-delete'.innerText
    }

    if ([DateTime]$runDetails.'step-details'.'end-date' -ne $null)
    {
        $properties = [ordered]@{
            RunProfile     = $runDetails.'run-profile-name'
            Connector      = $runDetails.'ma-name'
            StartTime      = [DateTime]$runDetails.'step-details'.'start-date'
            EndTime        = [DateTime]$runDetails.'step-details'.'end-date'
            DurationSeconds= ([DateTime]$runDetails.'step-details'.'end-date' - [DateTime]$runDetails.'step-details'.'start-date').ToTalSeconds
            ImportAdd      = $importAdd
            ImportUpdate   = $importUpdate
            ImportDelete   = $importDelete
            ExportAdd      = $exportAdd
            ExportUpdate   = $exportUpdate
            ExportDelete   = $exportDelete 
        }

        $outputObject = New-Object PSObject -Property $properties
        Write-Output $outputObject
    }
}