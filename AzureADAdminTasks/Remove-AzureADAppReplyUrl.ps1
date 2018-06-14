<# 
.SYNOPSIS
    Removes Application Reply URLs

.PARAMETER ApplicationObjectId
    Application ObjectId

.PARAMETER ReplyUrlToRemove
    Endpoint to Remove

.DISCLAIMER
    THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
    ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
    THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
    PARTICULAR PURPOSE.

    Copyright (c) Microsoft Corporation. All rights reserved.
#>
[CmdletBinding(SupportsShouldProcess = $true)]

param(
    [Parameter(Mandatory=$true)]    
    [string] 
    $ApplicationObjectId,

    [Parameter(Mandatory=$true)]
    [String]
    $ReplyUrlToRemove
)

try 
{
    Get-AzureADTenantDetail | Out-Null
} 
catch 
{
    Connect-AzureAD 
}

$app = Get-AzureADApplication -ObjectId $ApplicationObjectId -ErrorAction SilentlyContinue 

if ($app -eq $null)
{
    Write-Error -Message "Application not found with Object ID $ApplicationObjectId"
    Return 
}

$appReplyUrls = $app.ReplyUrls

if ($appReplyUrls -notcontains $ReplyUrlToRemove)
{
    Write-Warning "Reply URL $ReplyUrlToRemove is not found in the Application $ApplicationObjectId"
    Return 
}

$filteredReplyUrls = $appReplyUrls | where {$_ -ne $ReplyUrlToRemove}

$app | Set-AzureADApplication -ReplyUrls $filteredReplyUrls

Write-Information "Reply URL $ReplyUrlToRemove removed from Application $ApplicationObjectId"

Get-AzureADApplication -ObjectId $ApplicationObjectId | fl





