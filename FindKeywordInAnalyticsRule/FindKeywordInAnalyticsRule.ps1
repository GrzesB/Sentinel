
<#
    .SYNOPSIS
    Finds alert rules that are containing sepcified "keyword".

    .DESCRIPTION
    Script finds scheduled alert rules that are containing sepcified "keyword".

    .PARAMETER ResourceGroupName
    Specifies the resource group name for Microsoft Sentinel.

    .PARAMETER WorkspaceName
    Specifies the Log Analytics workspace name for Microsoft Sentinel.

    .PARAMETER SubscriptionName
    Optional parameter specifies the subscription name for Microsoft Sentinel.

    .PARAMETER SkipAuthentication
    Switch parameter that allows to skip authentication (in case PowerShell session to Azure is already authenticated).

    .INPUTS
    None. You cannot pipe objects to FindKeywordInAnalyticsRule script.

    .OUTPUTS
    None.

    .EXAMPLE
    FindKeywordInAnalyticsRule.ps1 -ResourceGroupName sentinelrg -WorkspaceName sentinel-la -keyword "sysmon"

    Connects to "sentinel-la" Log Analytics workspace on "sentinelrg" resource group and looks for "sysmon" keyword.

    .EXAMPLE
    FindKeywordInAnalyticsRule.ps1 -ResourceGroupName sentinelrg -WorkspaceName sentinel-la -SubscriptionName "Visual Studio" -keyword "sysmon"

    Connects to "sentinel-la" Log Analytics workspace on "sentinelrg" resource group. Subscription context is changed to subscription named "Visual Studio".
    Looks for "sysmon" keyword.

    .EXAMPLE
    FindKeywordInAnalyticsRule.ps1 -ResourceGroupName sentinelrg -WorkspaceName sentinel-la -SkipAuthentication -keyword "sysmon"

    Connects to "sentinel-la" Log Analytics workspace on "sentinelrg" resource group. 
    Authentication process is skipped (assumes authentication was already done, otherwise script will fail).
    Looks for "sysmon" keyword.

#>

# version 2022-07-25
# Script is distributed under MIT License - https://github.com/GrzesB/Sentinel/blob/master/FindKeywordInAnalyticsRule/LICENSE


[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)] [string] $ResourceGroupName,
    [Parameter(Mandatory=$true)] [string] $WorkspaceName,
    [Parameter(Mandatory=$false)] [string] $SubscriptionName = "",
    [Parameter(Mandatory=$false)] [switch] $SkipAuthentication,
    [Parameter(Mandatory=$true)] [string] $Keyword
)

#region Helper functions

function Get-SentinelAlertRules
{
    param(
    [Parameter(Mandatory=$true)] [string] $ResourceGroupName,
    [Parameter(Mandatory=$true)] [string] $WorkspaceName
    )

    $URL = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/alertRuleTemplates?api-version=$($apiVersion)"
    $response = Invoke-WebRequest -Method Get -Headers $authHeader -Uri $url
    $values = (ConvertFrom-Json $response.Content).value

    foreach ($alertRule in $values)
    {
        if ($alertRule.kind -eq "Scheduled")
        {
            $inUse = $false
            if ($alertRule.properties.alertRulesCreatedByTemplateCount -gt 0)
            {
                $inUse = $true
            }
        $rule = [PSCustomObject]@{
                displayName = $alertRule.properties.displayName
                query = $alertRule.properties.query
                version = $alertRule.properties.version
                inUse = $inUse
            }    
            $rule    
        }
    }
}

#endregion

# Main code
$apiVersion = "2021-10-01-preview"

# Check if required modules needs to be installed
if ((Get-InstalledModule Az.Accounts -ErrorAction SilentlyContinue) -eq $null)
{
    Write-Host "Az.Accounts module must be installed." -ForegroundColor Yellow
    exit 1
}

# Authenticate to Azure
if (-not $SkipAuthentication)
{
    Connect-AzAccount | Out-Null
}

if ($SubscriptionName -ne "")
{
    Set-AzContext -Subscription $SubscriptionName
}

$context = Get-AzContext
$AzProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
$profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList ($AzProfile)
$token = $profileClient.AcquireAccessToken($context.Subscription.TenantId)

$authHeader = @{
    'Content-Type'  = 'application/json'
    'Authorization' = 'Bearer ' + $token.AccessToken
}

$subscriptionId = $context.Subscription

$sentinelConnection = @{
    ResourceGroupName = $ResourceGroupName
    WorkspaceName = $WorkspaceName
}


# Get Alert rules
try
{  
    $rules = Get-SentinelAlertRules @sentinelConnection
}
catch
{
    Write-Host "Error reading active rules list:`n`t$($_.Exception.Message)`n" -ForegroundColor Red
    exit(1)
}

$list = @()
foreach ($rule in $rules)
{
    if ($rule.query.tolower().Contains($Keyword.tolower()))
    {
        $found = [PSCustomObject]@{
            AlertRuleDisplayName = $rule.displayName
            Version = $rule.version
            InUse = $rule.inUse
        }

        $list += $found
    }
}
$list | Sort-Object -Property AlertRuleDisplayName