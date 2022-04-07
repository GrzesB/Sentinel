
<#
    .SYNOPSIS
    Finds alert rules that are using Watchlist.

    .DESCRIPTION
    Script discovers watchlists and then detects in which alert rules these watchlists are used.

    .PARAMETER ResourceGroupName
    Specifies the resource group name for Microsoft Sentinel.

    .PARAMETER WorkspaceName
    Specifies the Log Analytics workspace name for Microsoft Sentinel.

    .PARAMETER SubscriptionName
    Optional parameter specifies the subscription name for Microsoft Sentinel.

    .PARAMETER SkipAuthentication
    Switch parameter that allows to skip authentication (in case PowerShell session to Azure is already authenticated).

    .INPUTS
    None. You cannot pipe objects to CreateAlertRules script.

    .OUTPUTS
    None.

    .EXAMPLE
    WhereIsMyWatchlistUsed.ps1 -ResourceGroupName sentinelrg -WorkspaceName sentinel-la 

    Connects to "sentinel-la" Log Analytics workspace on "sentinelrg" resource group.

    .EXAMPLE
    WhereIsMyWatchlistUsed.ps1 -ResourceGroupName sentinelrg -WorkspaceName sentinel-la -SubscriptionName "Visual Studio"

    Connects to "sentinel-la" Log Analytics workspace on "sentinelrg" resource group. Subscription context is changed to subscription named "Visual Studio".

    .EXAMPLE
    WhereIsMyWatchlistUsed.ps1 -ResourceGroupName sentinelrg -WorkspaceName sentinel-la -SkipAuthentication

    Connects to "sentinel-la" Log Analytics workspace on "sentinelrg" resource group. 
    Authentication process is skipped (assumes authentication was already done, otherwise script will fail).
#>

# version 2022-04-07
# Script is distributed under MIT License - https://github.com/GrzesB/Sentinel/blob/master/WhereIsMyWatchlistUsed/LICENSE


[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)] [string] $ResourceGroupName,
    [Parameter(Mandatory=$true)] [string] $WorkspaceName,
    [Parameter(Mandatory=$false)] [string] $SubscriptionName,
    [Parameter(Mandatory=$false)] [switch] $SkipAuthentication
)

#region Helper functions

function Get-SentinelAlertRules
{
    param(
    [Parameter(Mandatory=$true)] [string] $ResourceGroupName,
    [Parameter(Mandatory=$true)] [string] $WorkspaceName
    )

    $URL = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/alertRules?api-version=$($apiVersion)"
    $response = Invoke-WebRequest -Method Get -Headers $authHeader -Uri $url
    $values = (ConvertFrom-Json $response.Content).value

    foreach ($alertRule in $values)
    {
        $rule = [PSCustomObject]@{
            displayName = $alertRule.properties.displayName
            query = $alertRule.properties.query
        }

        $rule
    }
}

function Get-SentinelWatchlists
{
    param(
    [Parameter(Mandatory=$true)] [string] $ResourceGroupName,
    [Parameter(Mandatory=$true)] [string] $WorkspaceName
    )

    $URL = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/watchlists?api-version=$($apiVersion)"
    $response = Invoke-WebRequest -Method Get -Headers $authHeader -Uri $url
    $values = (ConvertFrom-Json $response.Content).value

    foreach ($watchlist in $values)
    {
        $list = [PSCustomObject]@{
            displayName = $watchlist.properties.displayName
            alias = $watchlist.properties.watchlistAlias
        }

        $list
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

# Get Watchlists
try
{  
    $watchlists = Get-SentinelWatchlists @sentinelConnection
}
catch
{
    Write-Host "Error reading watchlists list:`n`t$($_.Exception.Message)`n" -ForegroundColor Red
    exit(1)
}


foreach ($watchlist in $watchlists)
{
    foreach ($rule in $rules)
    {
        if ($rule.query -match "(?-i)_GetWatchlist\(['`"]" + $watchlist.alias)
        {
            $found = [PSCustomObject]@{
                WatchlistDisplayName = $watchlist.displayName
                AlertRuleDisplayName = $rule.displayName
            }

            $found
        }
    }
}
