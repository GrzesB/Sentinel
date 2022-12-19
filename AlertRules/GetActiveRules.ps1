
<#
    .SYNOPSIS
    Gets list of active rules in Microsoft Sentinel instance.

    .DESCRIPTION
    Gets list of active rules in Microsoft Sentinel instance.

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
    GetActiveRules.ps1 -ResourceGroupName sentinelrg -WorkspaceName sentinel-la 

    Connects to "sentinel-la" Log Analytics workspace on "sentinelrg" resource group.

    .EXAMPLE
    GetActiveRules.ps1 -ResourceGroupName sentinelrg -WorkspaceName sentinel-la -SubscriptionName "Visual Studio"

    Connects to "sentinel-la" Log Analytics workspace on "sentinelrg" resource group. Subscription context is changed to subscription named "Visual Studio".

    .EXAMPLE
    GetActiveRules.ps1 -ResourceGroupName sentinelrg -WorkspaceName sentinel-la -SkipAuthentication

    Connects to "sentinel-la" Log Analytics workspace on "sentinelrg" resource group. 
    Authentication process is skipped (assumes authentication was already done, otherwise script will fail).
#>

# version 2022-12-19
# Script is distributed under MIT License - https://github.com/GrzesB/Sentinel/blob/master/AlertRules/LICENSE


[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)] [string] $ResourceGroupName,
    [Parameter(Mandatory=$true)] [string] $WorkspaceName,
    [Parameter(Mandatory=$false)] [string] $SubscriptionName,
    [Parameter(Mandatory=$false)] [switch] $SkipAuthentication
)

#region Helper functions

function Get-SentinelAlertRule
{
    param(
    [Parameter(Mandatory=$true)] [string] $ResourceGroupName,
    [Parameter(Mandatory=$true)] [string] $WorkspaceName
    )

    $URL = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/alertRules?api-version=2021-10-01"
    $response = Invoke-WebRequest -Method Get -Headers $authHeader -Uri $url
    $values = (ConvertFrom-Json $response.Content).value

    foreach ($alertRule in $values)
    {
        $rule = [PSCustomObject]@{
            displayName = $alertRule.properties.displayName.Trim('.')
            templateVersion = $alertRule.properties.templateVersion
            enabled = $alertRule.properties.enabled
            severity = $alertRule.properties.severity
        }

        $rule
    }
}
#endregion

# Main code

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


# Get rules list
try
{  
    $rules = Get-SentinelAlertRule @sentinelConnection
}
catch
{
    Write-Host "Error reading active rules list:`n`t$($_.Exception.Message)`n" -ForegroundColor Red
    exit(1)
}

$rules

if ($rules.count -eq 0)
{
    Write-Host "No rules enabled."
}