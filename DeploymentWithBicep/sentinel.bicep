// == deploy Log Analytics workspace
param dailyQuota int = 0

resource logAnalyticsWorkspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: 'CompanySOC'
  location: resourceGroup().location
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 90
    workspaceCapping: {
      dailyQuotaGb: (dailyQuota == 0) ? null : dailyQuota 
    }
  }
}

// ==========================================================================================
// == deploy Sentinel
resource Sentinel 'Microsoft.SecurityInsights/onboardingStates@2024-03-01' = {
  name: 'default'
  scope: logAnalyticsWorkspace
}


// ==========================================================================================
// == deploy Sentinel components

// == deploy Office365 solution
var _solutionId = 'azuresentinel.azure-sentinel-solution-office365'
var _solutionVersion = '3.0.4'
var _solutionSufix = '${_solutionId}-Solution-${_solutionId}-${_solutionVersion}'

resource ContentHub_Office365 'Microsoft.SecurityInsights/contentPackages@2023-04-01-preview' = {
  name: 'Microsoft 365"'
  scope: logAnalyticsWorkspace
  properties: {
    contentId: _solutionId
    contentProductId: '${take(_solutionId,50)}-sl-${uniqueString(_solutionSufix)}'
    contentKind: 'Solution'
    displayName: 'Microsoft 365 (formerly, Office 365)'
    version: _solutionVersion
  }
  dependsOn: [Sentinel]
}

// == enable Office365 Data Connector for Exchange data
resource Office365_Connector 'Microsoft.SecurityInsights/dataConnectors@2023-02-01-preview' = {
  name: 'Office365ConnectorConfig'
  scope: logAnalyticsWorkspace
  dependsOn: [ContentHub_Office365]
  kind: 'Office365' 
  properties: {
    dataTypes: {
      exchange: {
        state: 'Enabled'
      }
      sharePoint: {
        state: 'Disabled'
      }
      teams: {
        state: 'Disabled'
      }
    }
    tenantId: subscription().tenantId
  }
}
