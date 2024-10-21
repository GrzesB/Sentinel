// ======== Sentinel deployment ==========

// == deploy resource group 
targetScope = 'subscription'

param rgLocation string = 'westeurope'
param rgName string = 'rg-CompanySOC-${rgLocation}'
param dailyQuota int = 0

resource rg 'Microsoft.Resources/resourceGroups@2024-03-01' = {
  name: rgName
  location: rgLocation
}

// == deploy Sentinel
module sentinel './sentinel.bicep' = {
  scope: rg
  name: 'sentinelDeployment'
  params: {
    dailyQuota: dailyQuota
  }
}
