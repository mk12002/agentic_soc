// Azure infrastructure for the platform (the Kubernetes package is deploy/kubernetes/overlays/azure).
//   az deployment group what-if -g <rg> -f deploy/azure/main.bicep -p prefix=soc adminGroupObjectId=<entra group id> \
//      pgAdminPassword=<secret> existingAppGatewayId=<the organisation's gateway>      (review), then `create`
// SKUs follow INFRASTRUCTURE_AND_COSTS.md section 10 (AKS Standard tier, 3 x D2s_v5, Flexible Server 2 vCore
// zone-redundant, ACR Standard, Key Vault standard). A dedicated WAF v2 gateway is created only when the console is
// internet-facing (decision D5); otherwise AGIC drives the organisation's existing Application Gateway.
// Everything is private by default: the database and Key Vault have no public endpoint, the cluster API is private,
// local accounts are off (Entra ID only), and every resource sends its logs to one Log Analytics workspace.
// Outputs give the values the overlay's CHANGE-ME placeholders need.

targetScope = 'resourceGroup'

@description('Short name prefix for every resource (lowercase letters and digits).')
@minLength(3)
@maxLength(10)
param prefix string

param location string = resourceGroup().location

@description('Entra ID group whose members administer the cluster (Azure RBAC for Kubernetes).')
param adminGroupObjectId string

@description('Administrator login of the PostgreSQL server (schema owner: used only by init-db).')
param pgAdminLogin string = 'socowner'

@secure()
@description('Its password - store it in Key Vault as part of soc-database-migrator-url, nowhere else.')
param pgAdminPassword string

@description('true: the console is internet-facing - a dedicated WAF v2 gateway is created (mandatory, D5).')
param internetFacing bool = false

@description('Internal console: resource id of the organisation\'s existing Application Gateway that AGIC will drive.')
param existingAppGatewayId string = ''

@description('Internet-facing only: Key Vault secret id (versionless) of the console TLS certificate.')
#disable-next-line secure-secrets-in-params // a reference (URI) to the certificate, not the certificate itself
param appGatewayCertSecretId string = ''

@description('Days the workspace keeps logs (31 is included in ingestion; longer is billed per GB-month).')
param logRetentionDays int = 31

param aksNodeSize string = 'Standard_D2s_v5'
param aksNodeCount int = 3
param vnetAddressSpace string = '10.0.0.0/16'
param appGatewaySubnet string = '10.0.0.0/24'
param aksSubnet string = '10.0.1.0/24'
param postgresSubnet string = '10.0.2.0/24'
param privateEndpointSubnet string = '10.0.3.0/24'

var zones = ['1', '2', '3']
var gatewayId = internetFacing ? resourceId('Microsoft.Network/applicationGateways', '${prefix}-agw') : existingAppGatewayId
var kvName = '${prefix}-kv-${uniqueString(resourceGroup().id)}'
var acrName = '${prefix}acr${uniqueString(resourceGroup().id)}'

// ------------------------------------------------------------------ logging

resource logs 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: '${prefix}-logs'
  location: location
  properties: {
    sku: {name: 'PerGB2018'}
    retentionInDays: logRetentionDays   // keep audit.anchor lines longer in the SIEM (Sentinel) or an immutable export
    features: {immediatePurgeDataOn30Days: false}
  }
}

// ------------------------------------------------------------------ network

resource vnet 'Microsoft.Network/virtualNetworks@2023-11-01' = {
  name: '${prefix}-vnet'
  location: location
  properties: {
    addressSpace: {addressPrefixes: [vnetAddressSpace]}
    subnets: [
      {name: 'appgw', properties: {addressPrefix: appGatewaySubnet}}
      {name: 'aks', properties: {addressPrefix: aksSubnet}}
      {
        name: 'postgres'
        properties: {
          addressPrefix: postgresSubnet
          delegations: [{name: 'pg', properties: {serviceName: 'Microsoft.DBforPostgreSQL/flexibleServers'}}]
        }
      }
      {name: 'endpoints', properties: {addressPrefix: privateEndpointSubnet, privateEndpointNetworkPolicies: 'Enabled'}}
    ]
  }
}

resource pgDns 'Microsoft.Network/privateDnsZones@2020-06-01' = {
  name: '${prefix}.private.postgres.database.azure.com'
  location: 'global'
}

resource pgDnsLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2020-06-01' = {
  parent: pgDns
  name: 'vnet'
  location: 'global'
  properties: {registrationEnabled: false, virtualNetwork: {id: vnet.id}}
}

resource kvDns 'Microsoft.Network/privateDnsZones@2020-06-01' = {
  name: 'privatelink.vaultcore.azure.net'
  location: 'global'
}

resource kvDnsLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2020-06-01' = {
  parent: kvDns
  name: 'vnet'
  location: 'global'
  properties: {registrationEnabled: false, virtualNetwork: {id: vnet.id}}
}

// ------------------------------------------------------------------ identity, secrets, registry

resource workload 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${prefix}-workload'
  location: location
}

resource kv 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: take(kvName, 24)
  location: location
  properties: {
    tenantId: subscription().tenantId
    sku: {family: 'A', name: 'standard'}
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 90
    enablePurgeProtection: true
    publicNetworkAccess: 'Disabled'
    networkAcls: {defaultAction: 'Deny', bypass: 'AzureServices'}
  }
}

resource kvEndpoint 'Microsoft.Network/privateEndpoints@2023-11-01' = {
  name: '${prefix}-kv-pe'
  location: location
  properties: {
    subnet: {id: '${vnet.id}/subnets/endpoints'}
    privateLinkServiceConnections: [{name: 'kv', properties: {privateLinkServiceId: kv.id, groupIds: ['vault']}}]
  }
}

resource kvEndpointDns 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2023-11-01' = {
  parent: kvEndpoint
  name: 'default'
  properties: {privateDnsZoneConfigs: [{name: 'kv', properties: {privateDnsZoneId: kvDns.id}}]}
}

var kvSecretsUser = '4633458b-17de-408a-b874-0445c86b69e6'      // Key Vault Secrets User
resource workloadReadsSecrets 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: kv
  name: guid(kv.id, workload.id, kvSecretsUser)
  properties: {
    principalId: workload.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', kvSecretsUser)
  }
}

resource acr 'Microsoft.ContainerRegistry/registries@2023-07-01' = {
  name: take(acrName, 50)
  location: location
  sku: {name: 'Standard'}                            // Premium adds private link and zone redundancy (not priced)
  properties: {
    adminUserEnabled: false                          // pulls by the kubelet identity, pushes by CI's identity
  }
}

// ------------------------------------------------------------------ database

resource pg 'Microsoft.DBforPostgreSQL/flexibleServers@2022-12-01' = {
  name: '${prefix}-pg-${uniqueString(resourceGroup().id)}'
  location: location
  sku: {name: 'Standard_D2ds_v5', tier: 'GeneralPurpose'}
  properties: {
    version: '16'
    administratorLogin: pgAdminLogin
    administratorLoginPassword: pgAdminPassword
    storage: {storageSizeGB: 128}
    backup: {backupRetentionDays: 35, geoRedundantBackup: 'Enabled'}
    highAvailability: {mode: 'ZoneRedundant'}        // synchronous standby in another zone, automatic failover
    network: {delegatedSubnetResourceId: '${vnet.id}/subnets/postgres', privateDnsZoneArmResourceId: pgDns.id}
    authConfig: {activeDirectoryAuth: 'Disabled', passwordAuth: 'Enabled'}
  }
  dependsOn: [pgDnsLink]
}

resource pgDb 'Microsoft.DBforPostgreSQL/flexibleServers/databases@2022-12-01' = {
  parent: pg
  name: 'soc_platform'
  properties: {charset: 'UTF8', collation: 'en_US.utf8'}
}

// TLS only (1.2+), the extension search needs, connection and lock logging, time limits on runaway work
var pgSettings = {
  require_secure_transport: 'on'
  ssl_min_protocol_version: 'TLSv1.2'
  'azure.extensions': 'PG_TRGM'
  max_connections: '300'
  log_connections: 'on'
  log_disconnections: 'on'
  log_lock_waits: 'on'
  idle_in_transaction_session_timeout: '600000'
}
@batchSize(1)
resource pgConfig 'Microsoft.DBforPostgreSQL/flexibleServers/configurations@2022-12-01' = [for s in items(pgSettings): {
  parent: pg
  name: s.key
  properties: {value: s.value, source: 'user-override'}
}]

// ------------------------------------------------------------------ web application firewall + gateway

resource waf 'Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies@2023-11-01' = if (internetFacing) {
  name: '${prefix}-waf'
  location: location
  properties: {
    policySettings: {
      state: 'Enabled'
      mode: 'Prevention'
      requestBodyCheck: true
      maxRequestBodySizeInKb: 2000
      fileUploadLimitInMb: 30
      requestBodyInspectLimitInKB: 128
    }
    managedRules: {
      managedRuleSets: [
        {ruleSetType: 'OWASP', ruleSetVersion: '3.2'}
        {ruleSetType: 'Microsoft_BotManagerRuleSet', ruleSetVersion: '1.0'}
      ]
    }
    customRules: [
      {
        name: 'RateLimitPerClient'                    // shared across every API replica (the app's own limit is per process)
        priority: 10
        ruleType: 'RateLimitRule'
        rateLimitDuration: 'OneMin'
        rateLimitThreshold: 3000
        groupByUserSession: [{groupByVariables: [{variableName: 'ClientAddr'}]}]
        matchConditions: [
          {
            matchVariables: [{variableName: 'RemoteAddr'}]
            operator: 'IPMatch'
            negationConditon: true                    // (sic: the API's spelling) every address but one = all
            matchValues: ['255.255.255.255/32']
          }
        ]
        action: 'Block'
      }
    ]
  }
}

resource agwIp 'Microsoft.Network/publicIPAddresses@2023-11-01' = if (internetFacing) {
  name: '${prefix}-agw-ip'          // WAF_v2 needs a public IP resource even for a private-only frontend
  location: location
  sku: {name: 'Standard'}
  zones: zones
  properties: {publicIPAllocationMethod: 'Static'}
}

resource agwIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = if (internetFacing) {
  name: '${prefix}-agw'
  location: location
}

resource agwReadsCert 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (internetFacing) {
  scope: kv
  name: guid(kv.id, agwIdentity.id, kvSecretsUser)
  properties: {
    principalId: agwIdentity!.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', kvSecretsUser)
  }
}

var agwName = '${prefix}-agw'
var frontend = 'public'
resource agw 'Microsoft.Network/applicationGateways@2023-11-01' = if (internetFacing) {
  name: agwName
  location: location
  zones: zones
  identity: {type: 'UserAssigned', userAssignedIdentities: {'${agwIdentity.id}': {}}}
  properties: {
    sku: {name: 'WAF_v2', tier: 'WAF_v2'}
    autoscaleConfiguration: {minCapacity: 2, maxCapacity: 10}
    firewallPolicy: {id: waf.id}
    sslPolicy: {policyType: 'Predefined', policyName: 'AppGwSslPolicy20220101S'}   // TLS 1.2+ only
    gatewayIPConfigurations: [{name: 'gw', properties: {subnet: {id: '${vnet.id}/subnets/appgw'}}}]
    frontendIPConfigurations: [
      {name: 'public', properties: {publicIPAddress: {id: agwIp.id}}}
    ]
    frontendPorts: [{name: 'https', properties: {port: 443}}]
    sslCertificates: [{name: 'soc-console', properties: {keyVaultSecretId: appGatewayCertSecretId}}]
    // placeholders AGIC replaces with the Ingress (deploy/kubernetes/overlays/azure/ingress.yaml)
    backendAddressPools: [{name: 'default'}]
    backendHttpSettingsCollection: [{name: 'default', properties: {port: 80, protocol: 'Http', requestTimeout: 120}}]
    httpListeners: [{
      name: 'default'
      properties: {
        frontendIPConfiguration: {id: resourceId('Microsoft.Network/applicationGateways/frontendIPConfigurations', agwName, frontend)}
        frontendPort: {id: resourceId('Microsoft.Network/applicationGateways/frontendPorts', agwName, 'https')}
        protocol: 'Https'
        sslCertificate: {id: resourceId('Microsoft.Network/applicationGateways/sslCertificates', agwName, 'soc-console')}
      }
    }]
    requestRoutingRules: [{
      name: 'default'
      properties: {
        ruleType: 'Basic'
        priority: 100
        httpListener: {id: resourceId('Microsoft.Network/applicationGateways/httpListeners', agwName, 'default')}
        backendAddressPool: {id: resourceId('Microsoft.Network/applicationGateways/backendAddressPools', agwName, 'default')}
        backendHttpSettings: {id: resourceId('Microsoft.Network/applicationGateways/backendHttpSettingsCollection', agwName, 'default')}
      }
    }]
  }
  dependsOn: [agwReadsCert]
}

// ------------------------------------------------------------------ cluster

resource aks 'Microsoft.ContainerService/managedClusters@2024-02-01' = {
  name: '${prefix}-aks'
  location: location
  identity: {type: 'SystemAssigned'}
  sku: {name: 'Base', tier: 'Standard'}              // uptime SLA for the control plane
  properties: {
    dnsPrefix: '${prefix}-aks'
    disableLocalAccounts: true                       // Entra ID sign-in only
    enableRBAC: true
    aadProfile: {managed: true, enableAzureRBAC: true, adminGroupObjectIDs: [adminGroupObjectId]}
    apiServerAccessProfile: {enablePrivateCluster: true}
    autoUpgradeProfile: {upgradeChannel: 'patch', nodeOSUpgradeChannel: 'NodeImage'}
    oidcIssuerProfile: {enabled: true}
    securityProfile: {workloadIdentity: {enabled: true}, imageCleaner: {enabled: true, intervalHours: 48}}
    networkProfile: {networkPlugin: 'azure', networkPolicy: 'azure', loadBalancerSku: 'standard', outboundType: 'loadBalancer'}
    agentPoolProfiles: [{
      name: 'system'
      mode: 'System'
      count: aksNodeCount
      vmSize: aksNodeSize
      availabilityZones: zones
      osType: 'Linux'
      osSKU: 'AzureLinux'
      vnetSubnetID: '${vnet.id}/subnets/aks'
      enableEncryptionAtHost: true
      maxPods: 50
    }]
    addonProfiles: {
      azureKeyvaultSecretsProvider: {enabled: true, config: {enableSecretRotation: 'true', rotationPollInterval: '2m'}}
      ingressApplicationGateway: {enabled: true, config: {applicationGatewayId: gatewayId}}
      omsagent: {enabled: true, config: {logAnalyticsWorkspaceResourceID: logs.id}}
      azurepolicy: {enabled: true}                   // pod security and image rules enforced cluster-wide
    }
  }
}

resource federated 'Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials@2023-01-31' = {
  parent: workload
  name: 'soc-platform'
  properties: {
    issuer: aks.properties.oidcIssuerProfile.issuerURL
    subject: 'system:serviceaccount:agentic-soc:soc-platform'
    audiences: ['api://AzureADTokenExchange']
  }
}

var acrPull = '7f951dda-4ed3-4680-a7ca-43fe172d538d'
resource kubeletPulls 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: acr
  name: guid(acr.id, aks.id, acrPull)
  properties: {
    principalId: aks.properties.identityProfile.kubeletidentity.objectId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', acrPull)
  }
}

var contributor = 'b24988ac-6180-42a0-ab88-20f7382dd24c'
// an existing gateway's owner grants AGIC Contributor on it (CLIENT_DEPLOYMENT_GUIDE.md); a new one is granted here
resource agicManagesGateway 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (internetFacing) {
  scope: agw
  name: guid(agw.id, aks.id, contributor)
  properties: {
    principalId: aks.properties.addonProfiles.ingressApplicationGateway.identity.objectId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', contributor)
  }
}

var networkContributor = '4d97b98b-1d4f-4787-a291-c67834d212e7'
resource agicJoinsSubnet 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: vnet
  name: guid(vnet.id, aks.id, networkContributor)
  properties: {
    principalId: aks.properties.addonProfiles.ingressApplicationGateway.identity.objectId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', networkContributor)
  }
}

var managedIdentityOperator = 'f1a07417-d97a-45cb-824c-7a7467783830'
resource agicUsesGatewayIdentity 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (internetFacing) {
  scope: agwIdentity
  name: guid(agwIdentity.id, aks.id, managedIdentityOperator)
  properties: {
    principalId: aks.properties.addonProfiles.ingressApplicationGateway.identity.objectId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', managedIdentityOperator)
  }
}

// ------------------------------------------------------------------ diagnostics: every control-plane log to one place

resource kvDiag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  scope: kv
  name: 'logs'
  properties: {workspaceId: logs.id, logs: [{categoryGroup: 'audit', enabled: true}, {categoryGroup: 'allLogs', enabled: true}]}
}

resource pgDiag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  scope: pg
  name: 'logs'
  properties: {workspaceId: logs.id, logs: [{categoryGroup: 'allLogs', enabled: true}]}
}

resource agwDiag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = if (internetFacing) {
  scope: agw
  name: 'logs'
  properties: {workspaceId: logs.id, logs: [{categoryGroup: 'allLogs', enabled: true}]}
}

resource aksDiag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  scope: aks
  name: 'logs'
  properties: {workspaceId: logs.id, logs: [{category: 'kube-audit-admin', enabled: true}, {category: 'guard', enabled: true}]}
}

resource acrDiag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  scope: acr
  name: 'logs'
  properties: {workspaceId: logs.id, logs: [{categoryGroup: 'allLogs', enabled: true}]}
}

// ------------------------------------------------------------------ what the Kubernetes overlay needs

output keyVaultName string = kv.name
output workloadIdentityClientId string = workload.properties.clientId
output tenantId string = subscription().tenantId
output acrLoginServer string = acr.properties.loginServer
output postgresHost string = pg.properties.fullyQualifiedDomainName
output appGatewaySubnet string = appGatewaySubnet
output postgresSubnet string = postgresSubnet
output wafPolicyId string = internetFacing ? waf.id : ''
output appGatewayId string = gatewayId
