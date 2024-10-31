# MISP to Microsoft Sentinel

This code can be used to create an Azure Function that writes threat intelligence from a MISP instance to Microsoft Sentinel. The code is a modified version of [script.py](https://github.com/cudeso/misp2sentinel/blob/main/script.py) in this repository with Azure Function specific code from [zolderio/misp-to-sentinel](https://github.com/zolderio/misp-to-sentinel) modified slightly.


## Installation

### Prerequisities
- An Azure Subscription 
- A Microsoft Sentinel Instance
- API and URL of your MISP instance

### Full Instructions

Full instructions in [INSTALL.md](../docs/INSTALL.MD)

### Summary

1. Create an app registration in the same Microsoft tenant where the Sentinel instance resides. The app requires Microsoft Sentinel Contributor assigned on the workspace.
2. Create a Keyvault in your Azure subscription
3. Add a new secret with the name "tenants" and the following value 
   * It's possible to add multiple Sentinel instances, it will loop all occurences
   * It's possible to add multiple instances of the same tenant, with different workspaceIds', it will loop over each entry
```json
[
   { 
      "tenantId": "<TENANT_ID_WITH_APP_1>",
      "id": "<APP_ID>",
      "secret": "<APP_SECRET>",
      "workspaceId": "<WORKSPACE_ID>"
   },
   {
      "tenantId": "<TENANT_ID_WITH_APP_N>",
      "id": "<APP_ID>",
      "secret": "<APP_SECRET_N>",
      "workspaceId": "<WORKSPACE_ID_N>"
   }
]
```
4. Add a new secret with the name "mispkey" and the value of your MISP API key
5. Create an Azure Function in your Azure subscription, this needs to be a Linux based Python 3.9 function.
6. Modify config.py to your needs (event filter). 
7. Upload the code to your Azure Function. 
   * If you are using VSCode, this can be done by clicking the Azure Function folder and selecting "Deploy to Function App", provided you have the Azure Functions extension installed.
   * If using Powershell, you can upload the ZIP file using the following command: `Publish-AzWebapp -ResourceGroupName <resourcegroupname> -Name <functionappname> -ArchivePath <path to zip file> -Force`. If you want to make changes to the ZIP-file, simply send the contents of the `AzureFunction`-folder (minus any `.venv`-folder you might have created) to a ZIP-file and upload that.
   * If using AZ CLI, you can upload the ZIP file using the following command: `az functionapp deployment source config-zip --resource-group <resourcegroupname> --name <functionappname> --src <path to zip file>`.
   * You can also use the [`WEBSITE_RUN_FROM_PACKAGE`](https://learn.microsoft.com/en-us/azure/azure-functions/functions-app-settings#website_run_from_package) configuration setting, which will allow you to upload the ZIP-file to a storage account (or Github repository) and have the Azure Function run from there. This is useful if you want to use a CI/CD pipeline to deploy the Azure Function, meaning you can just update the ZIP-file and have the Azure Function automatically update.
8. Add a "New application setting" (env variable) to your Azure Function named `tenants`. Create a reference to the key vault previously created (`@Microsoft.KeyVault(SecretUri=https://<keyvaultname>.vault.azure.net/secrets/tenants/)`).
9. Do the same for the `mispkey` secret (`@Microsoft.KeyVault(SecretUri=https://<keyvaultname>.vault.azure.net/secrets/mispkey/)`)
10. Add a "New application setting" (env variable) called `mispurl` and add the URL to your MISP-server (`https://<mispurl>`)
11.  Add a "New application setting" (env variable) `timerTriggerSchedule` and set it to run. If you're running against multiple tenants with a big filter, set it to run once every two hours or so. 
   * The `timerTriggerSchedule` takes a cron expression. For more information, see [Timer trigger for Azure Functions](https://learn.microsoft.com/en-us/azure/azure-functions/functions-bindings-timer?tabs=python-v2%2Cin-process&pivots=programming-language-python).
   * Run once every two hours cron expression: `0 */2 * * *`
12. Optionally add a "New application setting" (env variable) `misp_event_filters` and set it to a valid JSON object representing the filters to use when querying the MISP server (as per [MISP Settings](https://github.com/cudeso/misp2sentinel?tab=readme-ov-file#misp-settings)).

#### Multi-tenant support

If you want to push to multiple Azure tenants using a single app registration, you can accomplish this by making the app created in step 1 a multi tenant app. Customers can then consent to the app in their own tenant using the following url schema: 
 
`https://login.microsoftonline.com/common/adminconsent?client_id=<APP_ID>&sso_reload=true` 
 
This will allow you to add multiple tenants to the `tenants` variable in step 3. 
Please note that this will require you to add a redirect URL in the app registrations configuration, like `https://portal.azure.com`.

## Usage

If the installation was successful, the MISP data should be written to your Sentinel instance on 00:00 every day. Use the following query to test if the data was written successfully:

```
ThreatIntelligenceIndicator
```

## Credits

Credits for this update goes to:

* [cudeso](https://github.com/cudeso/misp2sentinel) for his work on upgrading the original MISP2Sentinel script
* [zolderik](https://github.com/zolderio/misp-to-sentinel/tree/main) for his work on the Azure Function. 

I've simply spliced them together and added some minor improvements.
