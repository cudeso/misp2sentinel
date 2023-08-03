- [MISP to Microsoft Sentinel integration](#misp-to-microsoft-sentinel-integration)
  - [Introduction](#introduction)
    - [Upload Indicators API and Graph API](#upload-indicators-api-and-graph-api)
    - [STIX instead of MISP JSON](#stix-instead-of-misp-json)
    - [Sentinel Workspaces](#sentinel-workspaces)
  - [Installation](#installation)
    - [Azure](#azure)
      - [Azure App registration](#azure-app-registration)
      - [Threat intelligence data connector](#threat-intelligence-data-connector)
      - [Azure Function (optional)](#azure-function)
    - [MISP](#misp)
  - [Configuration](#configuration)
    - [Microsoft settings](#microsoft-settings)
    - [MISP settings](#misp-settings)
    - [Integration settings](#integration-settings)
  - [Setup](#setup)
    - [Cron job](#cron-job)
  - [Integration details](#integration-details)
    - [MISP taxonomies](#misp-taxonomies)
    - [Attack patterns](#attack-patterns)
    - ["Created by" in Sentinel](#created-by-in-sentinel)
    - [Mappings](#mappings)
      - [Confidence level](#confidence-level)
      - [Sentinel threat type](#sentinel-threat-type)
      - [Kill Chain](#kill-chain)
      - [TLP](#tlp)
      - [Diamond model](#diamond-model)
      - [Threat actors](#threat-actors)
      - [Ignored types](#ignored-types)
      - [Expiration date](#expiration-date)
      - [Attribute mapping](#attribute-mapping)
  - [FAQ](#faq)
    - [I don't see my indicator in Sentinel](#i-dont-see-my-indicator-in-sentinel)
  - [Additional documentation](#additional-documentation)

# MISP to Microsoft Sentinel integration

## Introduction

The MISP to Microsoft Sentinel integration allows you to upload indicators from MISP to Microsoft Sentinel. It relies on **PyMISP** to get indicators from MISP and an **Azure App** to connect to Sentinel. 

### Upload Indicators API and Graph API

The integration supports two methods for sending threat intelligence from MISP to Microsoft Sentinel:

- Use the [Upload Indicators API](https://learn.microsoft.com/en-us/azure/sentinel/connect-threat-intelligence-upload-api), or
- Use the Graph API. This Microsoft Graph API is [deprecated](https://learn.microsoft.com/en-us/graph/migrate-azure-ad-graph-overview) and it is recommended to use the new Upload Indicators API. To facilitate the transition period, the integration script supports both APIs.

If you were previously using the *old* integration of MISP2Sentinel via the Microsoft Graph API then take a moment before upgrading.

- The new integration has different dependencies, for example the Python libarary [misp-stix](https://github.com/MISP/misp-stix) needs to be installed;
- Your Azure App requires permissions on your workplace;
- There are changes in `config.py`. The most important changes are listed below, you can always have a look at [_init_configuration()](https://github.com/cudeso/misp2sentinel/blob/main/script.py#L145) for all the details.

| Old | New |
|-----|-----|
| graph_auth  | ms_auth (now requires a 'scope') |
| targetProduct  | ms_target_product (Graph API only) |
| action | ms_action (Graph API only) |
| passiveOnly | ms_passiveonly (Graph API only)|
| defaultConfidenceLevel | default_confidence |
| | ms_api_version (Upload indicators) |
| | ms_max_indicators_request (Upload indicators) |
| | ms_max_requests_minute (Upload indicators) |
| | misp_event_limit_per_page (Upload indicators) |
| | days_to_expire_start (Upload indicators) |
| | days_to_expire_mapping (Upload indicators) |
| | days_to_expire_ignore_misp_last_seen (Upload indicators) |
| | log_file (Upload indicators) |

### STIX instead of MISP JSON

The change in API also has an impact on how data MISP data is used. The **Graph API** version queries the MISP REST API for results in MISP JSON format, and then does post-processing on the retrieved data. The new **Upload Indicators API** of Microsoft is STIX based. The integration now relies on [MISP-STIX](https://github.com/MISP/misp-stix) a Python library to handle the conversion between MISP and STIX format. For reference, [STIX](https://stixproject.github.io/), is a structured language for describing threat information to make sharing information between systems easier.

![docs/base-MISP2Sentinel.png](docs/base-MISP2Sentinel.png)

From a functional point of view, all indicators that can be synchronised via the Graph API, can also be synchronised via the Upload Indicators API. There are some features missing in the STIX implementation of Sentinel and as a result some context information (identity, attack patterns) is lost. But it is only a matter of time before these are implemented on the Sentinel side, after which you can fully benefit from the STIX conversion.

### Sentinel Workspaces

In addition to the change to STIX, the new API also supports Sentinel **Workspaces**. This means you can send indicators to just one workspace, instead of pushing them globally. Compared to the previous version of MISP2Sentinel there also has been a clean-up of the configuration settings and the integration no longer outputs to stdout, but writes its activity in a **log file**.

## Installation

### Azure

#### Azure App registration

You need to register a new **application** in the Microsoft [Application Registration Portal](https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/RegisteredApps).

1. Sign in to the [Application Registration Portal](https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/RegisteredApps).
2. Choose **New registration**.
3. Enter an application name, and choose **Register**. The application name does not matter but pick something that's easy recognisable. ![docs/misp2sentinel_appreg1.png](/docs/misp2sentinel_appreg1.png)
4. From the overview page of your app note the **Application ID** (client) and **Directory ID** (tenant). You will need it later to complete the configuration.
5. Under **Certificates & secrets** (in the left pane), choose **New client secret** and add a description. A new secret will be displayed in the **Value** column. Copy this password. You will need it later to complete the configuration and it will not be shown again.

As a next step, you need to grant the **necessary permissions**. For the Graph API do the following:

6. Under **API permissions** (left pane), choose **Add a permission > Microsoft Graph**.
7. Under **Application Permissions**, add **ThreatIndicators.ReadWrite.OwnedBy**.
8. Then grant **consent** for the new permissions via **Grant admin consent for Standaardmap** (*Standaardmap* is replaced with your local tenant setting). Without the consent the application will not have sufficient permissions.

If you plan on using the Upload Indicators API then additionally apply these steps:

9.  Grant the Azure App **Microsoft Sentinel Contributor** permissions for the workspaces you want to connect to. Do this by accessing the workspace, then choose **Access Control (IAM)** and choose Role Assignments. Then click **Add** to add the missing the role. 
10. Also take note of the **Workspace ID**. You can get this ID by accessing the Overview page of the workspace.

#### Threat intelligence data connector

After the registration of the app it's time to add a **data connector**.

For the Graph API:

1. Go to the Sentinel workspace.
1. Under **Configuration**, **Data connectors** search for **Threat Intelligence Platforms (Preview)**. Open the connection pane and click connect.

For the Upload Indicators API:

1. Go to the Sentinel workspace.
2. Under **Configuration**, click on **Data connectors** 
3. Select **Content hub**
4. Find and select the **Threat Intelligence** solution using the list view.
5. Select the **Install/Update** button.

#### Azure Function

**Please note**: This step is optional and replaces the need for running the solution directly on the MISP-server itself, instead chosing to run the script in an Azure Function.

1. Create an app registration in the same Microsoft tenant where the Sentinel instance resides. The app requires Microsoft Sentinel Contributor assigned on the workspace.
2. Create a Keyvault in your Azure subscription
3. Add a new secret with the name "tenants" and the following value (its possible to add multiple Sentinel instances, it will loop all occurences):
```json
{"<TENANT_ID_WITH_APP>": {"id": "<APP_ID>", "secret": "<APP_SECRET>", "workspaceid": "<WORKSPACE_ID>"} }
```
4. Add a new secret with the name "mispkey" and the value of your MISP API key
5. Create an Azure Function in your Azure subscription, this needs to be a Linux based Python 3.9 function.
6. Modify config.py to your needs (event filter). 
7. Upload the code to your Azure Function. 
   * If you are using VSCode, this can be done by clicking the Azure Function folder and selecting "Deploy to Function App", provided you have the Azure Functions extension installed.
   * If using Powershell, you can upload the ZIP file using the following command: `Publish-AzWebapp -ResourceGroupName <resourcegroupname> -Name <functionappname> -ArchivePath <path to zip file> -Force`. If you want to make changes to the ZIP-file, simply send the contents of the `AzureFunction`-folder (minus any `.venv`-folder you might have created) to a ZIP-file and upload that.
   * If using AZ CLI, you can upload the ZIP file using the following command: `az functionapp deployment source config-zip --resource-group <resourcegroupname> --name <functionappname> --src <path to zip file>`.
   * You can also use the [`WEBSITE_RUN_FROM_PACKAGE`](https://learn.microsoft.com/en-us/azure/azure-functions/functions-app-settings#website_run_from_package) configuration setting, which will allow you to upload the ZIP-file to a storage account (or Github repository) and have the Azure Function run from there. This is useful if you want to use a CI/CD pipeline to deploy the Azure Function, meaning you can just update the ZIP-file and have the Azure Function automatically update.
7. Add a "New application setting" (env variable) to your Azure Function named `tenants`. Create a reference to the key vault previously created (`@Microsoft.KeyVault(SecretUri=https://<keyvaultname>.vault.azure.net/secrets/tenants/)`).
8. Do the same for the `mispkey` secret (`@Microsoft.KeyVault(SecretUri=https://<keyvaultname>.vault.azure.net/secrets/mispkey/)`)
9. Add a "New application setting" (env variable) called `mispurl` and add the URL to your MISP-server (`https://<mispurl>`)
10. Add a "New application setting" (env variable) `timerTriggerSchedule` and set it to run. If you're running against multiple tenants with a big filter, set it to run once every two hours or so. 
   * The `timerTriggerSchedule` takes a cron expression. For more information, see [Timer trigger for Azure Functions](https://learn.microsoft.com/en-us/azure/azure-functions/functions-bindings-timer?tabs=python-v2%2Cin-process&pivots=programming-language-python).
   * Run once every two hours cron expression: `0 */2 * * *`

For a more in-depth guidance, check out the [INSTALL.MD](https://github.com/cudeso/misp2sentinel/blob/main/docs/INSTALL.MD) guidance, or read [Use Update Indicators API to push Threat Intelligence from MISP to Microsoft Sentinel](https://www.infernux.no/MicrosoftSentinel-MISP2SentinelUpdate/).

### MISP

You need to obtain an API key to access the MISP API. You can do this under **Global Actions**, **My Profile** and then choose **Auth keys**. Add a new key (this key can be set to read-only, the integration does not alter MISP data).

You then need **Python3**, a Python virtual environment and PyMISP.

1. Verify you have `python3` installed on your system
2. Download the repository `git clone https://github.com/cudeso/misp2sentinel.git`
4. Go to directory `cd misp2sentinel`
3. Create a virtual environment `virtualenv sentinel` and activate the environment `source sentinel/bin/activate`
4. Install the Python dependencies `pip install -r requirements.txt` 

## Configuration

The configuration is in `config.py`. 

### Microsoft settings

First define the Microsoft authentication settings in the dictionary **ms_auth**. The `tenant` (Directory ID), `client_id` (Application client ID), and `client_secret` (secret client value) are the values you obtained when setting up the Azure App. You can then choose between the Graph API or the recommended Upload Indicators API. To use the former : set `graph_api` to True and choose as `scope` 'https://graph.microsoft.com/.default'. To use the Upload Indicators API, set `graph_api` to False, choose as `scope` 'https://management.azure.com/.default' and set the workspace ID in `workspace_id`.
  
```
ms_auth = {
    'tenant': '<tenant>',
    'client_id': '<client_id>',
    'client_secret': '<client_secret>',
    'graph_api': False,                                # Set to False to use Upload Indicators API    
    #'scope': 'https://graph.microsoft.com/.default',  # Scope for GraphAPI
    'scope': 'https://management.azure.com/.default',  # Scope for Upload Indicators API
    'workspace_id': '<workspace_id>'
}
```

Next there are settings that influence the interaction with the Microsoft Sentinel APIs and set some of the defaults.

The settings relevant for the **Graph API** are
- `ms_passiveonly = False`: Determines if the indicator should trigger an event that is visible to an end-user. 
  - When set to ‘true,’ security tools will not notify the end user that a 'hit' has occurred. This is most often treated as audit or silent mode by security products where they will simply log that a match occurred but will not perform the action. This setting no longer exists in the Upload Indicators API.
- `ms_action = 'alert` : The action to apply if the indicator is matched from within the targetProduct security tool.
  - Possible values are: unknown, allow, block, alert. This setting no longer exists in the Upload Indicators API.

The settings relevant for the **Upload Indicators API**
- `ms_api_version = "2022-07-01"`: The API version. Leave this to "2022-07-01".
- `ms_max_indicators_request = 100`: Throttling limits for the API. Maximum indicators that can be send per request. Max. 100.
- `ms_max_requests_minute = 100`: Throttling limits for the API. Maximum requests per minute. Max. 100.

```
ms_passiveonly = False              # Graph API only
ms_action = 'alert'                 # Graph API only

ms_api_version = "2022-07-01"       # Upload Indicators API version
ms_max_indicators_request = 100     # Upload Indicators API: Throttle max: 100 indicators per request
ms_max_requests_minute = 100        # Upload Indicators API: Throttle max: 100 requests per minute
```

### MISP settings

Set `misp_key` to your MISP API key and `misp_domain` to the URL of your MISP server. You can also specify if the script should validate the certificate of the misp instance with `misp_verifycert` (usually relevant for self-signed certificates)

```
misp_key = '<misp_api_key>'
misp_domain = '<misp_url>'
misp_verifycert = False
```

The dictionary `misp_event_filters` then defines which filters you want to pass on to MISP. This applies to both Graph API and Uploadd Indictors API. The suggested settings are
- `"published": 1`: Only include events that are published
- `"tags": [ "workflow:state=\"complete\""]`: Only events with the workflow state 'complete'
- `"enforceWarninglist": True`: Skip indicators that match an entry with a warninglist. This is highly recommended, but obviously also depends on if you have enable MISP warninglists.
- `"includeEventTags": True`: Include the tags from events for additional context
- `"publish_timestamp": "14d`: Include events published in the last 14 days

There's one MISP filter commonly used that does not have an impact for this integration: **to_ids**. With MISP to_ids defines if an indicator is *actionable* or not. Unfortunately the REST API only supports the to_ids filter when querying for attributes. This integration queries for events. Does this mean that indicators with to_ids set to False are uploaded? No. In the Graph API version, only attributes with to_ids set to True are used. The Upload Indicators API relies on the MISP-STIX conversion of attributes (and objects). This conversion checks for the to_ids flag for indicators, the only exception being attributes part of an object (also see [#48](https://github.com/MISP/misp-stix/issues/48)).

```
misp_event_filters = {
    "published": 1,
    "tags": [ "workflow:state=\"complete\""],
    "enforceWarninglist": True,
    "includeEventTags": True,
    "publish_timestamp": "14d",
}
```

There's one additional setting for the Upload Indicators API and that's `misp_event_limit_per_page`. This setting defines how many events per search query are processed. Use this setting to limit the memory usage of the integration.

- `misp_event_limit_per_page = 50`

### Integration settings

The remainder of the settings deal with how the integration is handled.

**Ignore local tags and network destination**

These settings only apply for the Graph API:

- `ignore_localtags = True `: When converting tags from MISP to Sentinel, ignore the MISP local tags.
- `network_ignore_direction = True`: When set to true, not only store the indicator in the "Source/Destination" field of Sentinel (`networkDestinationIPv4, networkDestinationIPv6 or networkSourceIPv4, networkSourceIPv6`), also map in the fields without network context (`networkIPv4,networkIPv6`).

```
ignore_localtags = True             # Graph API only
network_ignore_direction = True     # Graph API only
```

**Indicator confidence level**

- `default_confidence = 50`: The default confidence level of indicators. This is a value between 0 and 100 and is used by both the Graph API and Upload Indicators API. You can set a confidence level per indicator, but if you don't set one then this default value is used.
  - This value is **overridden** when an attribute is tagged with the *MISP confidence level* ([MISP taxonomy](https://www.misp-project.org/taxonomies.html#_misp)). The tag is translated to a numerical confidence value (defined in `MISP_CONFIDENCE` in `constants.py`). It's possible to have more fine-grained confidence levels by adjusting the MISP taxonomy and simply adding entries to the predicate 'confidence-level'.

![docs/Taxonomies_-_MISP.png](docs/Taxonomies_-_MISP.png)

```
default_confidence = 50             # Sentinel default confidence level of indicator
```

**Days to expire indicator**

These settings apply to both the Graph API and Upload Indicators API.

- `days_to_expire = 50`: The default number of days after which an indictor in Sentinel will expire. 

For the Graph API the date is calculated based on the timestamp when the script is executed. The expiration of indicators works slightly different for the Upload Indicators API. There are two additional settings that apply for this API:
- `days_to_expire_start = "current_date"`: Define if you want to start counting the "expiration" date (defined in `days_to_expire`) from the current date (by using the value `current_date`) or from the value specified by MISP with `valid_from`.
- `days_to_expire_mapping`: Is a dictionary mapping specific expiration dates for indicators (STIX patterns). The numerical value is in days. This value overrides `days_to_expire`.

```
days_to_expire = 50                 # Graph API and Upload Indicators
days_to_expire_start = "current_date" # Upload Indicators API only. Start counting from "valid_from" | "current_date" ; 
days_to_expire_mapping = {          # Upload indicators API only. Mapping for expiration of specific indicator types
                    "ipv4-addr": 150,
                    "ipv6-addr": 150,
                    "domain-name": 300,
                    "url": 400,
                }
```

**Script output**

This version of MISP2Sentinel writes its output to a log file (defined in `log_file`).

If you're using the Graph API you can output the POST JSON to a log file with `write_post_json = True`. A similar option exist for the Upload Indicators API. With `write_parsed_indicators = True` it will output the parsed value of the indicators to a local file.

With `verbose_log = True` you can increase the verbosity setting of the log output.

```
log_file = "/tmp/misp2sentinel.log"
write_post_json = False             # Graph API only
verbose_log = False
write_parsed_indicators = False      # Upload Indicators only
```

## Setup 

### Cron job

It is best to run the integration is from the cron of user www-data.

```
# Sentinel
00 5 * * * cd /home/misp/misp2sentinel/ ; /home/misp/misp2sentinel/venv/bin/python /home/misp/misp2sentinel/script.py
```

## Integration details

### MISP taxonomies

To make the most of the Sentinel integration you have to enable these MISP taxonomies:

- [MISP taxonomy](https://www.misp-project.org/taxonomies.html#_misp)
- [sentinel-threattype](https://www.misp-project.org/taxonomies.html#_sentinel_threattype)
- [kill-chain](https://www.misp-project.org/taxonomies.html#_kill_chain)
- [diamond-model](https://www.misp-project.org/taxonomies.html#_diamond_model) *(only used with Graph API)*

These taxonomies are used to provide additional **context** to the synchronised indicators and are strictly not necessary for the well-functioning of the integration. But they provide useful information for Sentinel users to understand what the threat is about and which follow-up actions need to be taken. 

### Attack patterns

The attack patterns ([TTPType](https://stixproject.github.io/data-model/1.2/ttp/TTPType/) and others) are *not yet implemented by Microsoft*. This means that information from Galaxies and Clusters (such as those from MITRE) added to events or attributes are included in the synchronisation. Once there is full STIX support from Microsoft these attack patterns will be imported.

### "Created by" in Sentinel

The "Created by" field refers to the UUID of the organisation that created the event in MISP. The [identity](https://stixproject.github.io/documentation/idioms/identity/) concept is not yet implemented on the Sentinel side. It is in the STIX export from MISP but as identity objects are not yet created in Sentinel, the reference is only a textual link to the MISP organisation UUID.

### Mappings

![docs/attribute-tags-demo.png](docs/attribute-tags-demo.png)

![docs/attribute-tags-demo-sentinel.png](docs/attribute-tags-demo-sentinel.png)

![docs/attribute-tags-demo-sentinel2.png](docs/attribute-tags-demo-sentinel2.png)

#### Confidence level

The numerical value from the tags of the confidence level in the ([MISP taxonomy](https://www.misp-project.org/taxonomies.html#_misp)) are translated to the indicator confidence level.

#### Sentinel threat type 

You can identify the Sentinel threat type on event and attribute level with the taxonomy [sentinal-threattype](https://www.misp-project.org/taxonomies.html#_sentinel_threattype). The Graph API translates the tags from the **sentinal-threattype** taxonomy to the [Sentinel](https://learn.microsoft.com/en-us/graph/api/resources/tiindicator?view=graph-rest-beta#threattype-values) values for `threattype`. In STIX (and thus also for the Upload Indicators API) there is no sentinal-threattype. In this case the integration translates the indicators to [indicator_types](https://stixproject.github.io/data-model/1.2/indicator/IndicatorType/), which the Sentinel interface then represents under Threat type.

#### Kill Chain

The [Kill Chain tags](https://www.misp-project.org/taxonomies.html#_kill_chain) are translated by the Graph API to the [Kill Chain values of Microsoft](https://learn.microsoft.com/en-us/graph/api/resources/tiindicator?view=graph-rest-beta#killchain-values). Note that Sentinel uses C2 and Actions instead of "Command and Control" and "Actions on Objectives". The Upload Indicators API translates them to the [STIX](https://stixproject.github.io/documentation/idioms/kill-chain/) Kill Chain entities. In addition, the integration for the Upload Indicators API will also translate the MISP category into a Kill Chain.

#### TLP

The TLP (Traffic Light Protocol) tags of an event and attribute are translated to the STIX markers. If there's a TLP set on the attribute level then this takes precedence. If no TLP is set (on event or attribute), then **tlp-white** is applied (set via `SENTINEL_DEFAULT_TLP`.)

#### Diamond model

The Graph API translates the tags from the **diamond-model** taxonomy to [Sentinel](https://learn.microsoft.com/en-us/graph/api/resources/tiindicator?view=graph-rest-beta#diamondmodel-values). properties for `diamondModel`. The Diamond model is not used by the Upload Indicators API.

#### Threat actors

The Graph API translates the MISP attributes **threat-actor** to Sentinel properties for `activityGroupNames`. The MISP attributes **comment** are added to the Sentinel `description`. This is not used by the Upload Indicators API. Future versions of the Microsoft API will support attack patterns etc.

#### Ignored types

Only indicaotrs of type `stix` are used, as such the attributes of type `yara` or `sigma` are not synchronised.

#### Expiration date

For the Upload Indicators API:
- If the attribute type is in `days_to_expire_mapping`, use the days defined in the mapping
- If the there is no mapping, then use the default `days_to_expire`
- Start counting from today if `days_to_expire_start` is "current_date" (or from the "valid_from" time)
- If the end count date is beyond the date set in "valid_until", then discard the indicator

The `valid_until` value is set in MISP with the `last_seen` of an attribute. Depending on your use case you might want to ignore the `last_seen` of an attribute, and consequently ignore the  `valid_until` value. Do this by setting the configuration option `days_to_expire_ignore_misp_last_seen` to True.

```
days_to_expire_ignore_misp_last_seen = True
```

#### Attribute mapping

The attribute type matchings are defined in `constants.py`. 

```
ATTR_MAPPING = {
    'AS': 'networkSourceAsn',
    'email-dst': 'emailRecipient',
    'email-src-display-name': 'emailSenderName',
    'email-subject': 'emailSubject',
    'email-x-mailer': 'emailXMailer',
    'filename': 'fileName',
    'malware-type': 'malwareFamilyNames',
    'mutex': 'fileMutexName',
    'port': 'networkPort',
    'published': 'isActive',
    'size-in-bytes': 'fileSize',
    'url': 'url',
    'user-agent': 'userAgent',
    'uuid': 'externalId',
    'domain': 'domainName',
    'hostname': 'domainName'
}
```

There are also special cases covered in other sections of the Python code.

```
MISP_SPECIAL_CASE_TYPES = frozenset([
    *MISP_HASH_TYPES,
    'url',
    'ip-dst',
    'ip-src',
    'domain|ip',
    'email-src',
    'ip-dst|port',
    'ip-src|port'
])
```

- ip-dst and ip-src
- - mapped to either `networkDestinationIPv4`, `networkDestinationIPv6` or `networkSourceIPv4`, `networkSourceIPv6`
- - if the configuration value `network_ignore_direction` is set to true then the indicator is also mapped to `networkIPv4`,`networkIPv6`
- domain|IP
- - Mapped to a domain and an IP `domainName`
- - An IP without a specification of a direction `networkIPv4`, `networkIPv6`
- email-src
- - Mapped to a sender address `emailSenderAddress`
- - And to a source domain `emailSourceDomain`
- ip-dst|port and ip-src|port
- - apped to either `networkDestinationIPv4`, `networkDestinationIPv6` or `networkSourceIPv4`, `networkSourceIPv6`
- - if the configuration value `network_ignore_direction` is set to true then the indicator is also mapped to `networkIPv4`, `networkIPv6`
- - The port is mapped to `networkSourcePort`, `networkDestinationPort`
- - if the configuration value `network_ignore_direction` is set to true then the indicator is also mapped to `networkPort`
- url
- - MISP URL values that do not start with http or https or changed to start with http. Azure does not accept URLs that do not start with http

The supported hashes are defined in the set `MISP_HASH_TYPES`.

## FAQ

### I don't see my indicator in Sentinel

- Is the event published?
- Is the to_ids flag set to True?
- Is the indicator stored in a valid attribute type (`UPLOAD_INDICATOR_MISP_ACCEPTED_TYPES`)?

## Additional documentation

* [https://www.vanimpe.eu/2022/04/20/misp-and-microsoft-sentinel/](https://www.vanimpe.eu/2022/04/20/misp-and-microsoft-sentinel/)
* [https://techcommunity.microsoft.com/t5/microsoft-sentinel-blog/integrating-open-source-threat-feeds-with-misp-and-sentinel/ba-p/1350371](https://techcommunity.microsoft.com/t5/microsoft-sentinel-blog/integrating-open-source-threat-feeds-with-misp-and-sentinel/ba-p/1350371)
* https://learn.microsoft.com/en-us/graph/api/tiindicators-list?view=graph-rest-beta&tabs=http
* [Microsoft Graph Security Documentation](https://developer.microsoft.com/en-us/graph/docs/concepts/security-concept-overview)
* [Microsoft Graph Explorer](https://developer.microsoft.com/en-us/graph/graph-explorer)
* [https://github.com/cudeso/misp2sentinel/blob/main/docs/INSTALL.MD](https://github.com/cudeso/misp2sentinel/blob/main/docs/INSTALL.MD)
* [https://www.infernux.no/MicrosoftSentinel-MISP2SentinelUpdate/](https://www.infernux.no/MicrosoftSentinel-MISP2SentinelUpdate/)
* [Microsoft code samples](https://developer.microsoft.com/en-us/graph/code-samples-and-sdks)
* [MISP to Microsoft Graph Security connector](https://www.circl.lu/doc/misp/connectors/#misp-to-microsoft-graph-security-script)
