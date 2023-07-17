- [MISP to Microsoft Sentinel integration](#misp-to-microsoft-sentinel-integration)
  - [To do:](#to-do)
  - [Introduction](#introduction)
  - [Upload Indicators API and Graph API](#upload-indicators-api-and-graph-api)
  - [Installation](#installation)
    - [Azure](#azure)
      - [Azure App registration](#azure-app-registration)
      - [Threat intelligence data connector](#threat-intelligence-data-connector)
    - [MISP](#misp)
  - [Configuration](#configuration)
    - [Microsoft settings](#microsoft-settings)
    - [MISP settings](#misp-settings)
    - [Integration settings](#integration-settings)
  - [Integration details](#integration-details)
    - [Upload Indicators API, MISP to STIX and errors 'An Internal Error Has Occurred'](#upload-indicators-api-misp-to-stix-and-errors-an-internal-error-has-occurred)
    - [Attack patterns](#attack-patterns)
    - ["Created by" in Sentinel](#created-by-in-sentinel)
    - [Mappings](#mappings)
  - [Cron job](#cron-job)
    - [MISP configuration](#misp-configuration)
  - [Additional documentation](#additional-documentation)

# MISP to Microsoft Sentinel integration

## To do:

- Document changes to indicators in RequestObject when dealing with STIX


## Introduction

The MISP to Microsoft Sentinel integration allows you to upload indicators from MISP to Microsoft Sentinel. It relies on **PyMISP** to get indicators from MISP and an **Azure App** to connect to Sentinel. 

## Upload Indicators API and Graph API

The integration supports two methods for sending threat intelligence from MISP to Microsoft Sentinel:

- Use the [Upload Indicators API](https://learn.microsoft.com/en-us/azure/sentinel/connect-threat-intelligence-upload-api), or
- Use the Graph API. This Microsoft Graph API is [deprecated](https://learn.microsoft.com/en-us/graph/migrate-azure-ad-graph-overview) and it is recommended to use the new Upload Indicators API. To facilitate the transition period, the integration script supports both APIs.

The change in API also has an impact on how data MISP data is queried. The Graph API version queries the MISP REST API for results in MISP JSON format, and then does some post-processing on the retrieved data. The new Upload Indicators API of Microsoft is STIX based. Instead of MISP JSON the integration script now relies on [MISP-STIX](https://github.com/MISP/misp-stix), a Python library to handle the conversion between MISP and STIX formats. For reference, [STIX](https://stixproject.github.io/), is a structured language for describing threat information to make sharing information between systems easier.

![docs/base-MISP2Sentinel.png](docs/base-MISP2Sentinel.png)

From a functional point of view, all indicators that can be synchronised via the Graph API, can also be synchronised via the Upload Indicators API. There are some features missing in the STIX implementation of Sentinel and as a result some context information (identity, attack patterns) is lost. But it is only a matter of time before these are implemented on the Sentinel side, after which you can fully benefit from the STIX conversion.

In addition to the change to STIX, the new API also supports Sentinel **Workspaces**. This means you can send indicators to just one workspace, instead of pushing them globally. Compared to the previous version of MISP2Sentinel there also has been a clean-up of the configuration settings and the integration no longer outputs to stdout, but writes its activity in a log file.

## Installation

### Azure

#### Azure App registration

You need to register a new **application** in the Microsoft [Application Registration Portal](https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/RegisteredApps).

1. Sign in to the [Application Registration Portal](https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/RegisteredApps).
2. Choose **New registration**.
3. Enter an application name, and choose **Register**. The application name does not matter but pick something that's easy recognisable. ![docs/misp2sentinel_appreg1.png](/docs/misp2sentinel_appreg1.png)
4. From the overview page of your app note the **Application ID** (client) and **Directory ID** (tenant). You will need it later to complete the configuration.
5. Under **Certificates & secrets** (in the left pane), choose **New client secret** and add a description. A new secret will be displayed in the **Value** column. Copy this password. You will need it later to complete the configuration and it will not be shown again.
6. Under **API permissions** (left pane), choose **Add a permission > Microsoft Graph**.
7. Under **Application Permissions**, add **ThreatIndicators.ReadWrite.OwnedBy**.
8. Then grant **consent** for the new permissions via **Grant admin consent for Standaardmap** (*Standaardmap* is replaced with your local tenant setting). Without the consent the application will not have sufficient permissions.
9. Grant the Azure App **Microsoft Sentinel Contributor** permissions for the workspaces you want to connect to. To this by accessing the workspace, then choose **Access Control (IAM)** and choose Role Assignments. Then click **Add** to add the missing the role. 
10. Note the **Workspace ID**. You can get this ID by accessing the Overview page of the workspace.

#### Threat intelligence data connector

After the registration of the app it's time to add a **data connector**.

1. Go to the Sentinel workspace.
1. Under **Data connectors** search for **Threat Intelligence Platforms (Preview)**. Open the connection pane and click connect.
   - For the Upload Indicators API: add the **Threat Intelligence Upload Indicators API** data connector. Also see the guidance at https://learn.microsoft.com/en-us/azure/sentinel/connect-threat-intelligence-upload-api

### MISP

You need to obtain an API key to access the MISP REST API. You can do this under **Global Actions**, **My Profile** and then choose **Auth keys**. Add a new key (this key can be set to read-only, the integration does not alter MISP data).

You then need **Python3**, a Python virtual environment and PyMISP.

1. Verify you have `python3` installed on your system
2. Create a virtual environment `virtualenv sentinel` and activate the environment `source sentinel/bin/activate`
3. Download the repository `git clone https://github.com/cudeso/misp2sentinel.git`
4. Go to directory `cd misp2sentinel`
5. Install the Python dependencies `pip install -r requirements.txt` 

## Configuration

The **configuration** is in `config.py`. 

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

Next there are settings that influence the interaction with the API and set some of the defaults.

The settings only relevant for the **Graph API** are
- `ms_passiveonly = False`: Determines if the indicator should trigger an event that is visible to an end-user. When set to ‘true,’ security tools will not notify the end user that a ‘hit’ has occurred. This is most often treated as audit or silent mode by security products where they will simply log that a match occurred but will not perform the action. This setting no longer exists in the Upload Indicators API.
- `ms_action = 'alert` : The action to apply if the indicator is matched from within the targetProduct security tool. Possible values are: unknown, allow, block, alert. This setting no longer exists in the Upload Indicators API.

Then there are settings relevant for the **Upload Indicators API**
- `ms_api_version = "2022-07-01"`: The API version. Leave this to "2022-07-01" for the time being.
- `ms_max_indicators_request = 100`: Throttling limits for the API. Maximum indicators that can be send per request. Max. 100.
- `ms_max_requests_minute = 100`: Throttling limits for the API. Maximum requests per minute. Max. 100.

```
ms_passiveonly = False              # Graph API only
ms_action = 'alert'                 # Graph API only

ms_api_version = "2022-07-01"       # Upload Indicators API version
ms_max_indicators_request = 100     # Throttle max: 100 indicators per request
ms_max_requests_minute = 100        # Throttle max: 100 requests per minute
```

### MISP settings

Set `misp_key` to your MISP API key and `misp_domain` to the URL of your MISP server. Optionally you can also specify if the script should validate the certificate of the misp instance with `misp_verifycert`. 

```
misp_key = '<misp_api_key>'
misp_domain = '<misp_url>'
misp_verifycert = False
```

The dictionary `misp_event_filters` then defines which filters you want to pass on to MISP. Some of the suggested settings are
- `"published": 1`: Only include events that are published
- `"tags": [ "workflow:state=\"complete\""]`: Only events with the workflow state 'complete'
- `"to_ids": 1`: Only indicators that are marked as 'actionable'
- `"enforceWarninglist": True`: Skip indicators that match an entry with a warninglist
- `"includeEventTags": True`: Include the tags from events for additional context

```
misp_event_filters = {
    "published": 1,
    "tags": [ "workflow:state=\"complete\""],
    "to_ids": 1,
    "enforceWarninglist": True,
    "includeEventTags": True,    
}
```

Then specify how many events the MISP-STIX convertor can process. This is dependant on the amount of memory that you have available on the MISP server. The MISP-STIX runs as a separate process on your MISP server and setting this to a value to high can cause out-of-memory errors. If you have very large events, then it's advised to lower the limit. As you can guess from the link with the STIX convertor, this setting is only relevant for the Upload Indicators API.

- `misp_event_limit_per_page = 50`

### Integration settings

The remainder of the configuration file includes settings that deal with how the integration is handled.

**Ignore local tags and network destination (Graph API)**

- `ignore_localtags = True `: When converting tags from MISP to Sentinel, ignore the MISP local tags. Only applies to the Graph API.
- `network_ignore_direction = True`: When set to true, not only store the indicator in the "Source/Destination" field of Sentinel (`networkDestinationIPv4, networkDestinationIPv6 or networkSourceIPv4, networkSourceIPv6`), also map in the fields without network context (`networkIPv4,networkIPv6`). Only applies to the Graph API.

**Indicator confidence level**

- `default_confidence = 50`: The default confidence level of indicators. This is a value between 0 and 100 and is used by both the Graph API and Upload Indicators API. This value is **overridden** when the indicator is tagged with the *MISP confidence level* (see: [MISP taxonomy](https://www.misp-project.org/taxonomies.html#_misp) ) or `misp:confidence-level`. The tag is translated to a numerical confidence value (defined in `MISP_CONFIDENCE` in `constants.py`). It's possible to have more fine-grained confidence levels by adjusting the MISP taxonomy and simply adding entries to the predicate 'confidence-level'.
![docs/Taxonomies_-_MISP.png](docs/Taxonomies_-_MISP.png)

**Days to expire indicator**

The next settings apply to both the Graph API and Upload Indicators API.

- `days_to_expire = 50`: Are the default number of days after which an indictor in Sentinel will expire. For the Graph API the date is calculated based on the timestamp when the script is executed.

The expiration of indicators works slightly different for the Upload Indicators API.
- `days_to_expire_start = "current_date"`: Define if you want to start counting the "expiration" date (defined in `days_to_expire`) from the current date (with value `current_date`) or from the specified by MISP with `valid_from`.
- `days_to_expire_mapping`: Is a dictionary mapping specific expiration dates for indicators (STIX patterns). The numerical value is in days. This value overrides the default `days_to_expire`.

**Script output**

This version of MISP2Sentinel writes its output to a log file. You can specify this log file in 
- `log_file = "/tmp/misp2sentinel.log"`

If you're using the Graph API you can output the POST JSON to a log file with `write_post_json = True`. A similar option exist for the Upload Indicators API. With `write_parsed_indicators = True` it will output the parsed value of the indicators to a local file.

And finally, with `verbose_log = True` you can increase the verbosity setting of the log output.

```
ignore_localtags = True             # Graph API only
network_ignore_direction = True     # Graph API only

default_confidence = 50             # Sentinel default confidence level of indicator

days_to_expire = 50                 # Graph API and Upload Indicators
days_to_expire_start = "current_date" # Upload Indicators API only. Start counting from "valid_from" | "current_date" ; 
days_to_expire_mapping = {          # Upload indicators API only. Mapping for expiration of specific indicator types
                    "ipv4-addr": 150,
                    "ipv6-addr": 150,
                    "domain-name": 300,
                    "url": 400,
                }

log_file = "/tmp/misp2sentinel.log"
write_post_json = False             # Graph API only
verbose_log = False
write_parsed_indicators = False      # Upload Indicators only
```

## Integration details

### Upload Indicators API, MISP to STIX and errors 'An Internal Error Has Occurred'

The Upload Indicators API uses STIX. Instead of re-inventing the wheel, the integration for the Upload Indicators API uses the [MISP-STIX](https://github.com/MISP/misp-stix) conversion. This conversion does the heavy lifting of translating data in MISP, to data in STIX format, which is then usable by Sentinel. And although not all STIX objects are implemented by Microsoft (Sentinel-side), this will provide easier integration in the future. 

There is one issue with the MISP-STIX integration though. MISP-STIX relies on Python scripts to do the conversion, and this conversion can consume a substantial amount of memory. Hence the setting `misp_event_limit_per_page`, which is used in combination with the **pagination** option in MISP to query for event data. Unfortunately, it's not possible to know the total number of search results (pages) returned by MISP. The only approach for now is querying MISP for the "next page with result", and catch the error if there are no pages left.

```
Unknown error: the response is not in JSON.
Something is broken server-side, please send us everything that follows (careful with the auth key):

...

Response (if any):
{"name":"An Internal Error Has Occurred.","message":"An Internal Error Has Occurred.","url":"\/events\/restSearch"}
```

### Attack patterns

The attack patterns ([TTPType](https://stixproject.github.io/data-model/1.2/ttp/TTPType/) and others) are *not implemented by Microsoft*. This also means that information galaxies/clusters (such as those from MITRE) that you add to a threat event or attribute or not translated to Sentinel. Once there is full STIX support from Microsoft these attack patterns can also be imported.

### "Created by" in Sentinel

The "Created by" field refers to the UUID of the organisation that created the event in MISP. The [identity](https://stixproject.github.io/documentation/idioms/identity/) concept is not yet implemented on the Sentinel side. It is included in the STIX export from MISP but as identity objects are not created in Sentinel, the reference is only a textual link to the MISP organisation UUID.


### Mappings

Tags from the **diamond-model** taxonomy are set to the Sentinel properties for `diamondModel`. See for the different values at [https://learn.microsoft.com/en-us/graph/api/resources/tiindicator?view=graph-rest-beta#diamondmodel-values](https://learn.microsoft.com/en-us/graph/api/resources/tiindicator?view=graph-rest-beta#diamondmodel-values).

Tags from the **sentinal-threattype** taxonomy are set to the Sentinel properties for `threattype`. See for the different values at [https://learn.microsoft.com/en-us/graph/api/resources/tiindicator?view=graph-rest-beta#threattype-values](https://learn.microsoft.com/en-us/graph/api/resources/tiindicator?view=graph-rest-beta#threattype-values).

Tags from the **kill-chain** taxonomy are set to the Sentinel properties for `killChain`. See for the different values at [https://learn.microsoft.com/en-us/graph/api/resources/tiindicator?view=graph-rest-beta#killchain-values](https://learn.microsoft.com/en-us/graph/api/resources/tiindicator?view=graph-rest-beta#killchain-values). Note that Sentinel uses C2 and Actions instead of "Command and Control" and "Actions on Objectives". The import script takes care of the translation.

Tags from the MISP attribute level take precedence on the tags from the MISP event level. 

The MISP attributes **threat-actor** are set to Sentinel property `activityGroupNames`. The MISP attributes **comment** are added to the Sentinel `description`.

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

Further details on the specifics of the indicators can be found on the Azure Sentinel website.

## Cron job

It is best to run the integration is from the cron of user www-data.

```
# Sentinel
00 5 * * * cd /home/misp/misp2sentinel/ ; /home/misp/misp2sentinel/venv/bin/python /home/misp/misp2sentinel/script.py
```

### MISP configuration

To make the most of the Sentinel integration you have to enable these MISP taxonomies:

- [MISP taxonomy](https://www.misp-project.org/taxonomies.html#_misp)
- [sentinel-threattype](https://www.misp-project.org/taxonomies.html#_sentinel_threattype)
- [kill-chain](https://www.misp-project.org/taxonomies.html#_kill_chain)  *(currently only used with Graph API)*
- [diamond-model](https://www.misp-project.org/taxonomies.html#_diamond_model) *(currently only used with Graph API)*

These taxonomies are used to provide additional **context** to the synchronised indicators and are strictly not necessary for the well-functioning of the integration. But they provide useful information for Sentinel users to understand what the threat is about and which follow-up actions need to be taken. 


## Additional documentation

* [https://www.vanimpe.eu/2022/04/20/misp-and-microsoft-sentinel/](https://www.vanimpe.eu/2022/04/20/misp-and-microsoft-sentinel/)
* [https://techcommunity.microsoft.com/t5/microsoft-sentinel-blog/integrating-open-source-threat-feeds-with-misp-and-sentinel/ba-p/1350371](https://techcommunity.microsoft.com/t5/microsoft-sentinel-blog/integrating-open-source-threat-feeds-with-misp-and-sentinel/ba-p/1350371)
* https://learn.microsoft.com/en-us/graph/api/tiindicators-list?view=graph-rest-beta&tabs=http
* [Microsoft Graph Security Documentation](https://developer.microsoft.com/en-us/graph/docs/concepts/security-concept-overview)
* [Microsoft Graph Explorer](https://developer.microsoft.com/en-us/graph/graph-explorer)
* [Microsoft code samples](https://developer.microsoft.com/en-us/graph/code-samples-and-sdks)
* [MISP to Microsoft Graph Security connector](https://www.circl.lu/doc/misp/connectors/#misp-to-microsoft-graph-security-script)


