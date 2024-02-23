import os

from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential

mispkey = ''
mispurl=os.getenv('mispurl')

local_mode=os.getenv('local_mode', 'False')
keyVaultName=os.getenv('key_vault_name', '')

tenant_id=os.getenv('tenant_id', '')
workspace_id=os.getenv('workspace_id', '')
client_id=os.getenv('client_id', '')
client_secret=os.getenv('client_secret', '')

# MS API settings
ms_auth = {
    'tenant': tenant_id,
    'client_id': client_id,
    'client_secret': client_secret,
    'scope': 'https://management.azure.com/.default',
    'graph_api': False,
    'workspace_id': workspace_id
}

## If Azure Key Vault name variable is set, use it for secret values
if not len(keyVaultName) == 0:
    # Key vault section
    # Key Vault name must be a globally unique DNS name
    
    KVUri = f"https://{keyVaultName}.vault.azure.net"
    
    # Log in with the virtual machines managed identity
    credential = DefaultAzureCredential()
    client = SecretClient(vault_url=KVUri, credential=credential)
    
    # Retrieve values from KV (client secret, MISP-key most importantly)
    retrieved_mispkey = client.get_secret('MISP-Key')
    retrieved_clientsecret = client.get_secret('ClientSecret')
    
    # Set values with 
    mispkey = retrieved_mispkey.value
    ms_auth['client_secret'] = retrieved_clientsecret

mispkey=os.getenv('mispkey')

#####################
# Microsoft Section #
#####################

ms_max_indicators_request = 100     # Throttle max: 100 indicators per request
ms_max_requests_minute = 100        # Throttle max: 100 requests per minute
ms_useragent = 'MISP-1.0'
ms_target_product = 'Azure Sentinel'    # targetProduct
ms_api_version = "2022-07-01"       # Upload Indicators API version

# Graph API only settings
ms_passiveonly = False                  # passiveOnly
ms_action = 'alert'                     # action

################
# MISP Section #
################

# MISP API settings
misp_key = mispkey
misp_domain = mispurl
misp_verifycert = False

if(not bool(local_mode)):
    misp_verifycert = True

# MISP Event filters
misp_event_filters = {
    "timestamp": "14d",
    "enforceWarninglist": True,
    "includeEventTags": True
}

# MISP pagination settings
misp_event_limit_per_page = 100      # Limit memory use when querying MISP for STIX packages

########################
# Integration settings #
########################

log_file = "/tmp/misp2sentinel.log"
verbose_log = False
write_parsed_indicators = False      # Upload Indicators only

# Graph API only settings
ignore_localtags = True 
network_ignore_direction = True
write_post_json = False 


# IOC settings
default_confidence = 50
days_to_expire = 30
days_to_expire_start = "current_date" # Upload Indicators API only. Start counting from "valid_from" | "current_date" ; 
days_to_expire_mapping = {          # Upload indicators API only. Mapping for expiration of specific indicator types
                        "ipv4-addr": 150,
                        "ipv6-addr": 150,
                        "domain-name": 300,
                        "url": 400
                    }
