import os
mispkey=os.getenv('mispkey')
mispurl=os.getenv('mispurl')

ms_auth = {
    'tenant': '',
    'client_id': '',
    'client_secret': '',
    'scope': 'https://management.azure.com/.default',
    'graph_api': False,
    'workspace_id': ''
}
ms_max_indicators_request = 100     # Throttle max: 100 indicators per request
ms_max_requests_minute = 100        # Throttle max: 100 requests per minute
ms_useragent = 'MISP-1.0'
ms_target_product = 'Azure Sentinel'    # targetProduct
ms_passiveonly = False                  # passiveOnly
ms_action = 'alert'                     # action

misp_event_filters = {
    "timestamp": "1d"
}

misp_key = mispkey
misp_domain = mispurl
misp_verifycert = False
misp_event_limit_per_page = 50      # Limit memory use when querying MISP for STIX packages

days_to_expire = 30
network_ignore_direction = True
verbose_log = True
write_post_json = False
misp_ignore_localtags = True
default_confidence = 50
