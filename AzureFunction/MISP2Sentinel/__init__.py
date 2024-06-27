from pymisp import PyMISP
import MISP2Sentinel.config as config
from collections import defaultdict
from MISP2Sentinel.RequestManager import RequestManager
from MISP2Sentinel.RequestObject import RequestObject, RequestObject_Event, RequestObject_Indicator
from MISP2Sentinel.constants import *
import sys
from functools import reduce
import os
import datetime
from datetime import datetime, timedelta, timezone
import logging
import azure.functions as func
import requests
import json
from misp_stix_converter import MISPtoSTIX21Parser
from stix2.base import STIXJSONEncoder

if config.misp_verifycert is False:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def _get_misp_events_stix():
    logging.info(f"Using the following values for MISP API call: domain: {config.misp_domain}, misp API key: {config.misp_key[:-5] + '*' + '*' + '*' + '*' + '*'}...")
    misp = PyMISP(config.misp_domain, config.misp_key, config.misp_verifycert, False)
    result_set = []
    logging.debug("Query MISP for events.")
    remaining_misp_pages = True
    misp_page = 1
    misp_indicator_ids = []

    while remaining_misp_pages:
        try:
            if "limit" in config.misp_event_filters:
                result = misp.search(controller='events', return_format='json', **config.misp_event_filters)
            else:
                result = misp.search(controller='events', return_format='json', **config.misp_event_filters, limit=config.misp_event_limit_per_page, page=misp_page)

            if len(result) > 0:
                logging.info("Received MISP events page {} with {} events".format(misp_page, len(result)))
                for event in result:
                    misp_event = RequestObject_Event(event["Event"])
                    parser = MISPtoSTIX21Parser()
                    parser.parse_misp_event(event)
                    stix_objects = parser.stix_objects
                    for element in stix_objects:
                        if element.type in UPLOAD_INDICATOR_API_ACCEPTED_TYPES and \
                                        element.id not in misp_indicator_ids:
                            misp_indicator = RequestObject_Indicator(element, misp_event)
                            if misp_indicator.id:
                                if misp_indicator.valid_until:
                                    valid_until = json.dumps(misp_indicator.valid_until, cls=STIXJSONEncoder).replace("\"", "")
                                    if "Z" in valid_until:
                                        date_object = datetime.fromisoformat(valid_until[:-1])
                                    elif "." in valid_until:
                                        date_object = datetime.fromisoformat(valid_until.split(".")[0])
                                    else:
                                        date_object = datetime.fromisoformat(valid_until)
                                    if date_object > datetime.now():
                                        if config.verbose_log:
                                            logging.debug("Add {} to list of indicators to upload".format(misp_indicator.pattern))
                                        misp_indicator_ids.append(misp_indicator.id)
                                        result_set.append(misp_indicator._get_dict())
                                    else:
                                        logging.error("Skipping outdated indicator {}, valid_until: {}".format(misp_indicator.pattern, valid_until))
                                else:
                                    logging.error("Skipping indicator because valid_until was not set by MISP/MISP2Sentinel {}".format(misp_indicator.id))
                            else:
                                logging.error("Unable to process indicator")
                logging.debug("Processed {} indicators.".format(len(result_set)))
                misp_page += 1
            else:
                remaining_misp_pages = False

        except Exception as e:
            remaining_misp_pages = False
            logging.error("Error when processing data from MISP {}".format(e))

    return result_set, len(result_set)

def push_to_sentinel(tenant, id, secret, workspace):
    logging.info(f"Using Microsoft Upload Indicator API")
    config.ms_auth[TENANT] = tenant
    config.ms_auth[CLIENT_ID] = id
    config.ms_auth[CLIENT_SECRET] = secret
    config.ms_auth[WORKSPACE_ID] = workspace
    logging.info(f"Tenant: {tenant}")
    logging.info(f"Client ID: {id}")
    logging.info(f"Workspace ID: {workspace}")
    obfuscated_secret = secret[:-5] + '*' + '*' + '*' + '*' + '*'
    logging.info(f"Client Secret (obfuscated): {obfuscated_secret}")
    parsed_indicators, total_indicators = _get_misp_events_stix()
    logging.info("Found {} indicators in MISP".format(total_indicators))

    with RequestManager(total_indicators, tenant) as request_manager:
        logging.info("Start uploading indicators")
        request_manager.upload_indicators(parsed_indicators)
        logging.info("Finished uploading indicators")
        if config.write_parsed_indicators:
            json_formatted_str = json.dumps(parsed_indicators, indent=4)
            with open("parsed_indicators.txt", "w") as fp:
                fp.write(json_formatted_str)

def pmain():
    ## Multi-tenant mode
    tenants_env = os.getenv('tenants', '')
    if not tenants_env == '':
        tenants = json.loads(tenants_env)
        for item in tenants:
            push_to_sentinel(item['tenantId'], item['id'], item['secret'], item['workspaceId'])
    
    # Single-tenant mode
    tenant = config.ms_auth[TENANT]
    id = config.ms_auth[CLIENT_ID]
    secret = config.ms_auth[CLIENT_SECRET]
    workspace = config.ms_auth[WORKSPACE_ID]
    push_to_sentinel(tenant, id, secret, workspace)

def main(mytimer: func.TimerRequest) -> None:
    utc_timestamp = datetime.utcnow().replace(
        tzinfo=timezone.utc).isoformat()

    if mytimer.past_due:
        logging.info('The timer is past due!')

    logging.info("Start MISP2Sentinel")
    pmain()
    logging.info("End MISP2Sentinel")
    logging.info('Python timer trigger function ran at %s', utc_timestamp)

