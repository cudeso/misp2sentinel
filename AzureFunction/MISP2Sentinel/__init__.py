from pymisp import PyMISP
from pymisp import ExpandedPyMISP
import MISP2Sentinel.config as config
from collections import defaultdict
from MISP2Sentinel.RequestManager import RequestManager
from MISP2Sentinel.RequestObject import RequestObject, RequestObject_Event, RequestObject_Indicator
from MISP2Sentinel.constants import *
import sys
from functools import reduce
import os
import datetime
import logging
import azure.functions as func
import requests
import json

if config.misp_verifycert is False:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def _get_misp_events_stix():
    misp = ExpandedPyMISP(config.misp_domain, config.misp_key, config.misp_verifycert, False)
    result_set = []
    logging.info("Query MISP for events and return them in stix2 format.")
    remaining_misp_pages = True
    misp_page = 1
    misp_indicator_ids = []

    while remaining_misp_pages:
        try:
            # Avoid adding twice the "limit", as this would break pagination requests
            if "limit" in config.misp_event_filters:
                result = misp.search(controller='events', return_format='stix2', **config.misp_event_filters)
            else:
                result = misp.search(controller='events', return_format='stix2', **config.misp_event_filters, limit=config.misp_event_limit_per_page, page=misp_page)

            if result.get("objects", False):
                logging.info("Received MISP events page {}".format(misp_page))
                stix2_objects = result.get("objects")
                #print(stix2_objects)

                misp_event = False
                logging.info("Received {} objects".format(len(stix2_objects)))
                for element in stix2_objects:       # Extract event information
                    if element.get("type", False) == "report":
                        misp_event = RequestObject_Event(element)

                # If there's no event in the returned STIX package then something went wrong
                if not misp_event:
                    logging.debug("No MISP event in the returned STIX package. Skipping indicators.")
                else:
                    for element in stix2_objects:
                        if element.get("type", False) in UPLOAD_INDICATOR_API_ACCEPTED_TYPES and \
                                element.get("id") not in misp_indicator_ids:
                            misp_indicator = RequestObject_Indicator(element, misp_event)
                            if not misp_indicator.indicator:
                                logging.debug("Unable to process indicator {}".format(element["id"]))
                            else:
                                element["labels"] = misp_indicator.labels
                                element["description"] = misp_indicator.description
                                element["confidence"] = misp_indicator.confidence
                                element["object_marking_refs"] = misp_indicator.object_marking_refs
                                element["name"] = misp_indicator.name
                                element["indicator_types"] = misp_indicator.indicator_types
                                element["kill_chain_phases"] = misp_indicator.kill_chain_phases
                                element["external_references"] = misp_indicator.external_references
                                element["valid_until"] = misp_indicator.valid_until
                                element["valid_from"] = misp_indicator.valid_from

                                if misp_indicator.valid_until:
                                    date_object = datetime.fromisoformat(misp_indicator.valid_until[:-1])
                                    if date_object > datetime.now():
                                        if config.verbose_log:
                                            logging.debug("Add {} to list of indicators to upload".format(element.get("pattern")))
                                        misp_indicator_ids.append(element.get("id"))
                                        result_set.append(element)
                                    else:
                                        logging.error("Skipping outdated indicator {}".format(element.get("id")))
                                else:
                                    logging.error("Skipping indicator because valid_until was not set by MISP/MISP2Sentinel {}".format(element.get("id")))

                logging.info("Processed {} indicators.".format(len(result_set)))

                misp_page += 1

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
    parsed_indicators, total_indicators = _get_misp_events_stix()
    logging.info("Found {} indicators in MISP".format(total_indicators))

    with RequestManager(total_indicators, tenant) as request_manager:
        request_manager.upload_indicators(parsed_indicators)

def pmain():
    tenants = json.loads(os.getenv('tenants'))
    for key, value in tenants.items():
        push_to_sentinel(key, value['id'], value['secret'], value['workspaceid'])

def main(mytimer: func.TimerRequest) -> None:
    utc_timestamp = datetime.datetime.utcnow().replace(
        tzinfo=datetime.timezone.utc).isoformat()

    if mytimer.past_due:
        logging.info('The timer is past due!')

    logging.info("Start MISP2Sentinel")
    pmain()
    logging.info("End MISP2Sentinel")
    logging.info('Python timer trigger function ran at %s', utc_timestamp)