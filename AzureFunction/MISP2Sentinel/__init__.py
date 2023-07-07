from pymisp import PyMISP
from pymisp import ExpandedPyMISP
import MISP2Sentinel.config as config
from collections import defaultdict
from MISP2Sentinel.RequestManager import RequestManager
from MISP2Sentinel.RequestObject import RequestObject
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
    logging.debug("Query MISP for events and return them in stix2 format.")
    remaining_misp_pages = True
    misp_page = 0
    empty_event = {"info": "Unknown MISP event", "uuid": "", "tags": [], "tlp": False}
    misp_tags_ignore = ["Threat-Report", "misp:tool=\"MISP-STIX-Converter\""]
    misp_indicator_ids = []

    while remaining_misp_pages:
        misp_reports_indicator = {}
        try:
            result = misp.search(controller='events', return_format='stix2', **config.misp_event_filters, limit=config.misp_event_limit_per_page, page=misp_page)
            if result.get("objects", False):
                logging.debug("Received MISP events page {}".format(misp_page))
                stix2_objects = result.get("objects")

                for element in stix2_objects:       # Extract event information
                    if element.get("type", False) == "report":
                        misp_tags = []
                        misp_tag_tlp = ""
                        if element.get("labels", False):
                            for label in element.get("labels"):
                                if "tlp:" in label.lower() and label.lower() in TLP_MARKING_OBJECT_DEFINITION:
                                    misp_tag_tlp = label.lower()
                                if label not in misp_tags_ignore and label not in misp_tags:
                                    misp_tags.append(label)
                        if element.get("object_refs", False):
                            for object_ref in element.get("object_refs"):
                                if "indicator--" in object_ref:
                                    event_info = element.get("name", "").strip()
                                    event_uuid = element.get("id", "report--000").strip().split("report--")[1]
                                    misp_reports_indicator[object_ref] = {"info": event_info, "uuid": event_uuid, "tags": misp_tags, "tlp": misp_tag_tlp}

                for element in stix2_objects:
                    if element.get("type", False) in UPLOAD_INDICATOR_API_ACCEPTED_TYPES and element.get("id") not in misp_indicator_ids:
                        event_info = misp_reports_indicator.get(element["id"], empty_event)["info"]
                        event_uuid = misp_reports_indicator.get(element["id"], empty_event)["uuid"]
                        event_tags = misp_reports_indicator.get(element["id"], empty_event)["tags"]
                        event_tlp = misp_reports_indicator.get(element["id"], empty_event)["tlp"]

                        if event_tlp:
                            if element.get("object_marking_refs"):
                                element["object_marking_refs"].append(TLP_MARKING_OBJECT_DEFINITION[event_tlp])
                            else:
                                element["object_marking_refs"] = [TLP_MARKING_OBJECT_DEFINITION[event_tlp]]
                        for tag in event_tags:
                            if tag not in element.get("labels", []):
                                element["labels"].append(tag)

                        element["name"] = "{} {}".format(event_info, element.get("name", "")).strip()

                        # Check for misp:confidence-level="fairly-confident" and others
                        if not element.get("confidence", False):
                            element["confidence"] = config.default_confidence

                        # Link to MISP event
                        misp_event_reference = {
                            "source_name": "MISP",
                            "description": "MISP Event: {}".format(event_info),
                            "external_id": event_uuid,
                            "url": "https://{}/events/view/{}".format(config.misp_domain, event_uuid)
                        }
                        if element.get("external_references", False):
                            element["external_references"].append(misp_event_reference)
                        else:
                            element["external_references"] = [misp_event_reference]

                        misp_indicator_ids.append(element.get("id"))
                        result_set.append(element)
                logging.info("Processed {} indicators.".format(len(result_set)))
                misp_page += 1
        except Exception as e:
            remaining_misp_pages = False
            logging.info("Finished receiving MISP events.")

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