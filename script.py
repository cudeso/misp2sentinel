from pymisp import ExpandedPyMISP
import config
from collections import defaultdict
import datetime
from RequestManager import RequestManager
from RequestObject import RequestObject
from constants import *
import sys
from functools import reduce
import logging
import requests
import json

if config.misp_verifycert is False:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _get_events():
    misp = ExpandedPyMISP(config.misp_domain, config.misp_key, config.misp_verifycert)
    if len(config.misp_event_filters) == 0:
        return [event['Event'] for event in misp.search(controller='events', return_format='json')]
    events_for_each_filter = [
        [event['Event'] for event in misp.search(controller='events', return_format='json', **config.misp_event_filters)]
    ]
    event_ids_for_each_filter = [set(event['id'] for event in events) for events in events_for_each_filter]
    event_ids_intersection = reduce((lambda x, y: x & y), event_ids_for_each_filter)
    return [event for event in events_for_each_filter[0] if event['id'] in event_ids_intersection]


def _graph_post_request_body_generator(parsed_events):
    for event in parsed_events:
        request_body_metadata = {
            **{field: event[field] for field in REQUIRED_GRAPH_METADATA},
            **{field: event[field] for field in OPTIONAL_GRAPH_METADATA if field in event},
            'action': config.ms_action,
            'passiveOnly': config.ms_passiveonly,
            'targetProduct': config.ms_target_product,
        }

        if len(request_body_metadata.get('threatType', [])) < 1:
            request_body_metadata['threatType'] = 'watchlist'
        if config.default_confidence:
            request_body_metadata["confidence"] = config.default_confidence
        for request_object in event['request_objects']:
            request_body = {
                **request_body_metadata.copy(),
                **request_object.__dict__,
                'tags': request_body_metadata.copy()['tags'] + request_object.__dict__['tags'],
            }
            yield request_body


def _handle_timestamp(parsed_event):
    parsed_event['lastReportedDateTime'] = str(
        datetime.datetime.fromtimestamp(int(parsed_event['lastReportedDateTime'])))


def _handle_diamond_model(parsed_event):
    for tag in parsed_event['tags']:
        if 'diamond-model:' in tag:
            parsed_event['diamondModel'] = tag.split(':')[1]


def _handle_tlp_level(parsed_event):
    for tag in parsed_event['tags']:
        if 'tlp:' in tag:
            parsed_event['tlpLevel'] = tag.split(':')[1].lower().capitalize()
        if parsed_event['tlpLevel'] == 'Clear':
            parsed_event['tlpLevel'] = 'White'
    if 'tlpLevel' not in parsed_event:
        parsed_event['tlpLevel'] = 'Red'


def _get_misp_events_stix():
    misp = ExpandedPyMISP(config.misp_domain, config.misp_key, config.misp_verifycert, False)
    result_set = []
    logger.debug("Query MISP for events and return them in stix2 format.")
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
                logger.debug("Received MISP events page {}".format(misp_page))
                stix2_objects = result.get("objects")
                '''print(stix2_objects)'''

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
                logger.info("Processed {} indicators.".format(len(result_set)))
                misp_page += 1
        except Exception as e:
            remaining_misp_pages = False
            logger.info("Finished receiving MISP events.")

    return result_set, len(result_set)


def _init_configuration():
    config_mapping = {
        "graph_auth": "ms_auth",
        "targetProduct": "ms_target_product",
        "action": "ms_action",
        "passiveOnly": "ms_passiveonly",
        "defaultConfidenceLevel": "default_confidence"
    }

    use_old_config = False
    for old_value in config_mapping:
        if hasattr(config, old_value):
            p = getattr(config, old_value)
            setattr(config, config_mapping[old_value], p)
            use_old_config = True

    if not hasattr(config, "log_file"):
        sys.exit("Exiting. No log file configuration setting found (log_file).")
    if not (hasattr(config, "misp_domain") and hasattr(config, "misp_key") and hasattr(config, "misp_verifycert")):
        sys.exit("Exiting. No MISP authentication configuration setting found (misp_domain, misp_key and misp_verifycert).")
    if not hasattr(config, "ms_auth"):
        sys.exit("Exiting. No Microsoft authentication configuration setting found (ms_auth).")
    return use_old_config


def _build_logger():
    logger = logging.getLogger("misp2sentinel")
    logger.setLevel(logging.INFO)
    if config.verbose_log:
        logger.setLevel(logging.DEBUG)
    ch = logging.FileHandler(config.log_file, mode="a")
    ch.setLevel(logging.INFO)
    if config.verbose_log:
        ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    return logger


def main():
    logger.info("Fetching and parsing data from MISP ...")

    if config.ms_auth.get("graph_api", False):
        logger.info("Using Microsoft Graph API")
        events = _get_events()
        parsed_events = list()
        for event in events:
            parsed_event = defaultdict(list)

            for key, mapping in EVENT_MAPPING.items():
                parsed_event[mapping] = event.get(key, "")

            # Tags on event level
            tags = []
            for tag in event.get("Tag", []):
                if 'sentinel-threattype' in tag['name']:    # Can be overriden on attribute level
                    parsed_event['threatType'] = tag['name'].split(':')[1]
                    continue
                if config.misp_ignore_localtags:
                    if tag["local"] != 1:
                        tags.append(tag['name'].strip())
            parsed_event['tags'] = tags
            _handle_diamond_model(parsed_event)
            _handle_tlp_level(parsed_event)
            _handle_timestamp(parsed_event)

            for attr in event['Attribute']:
                if attr['type'] == 'threat-actor':
                    parsed_event['activityGroupNames'].append(attr['value'])
                if attr['type'] == 'comment':
                    parsed_event['description'] += attr['value']
                if attr['type'] in MISP_ACTIONABLE_TYPES:
                    parsed_event['request_objects'].append(RequestObject(attr))
            for obj in event['Object']:
                for attr in obj['Attribute']:
                    if attr['type'] == 'threat-actor':
                        parsed_event['activityGroupNames'].append(attr['value'])
                    if attr['type'] == 'comment':
                        parsed_event['description'] += attr['value']
                    if attr['type'] in MISP_ACTIONABLE_TYPES:
                        parsed_event['request_objects'].append(RequestObject(attr))
            parsed_events.append(parsed_event)
        del events
        total_indicators = sum([len(v['request_objects']) for v in parsed_events])
    else:
        logger.info("Using Microsoft Upload Indicator API")
        parsed_indicators, total_indicators = _get_misp_events_stix()
        logger.info("Found {} indicators in MISP".format(total_indicators))

    with RequestManager(total_indicators, logger) as request_manager:
        if config.ms_auth["graph_api"]:
            for request_body in _graph_post_request_body_generator(parsed_events):
                if config.verbose_log:
                    print(f"request body: {request_body}")
                request_manager.handle_indicator(request_body)
        else:
            request_manager.upload_indicators(parsed_indicators)


if __name__ == '__main__':
    check_for_old_config = _init_configuration()
    logger = _build_logger()

    logger.info("Start MISP2Sentinel")
    if check_for_old_config:
        logger.info("You're using an older configuration setting. Update config.py to the new configuration setting.")
    main()
    logger.info("End MISP2Sentinel")
