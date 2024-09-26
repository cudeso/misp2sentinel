from pymisp import *
import config
from collections import defaultdict
import datetime
from RequestManager import RequestManager
from RequestObject import RequestObject, RequestObject_Event, RequestObject_Indicator
from constants import *
import sys
from functools import reduce
import logging
import requests
import json
from datetime import datetime, timedelta
from misp_stix_converter import MISPtoSTIX21Parser
from stix2.base import STIXJSONEncoder

if config.misp_verifycert is False:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _get_events():
    misp = PyMISP(config.misp_domain, config.misp_key, config.misp_verifycert)
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
        datetime.fromtimestamp(int(parsed_event['lastReportedDateTime'])))


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
    misp = PyMISP(config.misp_domain, config.misp_key, config.misp_verifycert, False)
    result_set = []
    logger.debug("Query MISP for events.")
    remaining_misp_pages = True
    misp_page = 1
    misp_indicator_ids = []

    while remaining_misp_pages:
        try:
            if "limit" in config.misp_event_filters:
                result = misp.search(controller='events', return_format='json', **config.misp_event_filters)
                remaining_misp_pages = False # Limits are set in the misp_event_filters
            else:
                result = misp.search(controller='events', return_format='json', **config.misp_event_filters, limit=config.misp_event_limit_per_page, page=misp_page)

            if len(result) > 0:
                logger.info("Received MISP events page {} with {} events".format(misp_page, len(result)))
                for event in result:
                    misp_event = RequestObject_Event(event["Event"], logger, config.misp_flatten_attributes)
                    try:
                        parser = MISPtoSTIX21Parser()
                        parser.parse_misp_event(misp_event.event)
                        stix_objects = parser.stix_objects
                    except Exception as e:
                        logger.error("Error when processing data in event {} from MISP {}. Most likely a MISP-STIX conversion problem.".format(misp_event.id, e))
                        continue
                    if config.write_parsed_eventid:
                        logger.info("Processing event {} {}".format(event["Event"]["id"], event["Event"]["info"]))
                    for element in stix_objects:
                        if element.type in UPLOAD_INDICATOR_API_ACCEPTED_TYPES and \
                                        element.id not in misp_indicator_ids:
                            misp_indicator = RequestObject_Indicator(element, misp_event, logger)
                            if misp_indicator.id:
                                if misp_indicator.valid_until:
                                    valid_until = json.dumps(misp_indicator.valid_until, cls=STIXJSONEncoder).replace("\"", "")
                                    # Strip the dots from 'valid_until' to avoid date parse errors
                                    if "." in valid_until:
                                        valid_until = valid_until.split(".")[0]
                                    # There must be a "cleaner-Python" way to deal with converting these date formats
                                    if "Z" in valid_until:
                                        date_object = datetime.fromisoformat(valid_until[:-1])
                                    else:
                                        date_object = datetime.fromisoformat(valid_until)
                                    if date_object > datetime.now():
                                        if config.verbose_log:
                                            logger.debug("Add {} to list of indicators to upload".format(misp_indicator.pattern))
                                        misp_indicator_ids.append(misp_indicator.id)
                                        result_set.append(misp_indicator._get_dict())
                                    else:
                                        logger.error("Skipping outdated indicator {} in event {}, valid_until: {}".format(misp_indicator.pattern, misp_event.id, valid_until))
                                else:
                                    logger.error("Skipping indicator because valid_until was not set by MISP/MISP2Sentinel {}".format(misp_indicator.id))
                            else:
                                logger.error("Unable to process indicator. Invalid indicator type or invalid valid_until date. Event {}".format(misp_event.id))
                logger.info("Processed {} indicators".format(len(result_set)))
                misp_page += 1
            else:
                remaining_misp_pages = False

        except exceptions.MISPServerError as e:
            remaining_misp_pages = False
            logger.error("Error received from the MISP server {} - {} - {}".format(e, sys.exc_info()[2].tb_lineno, sys.exc_info()[1]))
        except Exception as e:
            remaining_misp_pages = False
            logger.error("Error when processing data from MISP {} - {} - {}".format(e, sys.exc_info()[2].tb_lineno, sys.exc_info()[1]))

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
    if not hasattr(config, "ms_useragent"):
        config.ms_useragent = "MISP-1.0"
    if not hasattr(config, "default_confidence"):
        config.default_confidence = 50
    if not hasattr(config, "ms_passiveonly"):
        config.ms_passiveonly = False
    if not hasattr(config, "ms_target_product"):
        config.ms_target_product = "Azure Sentinel"
    if not hasattr(config, "ms_action"):
        config.ms_action = "alert"
    if not hasattr(config, "misp_event_limit_per_page"):
        config.misp_event_limit_per_page = 100
    if not hasattr(config, "days_to_expire_ignore_misp_last_seen"):
        config.days_to_expire_ignore_misp_last_seen = False
    if not hasattr(config, "misp_remove_eventreports"):
        config.misp_remove_eventreports = True
    if not hasattr(config, "sentinel_write_response"):
        config.sentinel_write_response = False
    if not hasattr(config, "write_parsed_eventid"):
        config.write_parsed_eventid = False
    if not hasattr(config, "misp_flatten_attributes"):
        config.misp_flatten_attributes = False
    if not hasattr(config, "sourcesystem"):
        config.sourcesystem = "MISP"
    if not hasattr(config, "dry_run"):
        config.dry_run = False

    return use_old_config


global _build_logger


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
                if 'sentinel-threattype' in tag['name']:    # Can be overridden on attribute level
                    parsed_event['threatType'] = tag['name'].split(':')[1]
                    continue
                if config.ignore_localtags:
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
                if attr['type'] in MISP_ACTIONABLE_TYPES and attr['to_ids'] == True:
                    parsed_event['request_objects'].append(RequestObject(attr, parsed_event['description']))
            for obj in event['Object']:
                for attr in obj['Attribute']:
                    if attr['type'] == 'threat-actor':
                        parsed_event['activityGroupNames'].append(attr['value'])
                    if attr['type'] == 'comment':
                        parsed_event['description'] += attr['value']
                    if attr['type'] in MISP_ACTIONABLE_TYPES and attr['to_ids'] == True:
                        parsed_event['request_objects'].append(RequestObject(attr, parsed_event['description']))
            parsed_events.append(parsed_event)
        del events
        total_indicators = sum([len(v['request_objects']) for v in parsed_events])
    else:
        logger.info("Using Microsoft Upload Indicator API")
        parsed_indicators, total_indicators = _get_misp_events_stix()
        logger.info("Received {} indicators in MISP".format(total_indicators))

    if config.dry_run:
        logger.info("Dry run. Not uploading to Sentinel")
    else:
        with RequestManager(total_indicators, logger) as request_manager:
            if config.ms_auth["graph_api"]:
                for request_body in _graph_post_request_body_generator(parsed_events):
                    if config.verbose_log:
                        logger.debug("request body: {}".format(request_body))
                    request_manager.handle_indicator(request_body)
            else:
                logger.info("Start uploading indicators")
                request_manager.upload_indicators(parsed_indicators)
                logger.info("Finished uploading indicators")
                if config.write_parsed_indicators:
                    json_formatted_str = json.dumps(parsed_indicators, indent=4)
                    with open("parsed_indicators.txt", "w") as fp:
                        fp.write(json_formatted_str)


if __name__ == '__main__':
    check_for_old_config = _init_configuration()
    logger = _build_logger()

    logger.info("Start MISP2Sentinel")
    if check_for_old_config:
        logger.info("You're using an older configuration setting. Update config.py to the new configuration setting.")
    main()
    logger.info("End MISP2Sentinel")
