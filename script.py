from pymisp import *
import config
from collections import defaultdict
import datetime
from RequestManager import RequestManager
from RequestObject import RequestObject_Event, RequestObject_Indicator
from constants import *
import sys
import datetime
import logging
import json

from stix2 import parse, exceptions
import requests

if config.misp_verifycert is False:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def already_in_sentinel(stix_pattern):
    pattern = stix_pattern.split('=')[0].strip().replace('[', '').replace(']', '').replace(":value", "")
    if "hashes" in pattern:
        pattern = pattern.split(":")[0].strip()
    value = stix_pattern.split('=')[1].strip().replace('[', '').replace(']', '')
    
    rm = RequestManager(0, logger, config.ms_auth[TENANT])
    access_token = rm._get_access_token(
        config.ms_auth[TENANT], config.ms_auth[CLIENT_ID], config.ms_auth[CLIENT_SECRET], config.ms_auth[SCOPE]
    )
    if not access_token:
        logger.debug("No access token obtained for checking existing indicators in Sentinel")
        return False

    headers = {
        "Authorization": f"Bearer {access_token}",
        "user-agent": config.ms_useragent,
        "content-type": "application/json"
    }

    try:
        url = f"https://management.azure.com/subscriptions/{config.ms_auth.get("subscription_id")}/resourceGroups/{config.ms_auth.get("resourceGroupName")}/providers/Microsoft.OperationalInsights/workspaces/{config.ms_auth.get("workspaceName")}/providers/Microsoft.SecurityInsights/threatIntelligence/main/queryIndicators?api-version=2025-06-01"
        payload = {"filter": {"pattern": pattern}}
        payload = {"keywords": value,
                   "pageSize": 1,
                   "includeDisabled": False,
                   "patternTypes": [pattern]}
        resp = requests.post(url, headers=headers, json=payload, timeout=50)
        if resp.status_code != 200:
            return False

        try:
            body = resp.json()
        except Exception:
            return False

        result_len = False
        if isinstance(body, dict):
            if body.get("value"):
                result_len = len(body.get("value"))
            if body.get("results"):
                result_len = len(body.get("results"))
            return result_len
    except Exception:
        return False


def get_misp_events_upload_indicators():
    misp = PyMISP(config.misp_domain, config.misp_key, config.misp_verifycert, False)
    
    logger.debug("Query MISP for events")
    remaining_misp_pages = True
    indicator_count = 0
    misp_page = 1

    if config.write_parsed_indicators:
        # Clear existing parsed indicators file
        with open(PARSED_INDICATORS_FILE_NAME, "w") as fp:
            fp.write("")

    while remaining_misp_pages:
        result_set = []
        indicator_values = []

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

                    if config.write_parsed_eventid:
                        logger.info("Processing event {} {}".format(event["Event"]["id"], event["Event"]["info"]))

                    for element in misp_event.flatten_attributes:
                        if element["value"] not in indicator_values:
                            if element.get("to_ids", False) and \
                                        element.get("type", "") in UPLOAD_INDICATOR_MISP_ACCEPTED_TYPES:

                                misp_indicator = RequestObject_Indicator(element, misp_event, logger)
                                #print(misp_indicator._get_dict())
                                if misp_indicator.pattern is not None:
                                    try:
                                        parsed = parse(misp_indicator._get_dict(), allow_custom=False)
                                        skip_to_sentinel = False
                                        if config.ms_check_if_exist_in_sentinel:
                                            #start_time = datetime.datetime.now(datetime.timezone.utc)
                                            #logger.debug("already_in_sentinel check start: %s", start_time.isoformat())
                                            in_sentinel = already_in_sentinel(misp_indicator.pattern)
                                            #end_time = datetime.datetime.now(datetime.timezone.utc)
                                            #logger.debug("already_in_sentinel check end: %s", end_time.isoformat())
                                            #duration = end_time - start_time
                                            #logger.info("already_in_sentinel check duration for %s: %s", misp_indicator.pattern, str(duration))
                                            if in_sentinel:
                                                skip_to_sentinel = True
                                                logger.debug("Skipping indicator already in Sentinel: %s", misp_indicator.pattern)
                                        if not skip_to_sentinel:
                                            if config.verbose_log:
                                                logger.debug("Add {} to list of indicators to upload".format(misp_indicator.pattern))
                                            result_set.append(misp_indicator._get_dict())
                                            indicator_values.append(element["value"])
                                    except exceptions.STIXError as e:
                                        logger.error("Skipping invalid STIX indicator {} : {} from MISP event {} .".format(e, element.get("value", ""), misp_event.id))

                logger.info("Processed {} indicators".format(len(result_set)))
                indicator_count = indicator_count + len(result_set)
                misp_page += 1
            else:
                remaining_misp_pages = False

            if config.dry_run:
                logger.info("Dry run. Not uploading to Sentinel")
                if config.write_parsed_indicators:
                    write_parsed_indicators(result_set)
            else:
                with RequestManager(len(result_set), logger, config.ms_auth[TENANT]) as request_manager:
                    logger.info("Start uploading indicators")
                    request_manager.upload_indicators(result_set)
                    logger.info("Finished uploading indicators")
                    if config.write_parsed_indicators:
                        write_parsed_indicators(result_set)
        except Exception as e:
            remaining_misp_pages = False
            logger.error("Error when processing data from MISP {} - {} - {}".format(e, sys.exc_info()[2].tb_lineno, sys.exc_info()[1]))

    return indicator_count


def init_configuration():
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
        config.misp_flatten_attributes = True
    if not hasattr(config, "sourcesystem"):
        config.sourcesystem = "MISP"
    if not hasattr(config, "dry_run"):
        config.dry_run = False
    if not hasattr(config, "remove_pipe_from_misp_attribute"):
        config.remove_pipe_from_misp_attribute = True
    if not hasattr(config, "ms_check_if_exist_in_sentinel"):
        config.ms_check_if_exist_in_sentinel = False



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

def write_parsed_indicators(parsed_indicators):
    json_formatted_str = json.dumps(parsed_indicators, indent=4)
    with open(PARSED_INDICATORS_FILE_NAME, "a") as fp:
        fp.write(json_formatted_str)

def main():
    logger.info("Fetching and parsing data from MISP {}".format(config.misp_domain))
    logger.info("Using Microsoft Upload Indicator API")
    total_indicators = get_misp_events_upload_indicators()
    logger.info("Received {} indicators in MISP".format(total_indicators))


if __name__ == '__main__':
    logger = _build_logger()    
    logger.info("Start MISP2Sentinel")
    logger.info("Initializing configuration")
    init_configuration()
    main()
    logger.info("End MISP2Sentinel")
