from pymisp import *
import config
from collections import defaultdict
import datetime
import argparse
from RequestManager import RequestManager
from RequestObject import RequestObject_Event, RequestObject_Indicator
from constants import *
import sys
import logging
import json
import time

from stix2 import parse, exceptions
import requests
import uuid

if config.misp_verifycert is False:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def already_in_sentinel(stix_pattern, session):
    pattern = stix_pattern.split('=')[0].strip().replace('[', '').replace(']', '').replace(":value", "")
    if "hashes" in pattern:
        pattern = pattern.split(":")[0].strip()
    value = stix_pattern.split('=')[1].strip().replace('[', '').replace(']', '')
    
    if not session:
        return False

    try:
        url = f"https://management.azure.com/subscriptions/{config.ms_auth.get('subscription_id')}/resourceGroups/{config.ms_auth.get('resourceGroupName')}/providers/Microsoft.OperationalInsights/workspaces/{config.ms_auth.get('workspaceName')}/providers/Microsoft.SecurityInsights/threatIntelligence/main/queryIndicators?api-version=2025-09-01"
        payload = {"keywords": value,
                   "pageSize": 1,
                   "includeDisabled": False,
                   "patternTypes": [pattern]}
        resp = session.post(url, json=payload, timeout=50)
        if resp.status_code != 200:
            return False

        try:
            body = resp.json()
        except Exception:
            return False

        if isinstance(body, dict):
            if body.get("value"):
                return len(body.get("value")) > 0
            if body.get("results"):
                return len(body.get("results")) > 0
        return False
    except Exception:
        return False


def _get_sentinel_session(rm):
    access_token = rm._get_access_token(
        config.ms_auth[TENANT], config.ms_auth[CLIENT_ID], config.ms_auth[CLIENT_SECRET], config.ms_auth[SCOPE]
    )
    if not access_token:
        return None, 0
    session = requests.Session()
    session.headers.update({
        "Authorization": f"Bearer {access_token}",
        "user-agent": config.ms_useragent,
        "content-type": "application/json"
    })
    expiry = datetime.datetime.now().timestamp() + 3500
    return session, expiry


def _refresh_sentinel_session(session, expiry, rm):
    if datetime.datetime.now().timestamp() > expiry:
        access_token = rm._get_access_token(
            config.ms_auth[TENANT], config.ms_auth[CLIENT_ID], config.ms_auth[CLIENT_SECRET], config.ms_auth[SCOPE]
        )
        if access_token:
            session.headers["Authorization"] = f"Bearer {access_token}"
            expiry = datetime.datetime.now().timestamp() + 3500
    return expiry


def _revoke_indicators(indicators, session, rm, expiry):
    if not indicators:
        return 0, expiry

    workspace_id = config.ms_auth["workspace_id"]
    api_version = config.ms_api_version
    if config.ms_auth["new_upload_api"]:
        upload_url = f"https://api.ti.sentinel.azure.com/workspaces/{workspace_id}/threat-intelligence-stix-objects:upload?api-version={api_version}"
        indicator_value_key = "stixobjects"
    else:
        upload_url = f"https://sentinelus.azure-api.net/{workspace_id}/threatintelligence:upload-indicators?api-version={api_version}"
        indicator_value_key = "value"

    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    stix_objects = []
    for ind in indicators:
        props = ind.get("properties", {})
        external_id = props.get("externalId", "")
        if not external_id:
            name = ind.get("name", "")
            if name:
                external_id = f"indicator--{name}"
            else:
                logger.warning("Skipping indicator without externalId or name")
                continue

        stix_obj = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": external_id,
            "created": props.get("created", now),
            "modified": now,
            "pattern": props.get("pattern", "[ipv4-addr:value = '0.0.0.0']"),
            "pattern_type": "stix",
            "valid_from": props.get("validFrom", now),
            "revoked": True
        }
        stix_objects.append(stix_obj)

    if not stix_objects:
        return 0, expiry

    revoked_count = 0
    for i in range(0, len(stix_objects), 100):
        batch = stix_objects[i:i + 100]
        expiry = _refresh_sentinel_session(session, expiry, rm)

        body = {"sourcesystem": config.sourcesystem, indicator_value_key: batch}
        try:
            resp = session.post(upload_url, json=body, timeout=60)
            logger.debug("Revoke upload response: %s %s", resp.status_code, resp.text[:500] if resp.text else "(empty)")
            if resp.status_code == 200:
                revoked_count += len(batch)
            else:
                logger.error("Error revoking indicators (batch %d): %s %s", i // 100, resp.status_code, resp.text[:500] if resp.text else "(empty)")
        except Exception as e:
            logger.error("Exception revoking indicators (batch %d): %s", i // 100, e)

    return revoked_count, expiry


def get_misp_toids_disabled(timeframe):
    misp = PyMISP(config.misp_domain, config.misp_key, config.misp_verifycert, False)

    logger.info("Querying MISP for attributes with to_ids=False changed in the last {}".format(timeframe))
    results = misp.search(controller='attributes', to_ids=0, timestamp=timeframe,
                          type_attribute=list(UPLOAD_INDICATOR_MISP_ACCEPTED_TYPES), return_format='json')

    attributes = []
    if isinstance(results, dict):
        attributes = results.get("Attribute", results.get("response", {}).get("Attribute", []))
    elif isinstance(results, list):
        attributes = results

    values = []
    for attr in attributes:
        v = attr.get("value", "")
        if v and v not in values:
            values.append(v)

    logger.info("Found {} unique attribute values with to_ids recently set to False".format(len(values)))
    return values


def delete_indicators_from_sentinel(values):
    rm = RequestManager(0, logger, config.ms_auth[TENANT])
    session, expiry = _get_sentinel_session(rm)
    if not session:
        logger.error("Could not get Sentinel access token for to_ids verification")
        return

    url = (
        f"https://management.azure.com/subscriptions/{config.ms_auth.get('subscription_id')}"
        f"/resourceGroups/{config.ms_auth.get('resourceGroupName')}"
        f"/providers/Microsoft.OperationalInsights/workspaces/{config.ms_auth.get('workspaceName')}"
        f"/providers/Microsoft.SecurityInsights/threatIntelligence/main/queryIndicators"
        f"?api-version=2025-09-01"
    )

    values_set = set(values)
    to_revoke = {}

    skip_token = None
    while True:
        expiry = _refresh_sentinel_session(session, expiry, rm)
        payload = {"pageSize": 100, "includeDisabled": False, "sources": [config.sourcesystem]}
        if skip_token:
            payload["skipToken"] = skip_token
        try:
            resp = session.post(url, json=payload, timeout=60)
            if resp.status_code != 200:
                logger.error("Error querying Sentinel indicators: {}".format(resp.status_code))
                break
            body = resp.json()
        except Exception as e:
            logger.error("Exception querying Sentinel indicators: {}".format(e))
            break

        indicators = body.get("value", [])
        if not indicators:
            break

        for indicator in indicators:
            pattern = indicator.get("properties", {}).get("pattern", "")
            for v in list(values_set):
                if "'{}'".format(v) in pattern:
                    to_revoke[v] = indicator
                    values_set.discard(v)

        if not values_set:
            break

        skip_token = body.get("nextLink") or body.get("skipToken")
        if not skip_token:
            break

    if config.dry_run:
        for attr_value, indicator in to_revoke.items():
            logger.info("Dry run - would revoke from Sentinel: {} ({})".format(attr_value, indicator.get("name")))
        revoked_count = len(to_revoke)
    elif to_revoke:
        indicator_list = list(to_revoke.values())
        revoked_count, expiry = _revoke_indicators(indicator_list, session, rm, expiry)
        for attr_value in to_revoke:
            logger.info("Revoked from Sentinel: {}".format(attr_value))
    else:
        revoked_count = 0

    not_found_count = len(values_set)
    for v in values_set:
        logger.debug("Not found in Sentinel: {}".format(v))

    logger.info("to_ids verification complete: {} revoked, {} not found in Sentinel".format(revoked_count, not_found_count))


def verify_recent_toids_change():
    values = get_misp_toids_disabled(config.timeframe_toids_change)
    if values:
        delete_indicators_from_sentinel(values)
    else:
        logger.info("No indicators to delete from Sentinel based on to_ids change")


def delete_outdated_indicators():
    rm = RequestManager(0, logger, config.ms_auth[TENANT])
    session, expiry = _get_sentinel_session(rm)
    if not session:
        logger.error("Could not get Sentinel access token for outdated indicator deletion")
        return

    url = (
        f"https://management.azure.com/subscriptions/{config.ms_auth.get('subscription_id')}"
        f"/resourceGroups/{config.ms_auth.get('resourceGroupName')}"
        f"/providers/Microsoft.OperationalInsights/workspaces/{config.ms_auth.get('workspaceName')}"
        f"/providers/Microsoft.SecurityInsights/threatIntelligence/main/queryIndicators"
        f"?api-version=2025-09-01"
    )

    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    total_revoked = 0
    revoked_ids = set()
    consecutive_all_seen = 0
    max_consecutive_all_seen = 3

    while True:
        expiry = _refresh_sentinel_session(session, expiry, rm)
        payload = {
            "sources": [config.sourcesystem],
            "maxValidUntil": now,
            "includeDisabled": True,
            "pageSize": 100
        }

        try:
            resp = session.post(url, json=payload, timeout=60)
            if resp.status_code != 200:
                logger.error("Error querying outdated Sentinel indicators: {}".format(resp.status_code))
                break
            body = resp.json()
        except Exception as e:
            logger.error("Exception querying outdated Sentinel indicators: {}".format(e))
            break

        indicators = body.get("value", [])
        if not indicators:
            break

        new_indicators = [i for i in indicators if i.get("name", "") not in revoked_ids]

        if not new_indicators:
            consecutive_all_seen += 1
            wait_time = min(30 * consecutive_all_seen, 120)
            logger.info("All {} returned indicators already revoked (attempt {}/{}), waiting {}s for Sentinel to catch up...".format(
                len(indicators), consecutive_all_seen, max_consecutive_all_seen, wait_time))
            if consecutive_all_seen >= max_consecutive_all_seen:
                logger.info("Sentinel still returning already-revoked indicators after {} retries, stopping".format(max_consecutive_all_seen))
                break
            time.sleep(wait_time)
            continue

        consecutive_all_seen = 0

        if config.dry_run:
            for indicator in new_indicators:
                indicator_name = indicator.get("name", "")
                pattern = indicator.get("properties", {}).get("pattern", "")
                valid_until = indicator.get("properties", {}).get("validUntil", "")
                logger.info("Dry run - would revoke outdated indicator: {} (validUntil: {}, pattern: {})".format(indicator_name, valid_until, pattern))
            break

        for indicator in new_indicators:
            indicator_name = indicator.get("name", "")
            pattern = indicator.get("properties", {}).get("pattern", "")
            valid_until = indicator.get("properties", {}).get("validUntil", "")
            logger.info("Revoking: {} (validUntil: {}, pattern: {})".format(indicator_name, valid_until, pattern))
            revoked_ids.add(indicator_name)

        revoked_count, expiry = _revoke_indicators(new_indicators, session, rm, expiry)
        total_revoked += revoked_count
        skipped = len(indicators) - len(new_indicators)
        logger.info("Batch revoked: {} new, {} skipped as already revoked (total so far: {}), waiting 15s...".format(
            revoked_count, skipped, total_revoked))
        time.sleep(15)

    if config.dry_run:
        logger.info("Outdated indicator cleanup complete (dry run)")
    else:
        logger.info("Outdated indicator cleanup: {} total revoked via upload API".format(total_revoked))


def get_misp_events_upload_indicators(event_uuid=None):
    misp = PyMISP(config.misp_domain, config.misp_key, config.misp_verifycert, False)
    
    if event_uuid:
        misp_event_filters = {"uuid": event_uuid}
        logger.info("Using event UUID filter: {}".format(event_uuid))
    else:
        misp_event_filters = config.misp_event_filters
    
    logger.debug("Query MISP for events")
    remaining_misp_pages = True
    indicator_count = 0
    indicator_count_match_sentinel = 0
    indicator_values = []
    misp_page = 1

    sentinel_session = None
    sentinel_headers_expiry = 0
    if config.ms_check_if_exist_in_sentinel:
        rm = RequestManager(0, logger, config.ms_auth[TENANT])
        sentinel_session, sentinel_headers_expiry = _get_sentinel_session(rm)
        if not sentinel_session:
            logger.error("Could not get Sentinel access token for existing indicator check")

    if config.write_parsed_indicators:
        # Clear existing parsed indicators file
        with open(PARSED_INDICATORS_FILE_NAME, "w") as fp:
            fp.write("")

    while remaining_misp_pages:
        result_set = []

        try:
            if "limit" in misp_event_filters:
                result = misp.search(controller='events', return_format='json', **misp_event_filters)
                remaining_misp_pages = False # Limits are set in the misp_event_filters
            else:
                result = misp.search(controller='events', return_format='json', **misp_event_filters, limit=config.misp_event_limit_per_page, page=misp_page)

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
                                if misp_indicator.valid_until:
                                    try:
                                        vu_dt = datetime.datetime.strptime(misp_indicator.valid_until, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
                                    except Exception:
                                        try:
                                            vu_dt = datetime.datetime.fromisoformat(misp_indicator.valid_until.replace('Z', '+00:00'))
                                        except Exception:
                                            logger.debug("Unable to parse valid_until {}, skipping indicator {}".format(misp_indicator.valid_until, element["value"]))
                                            continue
                                    if vu_dt <= datetime.datetime.now(datetime.timezone.utc):
                                        logger.debug("Skipping indicator because valid_until is in the past: {} {}".format(misp_indicator.valid_until, element["value"]))
                                        continue

                                if misp_indicator.pattern is not None:
                                    is_custom = element.get("type", "") in MISP_CUSTOM_ATTRIBUTE
                                    try:
                                        if not is_custom:
                                            parsed = parse(misp_indicator._get_dict(), allow_custom=False)
                                        skip_to_sentinel = False
                                        if config.ms_check_if_exist_in_sentinel:
                                            sentinel_headers_expiry = _refresh_sentinel_session(sentinel_session, sentinel_headers_expiry, rm)
                                            start_time = datetime.datetime.now(datetime.timezone.utc)
                                            in_sentinel = already_in_sentinel(misp_indicator.pattern, sentinel_session)
                                            end_time = datetime.datetime.now(datetime.timezone.utc)
                                            duration = end_time - start_time
                                            logger.debug("already_in_sentinel check duration for {} {}".format(misp_indicator.pattern, str(duration)))
                                            if in_sentinel:
                                                skip_to_sentinel = True
                                                indicator_count_match_sentinel += 1
                                                logger.info("Skipping indicator already in Sentinel: {}".format(misp_indicator.pattern))
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

    return indicator_count, indicator_count_match_sentinel


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
    if not hasattr(config, "timeframe_toids_change"):
        config.timeframe_toids_change = "1d"



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
    parser = argparse.ArgumentParser(description="MISP to Microsoft Sentinel indicator sync")
    parser.add_argument("--uuid", type=str, help="Process a single MISP event by UUID")
    parser.add_argument("--verify-recent-toids-change", action="store_true",
                        help="Find attributes where to_ids was recently set to False and delete them from Sentinel")
    parser.add_argument("--delete-outdated-indicators", action="store_true",
                        help="Delete expired indicators from Sentinel")
    args = parser.parse_args()

    event_uuid = None
    if args.uuid:
        try:
            uuid_obj = uuid.UUID(args.uuid.strip())
            event_uuid = str(uuid_obj)
            logger.info("Valid UUID parameter provided: {}".format(event_uuid))
        except ValueError:
            logger.error("Invalid UUID parameter provided: {}. Exiting.".format(args.uuid))
            sys.exit(1)

    if args.verify_recent_toids_change:
        logger.info("Running to_ids verification")
        verify_recent_toids_change()

    if args.delete_outdated_indicators:
        logger.info("Running outdated indicator cleanup")
        delete_outdated_indicators()

    logger.info("Fetching and parsing data from MISP {}".format(config.misp_domain))
    logger.info("Using Microsoft Upload Indicator API")
    total_indicators, indicator_count_match_sentinel = get_misp_events_upload_indicators(event_uuid)
    logger.info("Pushed {} indicators from MISP to Sentinel".format(total_indicators))
    if config.ms_check_if_exist_in_sentinel:
        logger.info("Skipped {} MISP indicators because they were already in Sentinel".format(indicator_count_match_sentinel))


if __name__ == '__main__':
    logger = _build_logger()    
    logger.info("====== Start MISP2Sentinel ======")
    logger.info("Initializing configuration")
    init_configuration()
    main()
    logger.info("====== End MISP2Sentinel ======")

