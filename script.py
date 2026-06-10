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
from urllib.parse import urlparse, parse_qs

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


def _extract_skip_token(body):
    next_link = body.get("nextLink")
    if next_link:
        qs = parse_qs(urlparse(next_link).query)
        token = qs.get("$skipToken") or qs.get("skipToken")
        if token:
            return token[0]
    return body.get("skipToken")


def _delete_sentinel_indicator(name, session):
    url = (
        f"https://management.azure.com/subscriptions/{config.ms_auth.get('subscription_id')}"
        f"/resourceGroups/{config.ms_auth.get('resourceGroupName')}"
        f"/providers/Microsoft.OperationalInsights/workspaces/{config.ms_auth.get('workspaceName')}"
        f"/providers/Microsoft.SecurityInsights/threatIntelligence/main/indicators/{name}"
        f"?api-version={config.ms_delete_api_version}"
    )
    for attempt in range(4):
        try:
            resp = session.delete(url, timeout=30)
        except requests.exceptions.RequestException as e:
            logger.error("Exception deleting indicator {}: {}".format(name, e))
            return False
        if resp.status_code in (200, 204):
            return True
        if resp.status_code == 404:
            logger.debug("Indicator {} already gone (404)".format(name))
            return True
        if resp.status_code == 429:
            retry_after = resp.headers.get("Retry-After")
            try:
                wait = float(retry_after) if retry_after else 2 ** attempt
            except ValueError:
                wait = 2 ** attempt
            logger.warning("Rate-limited deleting {} (attempt {}), sleeping {}s".format(name, attempt + 1, wait))
            time.sleep(wait)
            continue
        logger.error("Failed to delete indicator {}: {} {}".format(
            name, resp.status_code, resp.text[:300] if resp.text else ""))
        return False
    logger.error("Giving up deleting indicator {} after repeated 429s".format(name))
    return False


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
        return 0, 0

    url = (
        f"https://management.azure.com/subscriptions/{config.ms_auth.get('subscription_id')}"
        f"/resourceGroups/{config.ms_auth.get('resourceGroupName')}"
        f"/providers/Microsoft.OperationalInsights/workspaces/{config.ms_auth.get('workspaceName')}"
        f"/providers/Microsoft.SecurityInsights/threatIntelligence/main/queryIndicators"
        f"?api-version={config.ms_delete_api_version}"
    )

    values_set = set(values)
    to_delete = {}  # value -> indicator name

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
                    to_delete[v] = indicator.get("name")
                    values_set.discard(v)

        if not values_set:
            break

        skip_token = _extract_skip_token(body)
        if not skip_token:
            break

    deleted_count = 0
    for attr_value, indicator_name in to_delete.items():
        if not indicator_name:
            continue
        if config.dry_run:
            logger.info("Dry run - would delete from Sentinel: {} ({})".format(attr_value, indicator_name))
            deleted_count += 1
            continue
        expiry = _refresh_sentinel_session(session, expiry, rm)
        if _delete_sentinel_indicator(indicator_name, session):
            logger.info("Deleted from Sentinel: {} ({})".format(attr_value, indicator_name))
            deleted_count += 1

    not_found_count = len(values_set)
    for v in values_set:
        logger.debug("Not found in Sentinel: {}".format(v))

    logger.info("to_ids verification complete: {} deleted, {} not found in Sentinel".format(deleted_count, not_found_count))
    return deleted_count, not_found_count


def verify_recent_toids_change():
    values = get_misp_toids_disabled(config.timeframe_toids_change)
    if values:
        return delete_indicators_from_sentinel(values)
    logger.info("No indicators to delete from Sentinel based on to_ids change")
    return 0, 0


def delete_outdated_indicators():
    rm = RequestManager(0, logger, config.ms_auth[TENANT])
    session, expiry = _get_sentinel_session(rm)
    if not session:
        logger.error("Could not get Sentinel access token for outdated indicator deletion")
        return 0, 0

    url = (
        f"https://management.azure.com/subscriptions/{config.ms_auth.get('subscription_id')}"
        f"/resourceGroups/{config.ms_auth.get('resourceGroupName')}"
        f"/providers/Microsoft.OperationalInsights/workspaces/{config.ms_auth.get('workspaceName')}"
        f"/providers/Microsoft.SecurityInsights/threatIntelligence/main/queryIndicators"
        f"?api-version={config.ms_delete_api_version}"
    )

    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    payload = {
        "sources": [config.sourcesystem],
        "maxValidUntil": now,
        "includeDisabled": False,
        "pageSize": 100,
    }

    processed_names = set()
    total_deleted = 0
    total_failed = 0
    skip_token = None

    while True:
        expiry = _refresh_sentinel_session(session, expiry, rm)
        page_payload = dict(payload)
        if skip_token:
            page_payload["skipToken"] = skip_token
        try:
            resp = session.post(url, json=page_payload, timeout=60)
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

        new_in_batch = 0
        for indicator in indicators:
            name = indicator.get("name", "")
            if not name or name in processed_names:
                continue
            processed_names.add(name)
            new_in_batch += 1

            props = indicator.get("properties", {})
            pattern = props.get("pattern", "")
            valid_until = props.get("validUntil", "")

            if config.dry_run:
                logger.info("Dry run - would delete outdated indicator: {} (validUntil: {}, pattern: {})".format(
                    name, valid_until, pattern))
                continue

            logger.info("Deleting: {} (validUntil: {}, pattern: {})".format(name, valid_until, pattern))
            expiry = _refresh_sentinel_session(session, expiry, rm)
            if _delete_sentinel_indicator(name, session):
                total_deleted += 1
            else:
                total_failed += 1

        skip_token = _extract_skip_token(body)
        if not skip_token:
            break
        if new_in_batch == 0 and not config.dry_run:
            # In live mode the deletes shrink the result set, so a page with no
            # new names means Sentinel is still serving a stale view; stop here.
            break

    if config.dry_run:
        logger.info("Outdated indicator cleanup complete (dry run)")
    else:
        logger.info("Outdated indicator cleanup: {} deleted, {} failed".format(total_deleted, total_failed))
    return total_deleted, total_failed


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

    decay_search_params = {}
    if config.misp_decay_model_enabled:
        decay_search_params["includeDecayScore"] = True
        if config.misp_decay_model_id is not None:
            decay_search_params["decayingModelId"] = config.misp_decay_model_id
        logger.info("MISP Decay Model support enabled (model_id={}, min_score={}, exclude_decayed={})".format(
            config.misp_decay_model_id, config.misp_decay_model_min_score, config.misp_decay_model_exclude_decayed))

    indicator_count_decay_skipped = 0

    while remaining_misp_pages:
        result_set = []

        try:
            if "limit" in misp_event_filters:
                result = misp.search(controller='events', return_format='json', **misp_event_filters, **decay_search_params)
                remaining_misp_pages = False # Limits are set in the misp_event_filters
            else:
                result = misp.search(controller='events', return_format='json', **misp_event_filters, **decay_search_params, limit=config.misp_event_limit_per_page, page=misp_page)

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

                                if config.misp_decay_model_enabled:
                                    decay_scores = element.get("decay_score", [])
                                    if decay_scores:
                                        model_id = config.misp_decay_model_id
                                        selected = None
                                        for ds in decay_scores:
                                            if model_id is None or str(ds.get("DecayingModel", {}).get("id", "")) == str(model_id):
                                                selected = ds
                                                break
                                        if selected:
                                            if config.misp_decay_model_exclude_decayed and selected.get("decayed", False):
                                                logger.info("Skipping fully decayed indicator: {}".format(element["value"]))
                                                indicator_count_decay_skipped += 1
                                                continue
                                            score = selected.get("score")
                                            if score is not None:
                                                if score < config.misp_decay_model_min_score:
                                                    logger.info("Skipping indicator with decay score {:.1f} below threshold {}: {}".format(
                                                        score, config.misp_decay_model_min_score, element["value"]))
                                                    indicator_count_decay_skipped += 1
                                                    continue
                                                if config.misp_decay_model_override_confidence:
                                                    misp_indicator.confidence = int(round(score))
                                                    logger.debug("Decay score {:.1f} applied as confidence for {}".format(score, element["value"]))

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

    return indicator_count, indicator_count_match_sentinel, indicator_count_decay_skipped


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
    if not hasattr(config, "ms_delete_api_version"):
        config.ms_delete_api_version = "2025-09-01"
    if not hasattr(config, "misp_decay_model_enabled"):
        config.misp_decay_model_enabled = False
    if not hasattr(config, "misp_decay_model_id"):
        config.misp_decay_model_id = None
    if not hasattr(config, "misp_decay_model_override_confidence"):
        config.misp_decay_model_override_confidence = True
    if not hasattr(config, "misp_decay_model_min_score"):
        config.misp_decay_model_min_score = 0
    if not hasattr(config, "misp_decay_model_exclude_decayed"):
        config.misp_decay_model_exclude_decayed = True



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

    run_start = datetime.datetime.now(datetime.timezone.utc)

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
        toids_deleted, toids_not_found = verify_recent_toids_change()
    else:
        toids_deleted, toids_not_found = 0, 0

    if args.delete_outdated_indicators:
        logger.info("Running outdated indicator cleanup")
        outdated_deleted, outdated_failed = delete_outdated_indicators()
    else:
        outdated_deleted, outdated_failed = 0, 0

    logger.info("Fetching and parsing data from MISP {}".format(config.misp_domain))
    logger.info("Using Microsoft Upload Indicator API")
    total_indicators, indicator_count_match_sentinel, indicator_count_decay_skipped = get_misp_events_upload_indicators(event_uuid)
    logger.info("Pushed {} indicators from MISP to Sentinel".format(total_indicators))
    if config.ms_check_if_exist_in_sentinel:
        logger.info("Skipped {} MISP indicators because they were already in Sentinel".format(indicator_count_match_sentinel))

    duration = datetime.datetime.now(datetime.timezone.utc) - run_start
    logger.info("====== Run statistics ======")
    logger.info("  Duration                              : {}".format(str(duration).split(".")[0]))
    logger.info("  Dry run                               : {}".format(bool(config.dry_run)))
    logger.info("  Indicators pushed to Sentinel         : {}".format(total_indicators))
    if config.ms_check_if_exist_in_sentinel:
        logger.info("  Indicators skipped (already present)  : {}".format(indicator_count_match_sentinel))
    if config.misp_decay_model_enabled:
        logger.info("  Indicators skipped (decay model)      : {}".format(indicator_count_decay_skipped))
    if args.verify_recent_toids_change:
        logger.info("  to_ids deletions (deleted/not found)  : {} / {}".format(toids_deleted, toids_not_found))
    if args.delete_outdated_indicators:
        logger.info("  Outdated deletions (deleted/failed)   : {} / {}".format(outdated_deleted, outdated_failed))
    logger.info("============================")


if __name__ == '__main__':
    logger = _build_logger()    
    logger.info("====== Start MISP2Sentinel ======")
    logger.info("Initializing configuration")
    init_configuration()
    main()
    logger.info("====== End MISP2Sentinel ======")

