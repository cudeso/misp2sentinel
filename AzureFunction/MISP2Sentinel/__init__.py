from pymisp import *
import MISP2Sentinel.config as config
from MISP2Sentinel.RequestManager import RequestManager
from MISP2Sentinel.RequestObject import RequestObject_Event, RequestObject_Indicator
from MISP2Sentinel.constants import *
import sys
import os
import datetime
import logging
import azure.functions as func
import requests
import json

from stix2 import parse, exceptions
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
        url = f"https://management.azure.com/subscriptions/{config.ms_auth.get('subscription_id')}/resourceGroups/{config.ms_auth.get('resourceGroupName')}/providers/Microsoft.OperationalInsights/workspaces/{config.ms_auth.get('workspaceName')}/providers/Microsoft.SecurityInsights/threatIntelligence/main/queryIndicators?api-version=2025-06-01"
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


def get_misp_events_upload_indicators():
    misp = PyMISP(config.misp_domain, config.misp_key, config.misp_verifycert, False)

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
        access_token = rm._get_access_token(
            config.ms_auth[TENANT], config.ms_auth[CLIENT_ID], config.ms_auth[CLIENT_SECRET], config.ms_auth[SCOPE]
        )
        if access_token:
            sentinel_session = requests.Session()
            sentinel_session.headers.update({
                "Authorization": f"Bearer {access_token}",
                "user-agent": config.ms_useragent,
                "content-type": "application/json"
            })
            sentinel_headers_expiry = datetime.datetime.now().timestamp() + 3500

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
                                            if datetime.datetime.now().timestamp() > sentinel_headers_expiry:
                                                access_token = rm._get_access_token(
                                                    config.ms_auth[TENANT], config.ms_auth[CLIENT_ID], config.ms_auth[CLIENT_SECRET], config.ms_auth[SCOPE]
                                                )
                                                if access_token:
                                                    sentinel_session.headers["Authorization"] = f"Bearer {access_token}"
                                                    sentinel_headers_expiry = datetime.datetime.now().timestamp() + 3500
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
        config.misp_flatten_attributes = True
    if not hasattr(config, "sourcesystem"):
        config.sourcesystem = "MISP"
    if not hasattr(config, "dry_run"):
        config.dry_run = False
    if not hasattr(config, "remove_pipe_from_misp_attribute"):
        config.remove_pipe_from_misp_attribute = True
    if not hasattr(config, "ms_check_if_exist_in_sentinel"):
        config.ms_check_if_exist_in_sentinel = False

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


def write_parsed_indicators(parsed_indicators):
    json_formatted_str = json.dumps(parsed_indicators, indent=4)
    with open(PARSED_INDICATORS_FILE_NAME, "a") as fp:
        fp.write(json_formatted_str)


def push_to_sentinel(tenant, id, secret, workspace):
    config.ms_auth[TENANT] = tenant
    config.ms_auth[CLIENT_ID] = id
    config.ms_auth[CLIENT_SECRET] = secret
    config.ms_auth[WORKSPACE_ID] = workspace
    logger.info(f"Tenant: {tenant}")
    logger.info(f"Client ID: {id}")
    logger.info(f"Workspace ID: {workspace}")
    obfuscated_secret = secret[:-5] + '*' * 5
    logger.info(f"Client Secret (obfuscated): {obfuscated_secret}")

    logger.info("Fetching and parsing data from MISP {}".format(config.misp_domain))
    logger.info("Using Microsoft Upload Indicator API")
    total_indicators, indicator_count_match_sentinel = get_misp_events_upload_indicators()
    logger.info("Pushed {} indicators from MISP to Sentinel".format(total_indicators))
    if config.ms_check_if_exist_in_sentinel:
        logger.info("Skipped {} MISP indicators because they were already in Sentinel".format(indicator_count_match_sentinel))


def pmain(logger):
    tenants_env = os.getenv('tenants', '')
    if tenants_env:
        if tenants_env.startswith('@Microsoft.KeyVault'):
            logger.error("Key Vault reference for 'tenants' was not resolved. Check the function app identity and Key Vault access policy.")
            return
        tenants = json.loads(tenants_env)
        for item in tenants:
            for key in ('tenantId', 'id', 'secret', 'workspaceId'):
                if key not in item:
                    logger.error("Missing key '{}' in tenants configuration. Expected keys: tenantId, id, secret, workspaceId".format(key))
                    return
            push_to_sentinel(item['tenantId'], item['id'], item['secret'], item['workspaceId'])
    else:
        tenant = config.ms_auth[TENANT]
        id = config.ms_auth[CLIENT_ID]
        secret = config.ms_auth[CLIENT_SECRET]
        workspace = config.ms_auth[WORKSPACE_ID]
        push_to_sentinel(tenant, id, secret, workspace)


def main(mytimer: func.TimerRequest) -> None:
    check_for_old_config = _init_configuration()

    global logger
    logger = _build_logger()

    utc_timestamp = datetime.datetime.utcnow().replace(
        tzinfo=datetime.timezone.utc).isoformat()

    if mytimer.past_due:
        logger.info('The timer is past due!')

    logger.info("Start MISP2Sentinel")
    if check_for_old_config:
        logger.info("You're using an older configuration setting. Update config.py to the new configuration setting.")
    pmain(logger)
    logger.info("End MISP2Sentinel")
    logger.info('Python timer trigger function ran at %s', utc_timestamp)
