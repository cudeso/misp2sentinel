from pymisp import *
import config
from collections import defaultdict
import datetime
from RequestManager import RequestManager
from RequestObject import RequestObject_Event, RequestObject_Indicator
from constants import *
import sys
import logging
import json

from stix2 import parse, exceptions
import requests

if config.misp_verifycert is False:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _build_logger():
    logger = logging.getLogger("misp2sentinel-deleteindicators")
    log_level = logging.DEBUG if config.verbose_log else logging.INFO
    logger.setLevel(log_level)
    
    ch = logging.FileHandler(config.log_file, mode="a")
    ch.setLevel(log_level)
    
    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    
    return logger


def get_headers(logger):
    rm = RequestManager(0, logger, config.ms_auth[TENANT])
    access_token = rm._get_access_token(
        config.ms_auth[TENANT], config.ms_auth[CLIENT_ID], config.ms_auth[CLIENT_SECRET], config.ms_auth[SCOPE]
    )
    
    if not access_token:
        logger.error("No access token obtained for checking existing indicators in Sentinel")
        return None
    
    return {
        "Authorization": f"Bearer {access_token}",
        "user-agent": "MISP-1.0",
        "content-type": "application/json"
    }


def get_indicators(logger, max_indicators):
    headers = get_headers(logger)
    if not headers:
        return None
    
    url = (
        f"https://management.azure.com/subscriptions/{config.ms_auth.get('subscription_id')}"
        f"/resourceGroups/{config.ms_auth.get('resourceGroupName')}"
        f"/providers/Microsoft.OperationalInsights/workspaces/{config.ms_auth.get('workspaceName')}"
        f"/providers/Microsoft.SecurityInsights/threatIntelligence/main/queryIndicators"
        f"?api-version=2025-09-01"
    )
    
    payload = {
        "pageSize": max_indicators,
        "includeDisabled": False,
        "sources": [config.sourcesystem],
        "sortBy": [
            {
                "itemKey": "lastUpdatedTimeUtc",
                "sortOrder": "descending"
            }
        ]
    }
    
    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=50)
        resp.raise_for_status()
        
        body = resp.json()
        return body.get("value") if isinstance(body, dict) else None
        
    except requests.exceptions.HTTPError as e:
        logger.error(f"Error querying indicators in Sentinel: {e.response.status_code} - {e.response.text}")
    except requests.exceptions.RequestException as e:
        logger.error(f"Request error when querying indicators: {str(e)}")
    except json.JSONDecodeError:
        logger.error("Error parsing JSON response from Sentinel when querying indicators")
    
    return None


def revoke_indicators(logger, headers, indicators):
    if not indicators:
        return 0

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
        return 0

    revoked_count = 0
    for i in range(0, len(stix_objects), 100):
        batch = stix_objects[i:i + 100]
        body = {"sourcesystem": config.sourcesystem, indicator_value_key: batch}
        try:
            resp = requests.post(upload_url, headers=headers, json=body, timeout=60)
            logger.debug(f"Revoke upload response: {resp.status_code} {resp.text[:500] if resp.text else '(empty)'}")
            if resp.status_code == 200:
                revoked_count += len(batch)
            else:
                logger.error(f"Error revoking indicators (batch {i // 100}): {resp.status_code} {resp.text[:500] if resp.text else '(empty)'}")
        except Exception as e:
            logger.error(f"Exception revoking indicators (batch {i // 100}): {e}")

    return revoked_count


def main():
    logger = _build_logger()
    logger.info("Start MISP2Sentinel - Delete indicators from Azure Sentinel")
    
    sentinel_indicators = get_indicators(logger, max_indicators=10)
    indicator_count = len(sentinel_indicators) if sentinel_indicators else 0
    logger.info(f"Got {indicator_count} results from Sentinel")
    
    if not sentinel_indicators:
        logger.info("No indicators to delete")
        return
    
    headers = get_headers(logger)
    if not headers:
        logger.error("Failed to get authentication headers")
        return
    
    revoked = revoke_indicators(logger, headers, sentinel_indicators)
    logger.info(f"Revoked {revoked} indicators via STIX Objects API")
    
    logger.info("End MISP2Sentinel - Delete")


if __name__ == '__main__':
    main()
