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
        f"?api-version=2025-06-01"
    )
    
    payload = {
        "pageSize": max_indicators,
        "includeDisabled": False,
        "sources": ["MISP"],
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


def delete_indicator(logger, headers, indicator_name):
    delete_url = (
        f"https://management.azure.com/subscriptions/{config.ms_auth.get('subscription_id')}"
        f"/resourceGroups/{config.ms_auth.get('resourceGroupName')}"
        f"/providers/Microsoft.OperationalInsights/workspaces/{config.ms_auth.get('workspaceName')}"
        f"/providers/Microsoft.SecurityInsights/threatIntelligence/main/indicators/{indicator_name}"
        f"?api-version=2025-06-01"
    )
    
    try:
        response = requests.delete(delete_url, headers=headers, timeout=30)
        response.raise_for_status()
        logger.info(f"Deleted indicator successfully: {indicator_name}")
        return True
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to delete indicator: {indicator_name} - {str(e)}")
        return False


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
    
    for indicator in sentinel_indicators:
        indicator_name = indicator.get("name")
        if indicator_name:
            delete_indicator(logger, headers, indicator_name)
    
    logger.info("End MISP2Sentinel - Delete")


if __name__ == '__main__':
    main()
