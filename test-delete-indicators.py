"""
Reproducer for Microsoft Sentinel Threat Intelligence delete inconsistency.

Steps:
  1. List the 100 most recent threat intelligence indicators in the workspace.
  2. DELETE each one by name via the management API.
  3. GET each deleted indicator by name (expecting HTTP 404).
  4. Query the same list again and report how many of the just-deleted
     indicators are still returned.

Expected behaviour: step 3 returns 404 for all, step 4 returns 0 of the
deleted indicators.
Observed behaviour: step 3 returns 404 for all (resource is gone), but
step 4 keeps returning the same 100 indicators.
"""

import logging
import re
import sys

import requests

import config
from constants import CLIENT_ID, CLIENT_SECRET, SCOPE, TENANT
from RequestManager import RequestManager


API_VERSION = "2025-09-01"
HOW_MANY = 100
SOURCE = getattr(config, "sourcesystem", "MISP")

BASE_URL = (
    "https://management.azure.com"
    "/subscriptions/{sub}/resourceGroups/{rg}/providers"
    "/Microsoft.OperationalInsights/workspaces/{ws}/providers"
    "/Microsoft.SecurityInsights/threatIntelligence/main"
).format(
    sub=config.ms_auth["subscription_id"],
    rg=config.ms_auth["resourceGroupName"],
    ws=config.ms_auth["workspaceName"],
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("delete-test")


def get_session():
    rm = RequestManager(0, log, config.ms_auth[TENANT])
    token = rm._get_access_token(
        config.ms_auth[TENANT],
        config.ms_auth[CLIENT_ID],
        config.ms_auth[CLIENT_SECRET],
        config.ms_auth[SCOPE],
    )
    s = requests.Session()
    s.headers.update({
        "Authorization": "Bearer " + token,
        "content-type": "application/json",
        "user-agent": getattr(config, "ms_useragent", "MISP-1.0"),
    })
    return s


def list_latest_indicators(session, count):
    """Return up to `count` most recent indicators for SOURCE."""
    url = "{}/queryIndicators?api-version={}".format(BASE_URL, API_VERSION)
    body = {
        "pageSize": count,
        "includeDisabled": True,
        "sources": [SOURCE],
        "sortBy": [{"itemKey": "lastUpdatedTimeUtc", "sortOrder": "descending"}],
    }
    r = session.post(url, json=body, timeout=60)
    r.raise_for_status()
    return r.json().get("value", [])[:count]


def delete_indicator(session, name):
    url = "{}/indicators/{}?api-version={}".format(BASE_URL, name, API_VERSION)
    return session.delete(url, timeout=60).status_code


def get_indicator(session, name):
    url = "{}/indicators/{}?api-version={}".format(BASE_URL, name, API_VERSION)
    return session.get(url, timeout=60).status_code


def extract_value(props):
    """Pull the IOC value out of an indicator's properties."""
    for entry in props.get("parsedPattern", []) or []:
        for v in entry.get("patternTypeValues", []) or []:
            if v.get("value"):
                return str(v["value"])
    m = re.search(r"'([^']+)'", props.get("pattern", "") or "")
    return m.group(1) if m else ""


def main():
    session = get_session()

    log.info("Step 1: querying the latest %d indicators (source=%s)", HOW_MANY, SOURCE)
    indicators = list_latest_indicators(session, HOW_MANY)
    deleted_names = [i["name"] for i in indicators if i.get("name")]
    log.info("Step 1: got %d indicators", len(deleted_names))
    for i in indicators:
        p = i.get("properties", {})
        log.info("  id=%s value=%s externalId=%s",
                 i.get("name"), extract_value(p), p.get("externalId"))

    log.info("Step 2: deleting each indicator by name")
    ok = fail = 0
    for name in deleted_names:
        status = delete_indicator(session, name)
        if status in (200, 204):
            ok += 1
        else:
            fail += 1
            log.error("DELETE %s -> %s", name, status)
    log.info("Step 2: DELETE results -> success=%d failed=%d", ok, fail)

    log.info("Step 3: GET each deleted indicator by name (expect 404)")
    got_404 = got_200 = got_other = 0
    for name in deleted_names:
        status = get_indicator(session, name)
        if status == 404:
            got_404 += 1
        elif status == 200:
            got_200 += 1
        else:
            got_other += 1
            log.warning("GET %s -> %s", name, status)
    log.info("Step 3: GET results -> 404=%d 200=%d other=%d",
             got_404, got_200, got_other)

    log.info("Step 4: re-querying the latest %d indicators", HOW_MANY)
    again = list_latest_indicators(session, HOW_MANY)
    again_by_name = {i.get("name"): i for i in again}
    still_listed = [n for n in deleted_names if n in again_by_name]

    log.info("Step 4: query returned %d indicators", len(again))
    log.info(
        "Step 4: %d of the %d deleted indicators are STILL returned by queryIndicators",
        len(still_listed), len(deleted_names),
    )

    for name in still_listed:
        p = again_by_name[name].get("properties", {})
        log.info("  STILL LISTED id=%s value=%s externalId=%s",
                 name, extract_value(p), p.get("externalId"))


if __name__ == "__main__":
    main()
