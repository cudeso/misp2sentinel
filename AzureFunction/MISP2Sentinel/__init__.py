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

mispkey=os.getenv('mispkey')

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
            'action': config.action,
            'passiveOnly': config.passiveOnly,
            'targetProduct': config.targetProduct,
        }

        if len(request_body_metadata.get('threatType', [])) < 1:
            request_body_metadata['threatType'] = 'watchlist'
        if config.defaultConfidenceLevel:
            request_body_metadata["confidence"] = config.defaultConfidenceLevel
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


def pmain():
    if '-r' in sys.argv:
        print("Retrieve indicators from Sentinel")
        RequestManager.read_tiindicators()
        sys.exit()

    if '-d' in sys.argv:
        print("Delete indicators from Sentinel")
        # Delete an indicator
        request_manager = RequestManager(0)
        access_token = request_manager._get_access_token(
            config.graph_auth[TENANT],
            config.graph_auth[CLIENT_ID],
            config.graph_auth[CLIENT_SECRET])
        headers = {"Authorization": f"Bearer {access_token}", 'user-agent': 'MISP/1.0'}
        request_body = {'value': [sys.argv[2]]}
        response = requests.post(GRAPH_BULK_DEL_URL, headers=headers, json=request_body).json()
        print(json.dumps(response, indent=2))
        sys.exit()

    config.verbose_log = ('-v' in sys.argv)
    tenants = json.loads(os.getenv('tenants'))
    print('fetching & parsing data from misp...')
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
    for key, value in tenants.items():
        logging.info('Writing to tenant {}'.format(key))
        config.graph_auth[TENANT] = key
        config.graph_auth[CLIENT_ID] = value['id']
        config.graph_auth[CLIENT_SECRET] = value['secret']
        logging.info('GraphAuth_tenant: {}'.format(config.graph_auth[TENANT]))
        logging.info('GraphAuth_id: {}'.format(config.graph_auth[CLIENT_ID]))

        with RequestManager(total_indicators) as request_manager:
            for request_body in _graph_post_request_body_generator(parsed_events):
                if config.verbose_log:
                    print(f"request body: {request_body}")
                request_manager.handle_indicator(request_body)


def main(mytimer: func.TimerRequest) -> None:
    utc_timestamp = datetime.datetime.utcnow().replace(
        tzinfo=datetime.timezone.utc).isoformat()

    if mytimer.past_due:
        logging.info('The timer is past due!')

    pmain()
    logging.info('Python timer trigger function ran at %s', utc_timestamp)
