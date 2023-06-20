import os
mispkey=os.getenv('mispkey')
mispurl=os.getenv('mispurl')

graph_auth = {
    'tenant': '',
    'client_id': '',
    'client_secret': '',
}
targetProduct = 'Azure Sentinel'
action = 'alert'

misp_event_filters = {
  "type_attribute": ['ip-src','ip-dst','url'],
  "timestamp": "7d"
}

passiveOnly = False
days_to_expire = 30
misp_key = mispkey
misp_domain = mispurl
misp_verifycert = False

network_ignore_direction = True

verbose_log = True
write_post_json = False
misp_ignore_localtags = True
defaultConfidenceLevel = 50
