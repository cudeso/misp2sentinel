graph_auth = {
    'tenant': '<tenant id>',
    'client_id': '<client id>',
    'client_secret': '<client secret>',
}
targetProduct = 'Azure Sentinel'
action = 'alert'

misp_event_filters = {
    "published": 1,
    "tags": [ "workflow:state=\"complete\""],
    "to_ids": 1,
}

passiveOnly = False
days_to_expire = 60
misp_key = '<misp api_key>'
misp_domain = '<misp url>'
misp_verifycert = False

network_ignore_direction = True

verbose_log = True
write_post_json = False
misp_ignore_localtags = True
defaultConfidenceLevel = 50
