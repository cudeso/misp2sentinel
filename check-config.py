from pymisp import *
import config

import sys
import requests
import json

if config.misp_verifycert is False:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


if __name__ == '__main__':

    print("Testing MISP")
    try:
        misp = PyMISP(config.misp_domain, config.misp_key, config.misp_verifycert)
        print("Searching for one event")
        result = misp.search(controller='events', return_format='json', **config.misp_event_filters, limit=1)
        if len(result) > 0:
            print("Found one event: ", result[0]["Event"]["info"])
            print("MISP connection OK")
        else:
            print("No MISP events returned")
            print("Are there events in the MISP server?")
    except:
        print("Unable to authenticate to MISP")

    print("Testing Azure")
    data = {'client_id': config.ms_auth['client_id'], 'scope': config.ms_auth['scope'], 'client_secret': config.ms_auth['client_secret'], 'grant_type': 'client_credentials'}
    tenant = config.ms_auth['tenant']
    access_token_response = requests.post(f'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token', data=data).json()
    
    print(access_token_response)
    if 'access_token' in access_token_response:
        print("Got an access token")
        print("Azure connection OK")
    elif "error" in access_token_response:
        print("Azure connection not OK. Insufficient permissions or wrong credentials supplied")
        sys.exit("Exiting. Error: {}".format(access_token_response["error_description"]))        
    else:
        print("Azure connection not OK.") 
        sys.exit("Exiting. No access token found.")
