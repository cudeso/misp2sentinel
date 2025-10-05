import requests
import config
import datetime
import os
import json
import copy
import hashlib
from constants import *
import time
import sys
import logging


class RequestManager:
    def __init__(self, total_indicators, logger, tenant):
        self.total_indicators = total_indicators
        self.logger = logger
        self.tenant = tenant

    def __enter__(self):
        try:
            self.existing_indicators_hash_fd = open(EXISTING_INDICATORS_HASH_FILE_NAME+self.tenant+".json", 'r+')
            self.existing_indicators_hash = json.load(self.existing_indicators_hash_fd)
        except (FileNotFoundError, json.decoder.JSONDecodeError):
            self.existing_indicators_hash_fd = open(EXISTING_INDICATORS_HASH_FILE_NAME+self.tenant+".json", 'w')
            self.existing_indicators_hash = {}

        try:
            self.expiration_date_fd = open(EXPIRATION_DATE_FILE_NAME+self.tenant+".txt", 'r+')
            self.expiration_date = self.expiration_date_fd.read()
        except FileNotFoundError:
            self.expiration_date_fd = open(EXPIRATION_DATE_FILE_NAME+self.tenant+".txt", 'w')
            self.expiration_date = self._get_expiration_date_from_config()

        if self.expiration_date <= datetime.datetime.utcnow().strftime('%Y-%m-%d'):
            self.existing_indicators_hash = {}
            self.expiration_date = self._get_expiration_date_from_config()

        access_token = self._get_access_token(
            config.ms_auth[TENANT],
            config.ms_auth[CLIENT_ID],
            config.ms_auth[CLIENT_SECRET],
            config.ms_auth[SCOPE])
        self.headers = {"Authorization": f"Bearer {access_token}", "user-agent": config.ms_useragent, "content-type": "application/json"}
        self.headers_expiration_time = self._get_timestamp() + 3500
        self.indicators_to_be_sent = []
        self.indicators_to_be_sent_size = 0
        self.start_time = self.last_batch_done_timestamp = self._get_timestamp()
        if not os.path.exists(LOG_DIRECTORY_NAME):
            os.makedirs(LOG_DIRECTORY_NAME)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        True

    @staticmethod
    def _get_expiration_date_from_config():
        return (datetime.datetime.utcnow() + datetime.timedelta(config.days_to_expire)).strftime('%Y-%m-%d')

    #@staticmethod
    def _get_access_token(self, tenant, client_id, client_secret, scope):
        data = {
            CLIENT_ID: client_id,
            'scope': scope,
            CLIENT_SECRET: client_secret,
            'grant_type': 'client_credentials'
        }

        try:
            access_token_response = requests.post(
                f'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token',
                data=data
            ).json()
            if ACCESS_TOKEN in access_token_response:
                access_token = access_token_response[ACCESS_TOKEN]
                return access_token
            elif "error" in access_token_response:
                self.logger.error("Exiting. Error: {}".format(access_token_response["error_description"]))
                sys.exit("Exiting. Error: {}".format(access_token_response["error_description"]))
            else:
                self.logger.error("Exiting. No access token {} found.".format(ACCESS_TOKEN))
                sys.exit("Exiting. No access token {} found.".format(ACCESS_TOKEN))
        except requests.exceptions.RequestException as err:
            logging.error(f"Failed to get access token with: Tenant: {tenant} | ClientId: {client_id} | Scope: {scope} | Err: {err}")
        except Exception as e:
            logging.error(f"An unexpected error occurred: {e}")

    def upload_indicators(self, parsed_indicators):
        requests_number = 0
        start_timestamp = self._get_timestamp()
        safe_margin = 3
        while len(parsed_indicators) > 0:
            if requests_number >= config.ms_max_requests_minute:
                sleep_time = (config.ms_max_requests_minute + safe_margin) - (self._get_timestamp() - start_timestamp)
                if sleep_time > 0:
                    self.logger.info("Pausing upload for API request limit {}".format(sleep_time))
                    time.sleep(sleep_time)
                requests_number = 0
                start_timestamp = self._get_timestamp()
            self._update_headers_if_expired()
            workspace_id = config.ms_auth["workspace_id"]
            api_version = config.ms_api_version
            if config.ms_auth["new_upload_api"]:
                request_url = f"https://api.ti.sentinel.azure.com/workspaces/{workspace_id}/threat-intelligence-stix-objects:upload?api-version={api_version}"
                indicator_value_key = "stixobjects"
            else:
                request_url = f"https://sentinelus.azure-api.net/{workspace_id}/threatintelligence:upload-indicators?api-version={api_version}"
                indicator_value_key = "value"

            request_body = {"sourcesystem": config.sourcesystem, f"{indicator_value_key}": parsed_indicators[:config.ms_max_indicators_request]}

            # Setting result retry as true to enter the loop
            result = {"retry": True, "breakRun": False}

            while result.get("retry", True):
                response = requests.post(request_url, headers=self.headers, json=request_body)
                result = self.handle_response_codes(response, safe_margin, requests_number, request_body, parsed_indicators, indicator_value_key)
                # If retry is true, retry the request, otherwise continue to the next indicator
                if result.get("retry", False):
                    requests_number += 1
                # If breakRun is true, break out of the loop
                if result.get("breakRun", True):
                    break
                # Update parsed_indicators with the remaining indicators
                parsed_indicators = result.get("parsed_indicators", parsed_indicators)

    def handle_response_codes(self, response, safe_margin, requests_number, request_body, parsed_indicators, indicator_value_key):
        self.logger.debug("{} - {}".format(response.status_code, response.text))
        status_code = response.status_code
        result = {}
        switcher = {
            429: lambda: self.handle_rate_limit_exceeded(response, safe_margin, parsed_indicators),
            200: lambda: self.handle_success_response(response, request_body, parsed_indicators, requests_number, indicator_value_key),
        }
        result = switcher.get(status_code, lambda: self.handle_error_response(response))()
        self.logger.debug(result)
        return result

    def handle_rate_limit_exceeded(self, response, safe_margin, parsed_indicators):
        error_message = response.json()["message"]
        retry_after = int(error_message.split()[-2])
        self.logger.warning(f"Rate limit exceeded. Retrying after {retry_after} seconds.")
        time.sleep(retry_after + safe_margin)
        # Retry the request - go back one entry in the list (which had the error)
        parsed_indicators = parsed_indicators[config.ms_max_indicators_request-1:]
        return {"retry": True, "breakRun": False, "parsed_indicators": parsed_indicators}

    def handle_success_response(self, response, request_body, parsed_indicators, requests_number, indicator_value_key):
        try: # Check if response is JSON
            response_json = response.json()
        except ValueError as e:
            response_json = False

        if response_json and "errors" in response.json() and len(response.json()["errors"]) > 0:
            if config.sentinel_write_response:
                json_formatted_str = json.dumps(response.json(), indent=4)
                with open("sentinel_response.txt", "a") as fp:
                    fp.write(json_formatted_str)
            self.logger.error("Error when submitting indicators - error string received from Sentinel. {}".format(response.text))
            return {"retry": False, "breakRun": True}
        else:
            parsed_indicators = parsed_indicators[config.ms_max_indicators_request:]
            self.logger.info(
                "Indicators sent - request number: {} / indicators: {} / remaining: {}".format(requests_number, len(request_body[f"{indicator_value_key}"]), len(parsed_indicators)))
            return {"retry": False, "breakRun": False, "parsed_indicators": parsed_indicators}

    def handle_error_response(self, response):
        self.logger.error("Error when submitting indicators. Non HTTP-200 response. {}".format(response.text))
        return {"retry": False, "breakRun": True}

    def _update_headers_if_expired(self):
        if self._get_timestamp() > self.headers_expiration_time:
            access_token = self._get_access_token(
                config.ms_auth[TENANT],
                config.ms_auth[CLIENT_ID],
                config.ms_auth[CLIENT_SECRET],
                config.ms_auth[SCOPE])
            self.headers = {"Authorization": f"Bearer {access_token}", "user-agent": config.ms_useragent, "content-type": "application/json"}

    @staticmethod
    def _get_timestamp():
        return datetime.datetime.now().timestamp()
