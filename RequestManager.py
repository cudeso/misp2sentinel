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

class RequestManager:
    """A class that handles submitting TiIndicators to MS Graph Security API

    to use the class:
        with RequestManager() as request_manager:
            request_manager.handle_indicator(tiindicator)

    """

    RJUST = 5

    def __init__(self, total_indicators, logger):
        self.total_indicators = total_indicators
        self.logger = logger

    def __enter__(self):
        try:
            self.existing_indicators_hash_fd = open(EXISTING_INDICATORS_HASH_FILE_NAME, 'r+')
            self.existing_indicators_hash = json.load(self.existing_indicators_hash_fd)
        except (FileNotFoundError, json.decoder.JSONDecodeError):
            self.existing_indicators_hash_fd = open(EXISTING_INDICATORS_HASH_FILE_NAME, 'w')
            self.existing_indicators_hash = {}
        try:
            self.expiration_date_fd = open(EXPIRATION_DATE_FILE_NAME, 'r+')
            self.expiration_date = self.expiration_date_fd.read()
        except FileNotFoundError:
            self.expiration_date_fd = open(EXPIRATION_DATE_FILE_NAME, 'w')
            self.expiration_date = self._get_expiration_date_from_config()
        if self.expiration_date <= datetime.datetime.utcnow().strftime('%Y-%m-%d'):
            self.existing_indicators_hash = {}
            self.expiration_date = self._get_expiration_date_from_config()
        self.hash_of_indicators_to_delete = copy.deepcopy(self.existing_indicators_hash)
        # print(f"hash of indicators to delete {self.hash_of_indicators_to_delete}")
        access_token = self._get_access_token(
            config.ms_auth[TENANT],
            config.ms_auth[CLIENT_ID],
            config.ms_auth[CLIENT_SECRET],
            config.ms_auth[SCOPE])
        self.headers = {"Authorization": f"Bearer {access_token}", "user-agent": config.ms_useragent, "content-type": "application/json"}
        self.headers_expiration_time = self._get_timestamp() + 3500
        self.success_count = 0
        self.error_count = 0
        self.del_count = 0
        self.indicators_to_be_sent = []
        self.indicators_to_be_sent_size = 0
        self.start_time = self.last_batch_done_timestamp = self._get_timestamp()
        if not os.path.exists(LOG_DIRECTORY_NAME):
            os.makedirs(LOG_DIRECTORY_NAME)
        return self

    @staticmethod
    def _get_expiration_date_from_config():
        return (datetime.datetime.utcnow() + datetime.timedelta(config.days_to_expire)).strftime('%Y-%m-%d')

    def _get_access_token(self, tenant, client_id, client_secret, scope):
        data = {
            CLIENT_ID: client_id,
            'scope': scope,
            CLIENT_SECRET: client_secret,
            'grant_type': 'client_credentials'
        }

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

    def read_tiindicators(self):
        access_token = RequestManager._get_access_token(
            config.ms_auth[TENANT],
            config.ms_auth[CLIENT_ID],
            config.ms_auth[CLIENT_SECRET])

        res = requests.get(
            GRAPH_TI_INDICATORS_URL,
            headers={"Authorization": f"Bearer {access_token}"}
            ).json()
        if config.verbose_log:
            self.logger.info(res, indent=2)

    @staticmethod
    def _get_request_hash(request):
        return hashlib.sha256(
            json.dumps(
                {
                    k: v for k, v in request.items()
                    if k not in ("expirationDateTime", "lastReportedDateTime")
                },
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()

    def _log_post(self, response):
        # self._clear_screen()
        cur_batch_success_count = cur_batch_error_count = 0
        if config.verbose_log:
            self.logger.debug("Response: {}".format(response))

        if 'error' in response:
            self.error_count += 1
            cur_batch_error_count += 1
            file_name = f"{self._get_datetime_now()}_error.json"
            log_file_name = file_name.replace(':', '')
            with open(f'{LOG_DIRECTORY_NAME}/{log_file_name}', 'w') as file:
                json.dump(response['error'], file)
        else:
            if len(response['value']) > 0:
                for value in response['value']:
                    if "Error" in value:
                        self.error_count += 1
                        cur_batch_error_count += 1
                        file_name = f"{self._get_datetime_now()}_error_{value[INDICATOR_REQUEST_HASH]}.json"
                        log_file_name = file_name.replace(':', '')
                        with open(f'{LOG_DIRECTORY_NAME}/{log_file_name}', 'w') as file:
                            json.dump(value, file)
                    else:
                        self.success_count += 1
                        cur_batch_success_count += 1
                        self.existing_indicators_hash[value[INDICATOR_REQUEST_HASH]] = value['id']
                        # if not config.verbose_log:
                        #     continue
                        file_name = f"{self._get_datetime_now()}_{value[INDICATOR_REQUEST_HASH]}.json"
                        log_file_name = file_name.replace(':', '')
                        if config.write_post_json:
                            with open(f'{LOG_DIRECTORY_NAME}/{log_file_name}', 'w') as file:
                                json.dump(value, file)
            else:
                file_name = f"{self._get_datetime_now()}.json"
                log_file_name = file_name.replace(':', '')
                if config.write_post_json:
                    with open(f'{LOG_DIRECTORY_NAME}/{log_file_name}', 'w') as file:
                        json.dump(response, file)

        self.logger.info("Sending security indicators to Microsoft Graph Security")
        self.logger.info("{} indicators are parsed from MISP events. Only those that do not exist in Microsoft Graph Security will be sent.".format(self.total_indicators))

    @staticmethod
    def _get_datetime_now():
        return str(datetime.datetime.now()).replace(' ', '_')

    def __exit__(self, exc_type, exc_val, exc_tb):

        if config.ms_auth["graph_api"]:
            self._post_to_graph()
            self._del_indicators_no_longer_exist()

            self.expiration_date_fd.seek(0)
            self.expiration_date_fd.write(self.expiration_date)
            self.expiration_date_fd.truncate()

            self.existing_indicators_hash_fd.seek(0)
            json.dump(self.existing_indicators_hash, self.existing_indicators_hash_fd, indent=2)
            self.existing_indicators_hash_fd.truncate()

            self._print_summary()

    def _del_indicators_no_longer_exist(self):
        indicators = list(self.hash_of_indicators_to_delete.values())
        self.del_count = len(indicators)
        for i in range(0, len(indicators), 100):
            request_body = {'value': indicators[i: i+100]}
            if config.verbose_log:
                self.logger.debug(request_body)
            response = requests.post(GRAPH_BULK_DEL_URL, headers=self.headers, json=request_body).json()
            file_name = f"del_{self._get_datetime_now()}.json"
            log_file_name = file_name.replace(':', '')
            if config.write_post_json:
                json.dump(response, open(f'{LOG_DIRECTORY_NAME}/{log_file_name}', 'w'), indent=2)
        for hash_of_indicator_to_delete in self.hash_of_indicators_to_delete.keys():
            self.existing_indicators_hash.pop(hash_of_indicator_to_delete, None)

    def _print_summary(self):
        self.logger.info("Script finished running")
        self.logger.info("Total indicators sent:    {}".format(str(self._get_total_indicators_sent()).rjust(self.RJUST)))
        self.logger.info("Total response success:   {}".format(str(self.success_count).rjust(self.RJUST)))
        self.logger.info("Total response error:     {}".format(str(self.error_count).rjust(self.RJUST)))
        self.logger.info("Total indicators deleted: {}".format(str(self.del_count).rjust(self.RJUST)))

    def _post_to_graph(self):
        request_body = {'value': self.indicators_to_be_sent}
        response = requests.post(GRAPH_BULK_POST_URL, headers=self.headers, json=request_body).json()
        self.indicators_to_be_sent = []
        self._log_post(response)

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
            request_url = f"https://sentinelus.azure-api.net/{workspace_id}/threatintelligence:upload-indicators?api-version={api_version}"
            request_body = {"sourcesystem": config.sourcesystem, "value": parsed_indicators[:config.ms_max_indicators_request]}

            # Setting result retry as true to enter the loop
            result = {"retry": True, "breakRun": False}

            while result.get("retry", True):
                response = requests.post(request_url, headers=self.headers, json=request_body)
                result = self.handle_response_codes(response, safe_margin, requests_number, request_body, parsed_indicators)
                # If retry is true, retry the request, otherwise continue to the next indicator
                if result.get("retry", False):
                    requests_number += 1
                # If breakRun is true, break out of the loop
                if result.get("breakRun", True):
                    break
                # Update parsed_indicators with the remaining indicators
                parsed_indicators = result.get("parsed_indicators", parsed_indicators)

    def handle_response_codes(self, response, safe_margin, requests_number, request_body, parsed_indicators):
        self.logger.debug(response)
        status_code = response.status_code
        result = {}
        switcher = {
            429: lambda: self.handle_rate_limit_exceeded(response, safe_margin, parsed_indicators),
            200: lambda: self.handle_success_response(response, request_body, parsed_indicators, requests_number),
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
    
    def handle_success_response(self, response, request_body, parsed_indicators, requests_number):
        if "errors" in response.json() and len(response.json()["errors"]) > 0:
            if config.sentinel_write_response:
                json_formatted_str = json.dumps(response.json(), indent=4)
                with open("sentinel_response.txt", "a") as fp:
                    fp.write(json_formatted_str)
            self.logger.error("Error when submitting indicators - error string received from Sentinel. {}".format(response.text))
            return {"retry": False, "breakRun": True}
        else:
            parsed_indicators = parsed_indicators[config.ms_max_indicators_request:]
            self.logger.info(
                "Indicators sent - request number: {} / indicators: {} / remaining: {}".format(requests_number, len(request_body["value"]), len(parsed_indicators)))
            return {"retry": False, "breakRun": False, "parsed_indicators": parsed_indicators}

    def handle_error_response(self, response):
        self.logger.error("Error when submitting indicators. Non HTTP-200 response. {}".format(response.text))
        return {"retry": False, "breakRun": True}
    
    def handle_indicator(self, indicator):
        self._update_headers_if_expired()
        indicator[EXPIRATION_DATE_TIME] = self.expiration_date
        indicator_hash = self._get_request_hash(indicator)
        indicator[INDICATOR_REQUEST_HASH] = indicator_hash
        self.hash_of_indicators_to_delete.pop(indicator_hash, None)
        if indicator_hash not in self.existing_indicators_hash:
            self.indicators_to_be_sent.append(indicator)
        if len(self.indicators_to_be_sent) >= 100:
            self.logger.info("Number of indicators sent: {}".format(self.success_count+self.error_count))
            self._post_to_graph()

    def _update_headers_if_expired(self):
        if self._get_timestamp() > self.headers_expiration_time:
            access_token = self._get_access_token(
                config.ms_auth[TENANT],
                config.ms_auth[CLIENT_ID],
                config.ms_auth[CLIENT_SECRET],
                config.ms_auth[SCOPE])
            self.headers = {"Authorization": f"Bearer {access_token}", "user-agent": config.ms_useragent, "content-type": "application/json"}

    @staticmethod
    def _clear_screen():
        if os.name == 'posix':
            os.system('clear')
        else:
            os.system('cls')

    @staticmethod
    def _get_timestamp():
        return datetime.datetime.now().timestamp()

    def _get_total_indicators_sent(self):
        return self.error_count + self.success_count