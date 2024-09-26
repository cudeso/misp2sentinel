from distutils.command.config import config
import config
from constants import *
from datetime import datetime, timedelta
from stix2.base import STIXJSONEncoder
from stix2.utils import STIXdatetime
import json


class RequestObject_Indicator:
    def _get_dict(self):
        dict = {}
        dict["indicator_types"] = self.indicator_types
        dict["confidence"] = self.confidence
        dict["object_marking_refs"] = self.object_marking_refs
        dict["external_references"] = self.external_references
        dict["valid_from"] = json.dumps(self.valid_from, cls=STIXJSONEncoder).replace("\"", "")
        dict["valid_until"] = json.dumps(self.valid_until, cls=STIXJSONEncoder).replace("\"", "")
        dict["labels"] = self.labels
        dict["type"] = self.type
        dict["spec_version"] = self.spec_version
        dict["id"] = self.id
        dict["created_by_ref"] = self.created_by_ref
        dict["created"] = json.dumps(self.created, cls=STIXJSONEncoder).replace("\"", "")
        dict["modified"] = json.dumps(self.modified, cls=STIXJSONEncoder).replace("\"", "")
        dict["description"] = self.description
        dict["name"] = self.name
        dict["pattern"] = self.pattern
        dict["pattern_type"] = self.pattern_type
        dict["pattern_version"] = self.pattern_version
        dict["kill_chain_phases"] = self.kill_chain_phases
        dict["revoked"] = self.revoked
        return dict

    def __init__(self, element, misp_event, logger):
        self.misp_event = misp_event
        self.logger = logger

        if not hasattr(element, "id"):
            self.id = False
        if not hasattr(element, "indicator_types"):
            self.indicator_types = []
        if not hasattr(element, "confidence"):
            self.confidence = config.default_confidence
        if not hasattr(element, "description"):
            self.description = ""
        if not hasattr(element, "object_marking_refs"):
            self.object_marking_refs = []
        if not hasattr(element, "external_references"):
            self.external_references = []
        if not hasattr(element, "kill_chain_phases"):
            self.kill_chain_phases = []
        if not hasattr(element, "valid_from"):
            self.valid_from = False
        if not hasattr(element, "valid_until"):
            self.valid_until = False
        sentinel_threattype = False
        filtered_labels = []
        filtered_kill_chain_phases = []

        # Convert all the STIX indicator elements (we already set some previously, catch the remaining properties)
        for el in element:
            setattr(self, el, element[el])

        if self.pattern_type.strip().lower() != "stix":
            self.id = False
            logger.error("Ignoring non STIX pattern type {}".format(self.pattern_type))
        elif not self.id:
            logger.error("Ignoring indicator without ID {}".format(self.pattern))
        else:
            if len(self.description) > 0:
                self.description = "{} - {}".format(self.description, misp_event.name)
            else:
                self.description = "{}".format(misp_event.name)

            for label in self.labels:
                label = label.strip()
                ignore_tag = False
                if config.ignore_localtags:
                    # Not ideal for speed; but we don't have the "local" status of the tag
                    for lookup_attribute in self.misp_event.event["Attribute"]:
                        if "indicator--{}".format(lookup_attribute["uuid"]) == element.id:
                            for tag in lookup_attribute.get("Tag", []):
                                if tag["name"].strip() == label and tag["local"] == 1:
                                    ignore_tag = True
                                    break
                    for lookup_object in self.misp_event.event["Object"]:
                        for lookup_attribute in lookup_object["Attribute"]:
                            if "indicator--{}".format(lookup_attribute["uuid"]) == element.id:
                                for tag in lookup_attribute.get("Tag", []):
                                    if tag["name"].strip() == label and tag["local"] == 1:
                                        ignore_tag = True
                                        break

                if not ignore_tag:
                    if "misp:type=" in label:
                        misp_type = label.split("=")[1].strip('"')
                        if misp_type not in UPLOAD_INDICATOR_MISP_ACCEPTED_TYPES:
                            logger.debug("Skipping type {}".format(misp_type))
                            break
                    elif MISP_CONFIDENCE["prefix"] in label.lower():
                        confidence_tag = label.lower().split("{}=".format(MISP_CONFIDENCE["prefix"]))[1].replace("\"", "")
                        for confidence in MISP_CONFIDENCE["matches"]:
                            if confidence == confidence_tag:
                                self.confidence = MISP_CONFIDENCE["matches"][confidence]
                    elif "sentinel-threattype" in label:
                        sentinel_threattype = label.split("sentinel-threattype:")[1].strip()
                        if sentinel_threattype not in self.indicator_types:
                            self.indicator_types.append(sentinel_threattype)
                    elif 'kill-chain:' in label:
                        kill_chain = label.split(':')[1]
                        if KILL_CHAIN_MARKING_OBJECT_DEFINITION.get(kill_chain):
                            filtered_kill_chain_phases.append({"kill_chain_name": "lockheed-martin-cyber-kill-chain", "phase_name": kill_chain})
                            self.object_marking_refs.append(KILL_CHAIN_MARKING_OBJECT_DEFINITION[kill_chain])
                    else:
                        filtered_labels.append(label)
            self.labels = filtered_labels

            if not sentinel_threattype:
                if not misp_event.sentinel_threattype:
                    self.indicator_types.append(SENTINEL_DEFAULT_THREATTYPE)

            if misp_event.tlp:
                self.object_marking_refs.append(TLP_MARKING_OBJECT_DEFINITION[misp_event.tlp])

            self.name = "{} {}".format(misp_event.info, element.get("name", "")).strip()

            # Fix kill_chain_phases https://github.com/MISP/misp-stix/issues/47
            for phase in self.kill_chain_phases:
                '''if phase.phase_name == "network":
                    phases.append({"kill_chain_name": "misp-category", "phase_name": "Network activity"})
                else:
                    phases.append({"kill_chain_name": phase.kill_chain_name, "phase_name": phase.phase_name})'''
                filtered_kill_chain_phases.append({"kill_chain_name": phase.kill_chain_name, "phase_name": phase.phase_name})
            self.kill_chain_phases = filtered_kill_chain_phases

            # Link to MISP event
            self.external_references.append({
                                            "source_name": "MISP",
                                            "description": "MISP Event: {}".format(misp_event.info),
                                            "external_id": misp_event.uuid,
                                            "url": "{}/events/view/{}".format(config.misp_domain, misp_event.uuid)
                                            })

            date_object = False
            # Set the valid_until if not set by MISP (never ; https://github.com/MISP/misp-stix/issues/1)
            if config.days_to_expire_ignore_misp_last_seen or not self.valid_until:
                days_to_expire = config.days_to_expire

                # If we have a mapping, then we use a custom number of days to expire
                if hasattr(config, "days_to_expire_mapping"):
                    for el in config.days_to_expire_mapping:
                        if el.strip().lower() in self.pattern:
                            days_to_expire = config.days_to_expire_mapping[el]

                if config.days_to_expire_start.lower().strip() == "current_date":       # We start counting from current date
                    date_object = datetime.now() + timedelta(days=days_to_expire)
                elif config.days_to_expire_start.lower().strip() == "valid_from":       # Start counting from valid_from
                    if type(self.valid_from) is STIXdatetime:
                        self.valid_from = json.dumps(self.valid_from, cls=STIXJSONEncoder).replace("\"", "")
                    date_object = datetime.fromisoformat(self.valid_from[:-1]) + timedelta(days=days_to_expire)
                if date_object:
                    self.valid_until = date_object.strftime("%Y-%m-%dT%H:%M:%SZ")

            for tag in misp_event.labels:
                if tag not in self.labels:
                    self.labels.append(tag)

            self._cleanup_labels()

    def _cleanup_labels(self):
        new_labels = []
        for label in self.labels:
            ignore = False
            if label.strip() in MISP_TAGS_IGNORE:
                ignore = True
            for tag in MISP_TAGS_IGNORE:
                if tag.strip().lower() in label.strip().lower():
                    ignore = True
            if not ignore: # We can also do this the other way around, end result remains the same
                if 'MISP_ALLOWED_TAXONOMIES' in globals() and len(MISP_ALLOWED_TAXONOMIES) > 0: # check if someone did not update the constants file
                    matches_allowed_taxonomy = False
                    for taxonomy in MISP_ALLOWED_TAXONOMIES:
                        if "{}:".format(taxonomy).strip().lower() in label.strip().lower():
                            matches_allowed_taxonomy = True
                    if not matches_allowed_taxonomy:
                        ignore = True
            if not ignore:
                new_labels.append(label)
        self.labels = new_labels


class RequestObject_Event:
    def __init__(self, event, logger, misp_flatten_attributes=False):
        if misp_flatten_attributes:
            object_attributes = []
            for misp_object in event["Object"]:
                for object_attribute in misp_object["Attribute"]:
                    if len(object_attribute["comment"].strip()) > 0:
                        comment = "{} (was part of {} object)".format(object_attribute["comment"], misp_object["name"])
                    else:
                        comment = "(was part of {} object)".format(misp_object["name"])
                    object_attribute["comment"] = comment
                    object_attributes.append(object_attribute)
            event_attributes = object_attributes + event["Attribute"]
            event["Attribute"] = event_attributes
            event["Object"] = []
            self.event = event
            self.flatten_attributes = event_attributes
        else:
            self.event = event
            self.flatten_attributes = []
        self.labels = []
        self.sentinel_threattype = False
        self.tlp = SENTINEL_DEFAULT_TLP

        if config.misp_remove_eventreports:
            if self.event.get("EventReport", False):
                self.event["EventReport"] = []

        for label in event.get("Tag", []):
            # Ignore local tags
            if config.ignore_localtags and label["local"] == 1:
                continue

            label = label["name"].strip()
            if "tlp:" in label.lower() and label.lower() in TLP_MARKING_OBJECT_DEFINITION:
                self.tlp = label

            if "sentinel-threattype" in label:
                self.sentinel_threattype = label.split("sentinel-threattype:")[1].strip()

            if label not in self.labels:
                self.labels.append(label)

        self.uuid = event["uuid"]
        self.info = event["info"]
        self.id = event["id"]
        self.threat_level_id = MISP_THREATLEVEL[int(event["threat_level_id"])]
        self.analysis = MISP_ANALYSIS[int(event["analysis"])]
        self.distribution = event["distribution"]
        self.eventdate = event["date"]
        self.org = event["Orgc"]["name"].strip()
        self.name = "{} ({}-{}) by {} on {}".format(self.info, self.id, self.uuid, self.org, self.eventdate)


class RequestObject:
    """A class that parses attribute from misp to the format consumable by MS Graph API

    to use the class:
        request_object = RequestObject(attr) # this reads in the attr and parses it
        # then use request.__dict__ to get the parsed dict

    """
    def __init__(self, attr, event_description=""):
        mapping = ATTR_MAPPING.get(attr['type'])
        if mapping is not None:
            setattr(self, mapping, attr['value'])
        if attr['type'] in MISP_SPECIAL_CASE_TYPES:
            self._handle_special_cases(attr)
        # self.tags = [tag['name'].strip() for tag in attr.get("Tag", [])]
        # Tags on attribute level
        self.tags = []
        tags_remove = []
        for tag in attr.get("Tag", []):
            if config.ignore_localtags:
                if tag["local"] != 1:
                    self.tags.append(tag['name'].strip())
        for tag in self.tags:
            if 'diamond-model:' in tag:
                self.diamondModel = tag.split(':')[1]
                tags_remove.append(tag)
            if 'kill-chain:' in tag:
                kill_chain = tag.split(':')[1]
                # Fix some Azure quirks
                if kill_chain == "Command and Control":
                    kill_chain = "C2"
                elif kill_chain == "Actions on Objectives":
                    kill_chain = "Actions"
                self.killChain = [kill_chain]
                tags_remove.append(tag)
            if 'sentinel-threattype' in tag:    # Override with attribute value
                self.threatType = tag.split(':')[1]
                tags_remove.append(tag)

            if MISP_CONFIDENCE["prefix"] in tag.lower():
                confidence_tag = tag.lower().split("{}=".format(MISP_CONFIDENCE["prefix"]))[1].replace("\"", "")
                for confidence in MISP_CONFIDENCE["matches"]:
                    if confidence == confidence_tag:
                        self.confidence = MISP_CONFIDENCE["matches"][confidence]

        for tag in tags_remove:
            self.tags.remove(tag)
        self.additionalInformation = attr['comment']
        self.description = "{} {}".format(event_description, attr['comment']).strip()

    def _handle_ip(self, attr, attr_type, graph_v4_name, graph_v6_name):
        if attr['type'] == attr_type:
            if '.' in attr['value']:
                setattr(self, graph_v4_name, attr['value'])
            else:
                setattr(self, graph_v6_name, attr['value'])

    def _aggregated_handle_ip(self, attr):
        # Fix https://github.com/cudeso/misp2sentinel/issues/21
        if "/" in attr['value']:
            self._handle_ip(attr, 'ip-dst', 'networkDestinationCidrBlock', 'networkDestinationIPv6')
            self._handle_ip(attr, 'ip-src', 'networkSourceCidrBlock', 'networkSourceIPv6')
        else:
            self._handle_ip(attr, 'ip-dst', 'networkDestinationIPv4', 'networkDestinationIPv6')
            self._handle_ip(attr, 'ip-src', 'networkSourceIPv4', 'networkSourceIPv6')
        if config.network_ignore_direction:
            if "/" in attr['value']:
                self._handle_ip(attr, 'ip-dst', 'networkCidrBlock', 'networkIPv6')
                self._handle_ip(attr, 'ip-src', 'networkCidrBlock', 'networkIPv6')
            else:
                self._handle_ip(attr, 'ip-dst', 'networkIPv4', 'networkIPv6')
                self._handle_ip(attr, 'ip-src', 'networkIPv4', 'networkIPv6')

    def _handle_file_hash(self, attr):
        if attr['type'] in MISP_HASH_TYPES:
            if 'filename|' in attr['type']:
                self.fileHashType = attr['type'].split('|')[1]
                self.fileName, self.fileHashValue = attr['value'].split('|')
            else:
                self.fileHashType = attr['type']
                self.fileHashValue = attr['value']
            if self.fileHashType not in ['sha1', 'sha256', 'md5', 'authenticodeHash256', 'lsHash', 'ctph']:
                self.fileHashType = "unknown"

    def _handle_email_src(self, attr):
        if attr['type'] == 'email-src':
            self.emailSenderAddress = attr['value']
            self.emailSourceDomain = attr['value'].split('@')[1]

    def _handle_ip_port(self, attr):
        if attr['type'] == 'ip-dst|port' or attr['type'] == 'ip-src|port':
            ip = attr['value'].split('|')[0]
            port = attr['value'].split('|')[1]
            if attr['type'] == 'ip-dst|port':
                self.networkDestinationPort = port
                if '.' in attr['value']:
                    self.networkDestinationIPv4 = ip
                    if config.network_ignore_direction:
                        self.networkIPv4 = ip
                        self.networkPort = port
                else:
                    self.networkDestinationIPv6 = ip
                    if config.network_ignore_direction:
                        self.networkIPv6 = ip
                        self.networkPort = port
            elif attr['type'] == 'ip-src|port':
                self.networkSourcePort = port
                if '.' in attr['value']:
                    self.networkSourceIPv4 = ip
                    if config.network_ignore_direction:
                        self.networkIPv4 = ip
                        self.networkPort = port
                else:
                    self.networkSourceIPv6 = ip
                    if config.network_ignore_direction:
                        self.networkIPv6 = ip
                        self.networkPort = port

    def _handle_special_cases(self, attr):
        self._aggregated_handle_ip(attr)
        self._handle_domain_ip(attr)
        self._handle_email_src(attr)
        self._handle_ip_port(attr)
        self._handle_file_hash(attr)
        self._handle_url(attr)

    def _handle_url(self, attr):
        if attr['type'] == 'url':
            if not attr['value'].startswith(('http://', 'https://')):
                self.url = "http://{}".format(attr['value'])
            else:
                self.url = attr['value']

    def _handle_domain_ip(self, attr):
        if attr['type'] == 'domain|ip':
            self.domainName, ip = attr['value'].split('|')
            if '.' in ip:
                self.networkIPv4 = ip
            else:
                self.networkIPv6 = ip
