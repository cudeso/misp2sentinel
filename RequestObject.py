import config
from constants import *
from datetime import datetime, timedelta, timezone
import json
import ipaddress
import uuid


class RequestObject_Indicator:
    def _get_dict(self):
        return {k: v for k, v in self.__dict__.items() if not k.startswith('__') and not callable(v)}        

    def __init__(self, element, misp_event, logger):
        # Set default values
        self.confidence = config.default_confidence
        self.indicator_types = []
        self.object_marking_refs = []
        self.external_references = []
        self.kill_chain_phases = []
        self.valid_from = False
        self.valid_until = False
        self.description = element.get("comment", "").strip()
        self.name = ""
        self.labels = []

        self.type = 'indicator'
        self.spec_version = '2.1'
        # Some UUIDs from MISP are not valid, so we create our own
        uuid_str = element.get("uuid", "")
        try:
            parsed_uuid = uuid.UUID(uuid_str)
            if parsed_uuid.version == 4 and str(parsed_uuid) == uuid_str:
                self.id = f"indicator--{uuid_str}"
            else:
                self.id = f"indicator--{uuid.uuid4()}"
        except Exception:
            self.id = f"indicator--{uuid.uuid4()}"
        
        self.created_by_ref = "identity--{}".format(misp_event.org_uuid)
        self.pattern_type = 'stix'
        self.pattern_version = '2.1'
        self.revoked = False
        self.pattern = self.convert_pattern(element.get("type", ""), element.get("value", ""))
        self.valid_from = self.ts_to_iso(element.get("timestamp", None))
        
        def _to_datetime(value):
            if isinstance(value, datetime):
                return value
            if value is None:
                return datetime.now(timezone.utc)
            if isinstance(value, (int, float)):
                try:
                    return datetime.fromtimestamp(value, tz=timezone.utc)
                except Exception:
                    pass
            if isinstance(value, str):
                s = value.strip()
                if s.endswith('Z'):
                    s = s[:-1] + '+00:00'
                try:
                    return datetime.fromisoformat(s)
                except Exception:
                    try:
                        from dateutil import parser as _parser
                        return _parser.parse(s)
                    except Exception:
                        for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
                            try:
                                return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
                            except Exception:
                                continue
            return datetime.now(timezone.utc)

        days_to_expire = int(getattr(config, 'days_to_expire', 0) or 0)
        valid_from_dt = _to_datetime(self.valid_from)
        date_object = valid_from_dt + timedelta(days=days_to_expire)
        self.valid_until = date_object.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')

        self.created = self.ts_to_iso(None)
        self.modified = self.ts_to_iso(None)
        sentinel_threattype = False
        tlp = False

        if self.pattern is not None:
            # Set valid_until pattern
            if config.days_to_expire_ignore_misp_last_seen or not element.get("valid_until", False):
                days_to_expire = config.days_to_expire

                # If we have a mapping, then we use a custom number of days to expire
                if hasattr(config, "days_to_expire_mapping"):
                    for el in config.days_to_expire_mapping:
                        if el.strip().lower() in self.pattern:
                            days_to_expire = config.days_to_expire_mapping[el]

                if config.days_to_expire_start.lower().strip() == "current_date":
                    date_object = datetime.now() + timedelta(days=days_to_expire)
                elif config.days_to_expire_start.lower().strip() == "valid_from":
                    date_object = valid_from_dt + timedelta(days=days_to_expire)
                if date_object:
                    self.valid_until = self.ts_to_iso(date_object.timestamp())
                else:
                    self.logger.error("Could not set valid_until for indicator {}".format(self.pattern))

            # Set the attribute description to the to comment and MISP event name
            if len(self.description) > 0:
                self.description = "{} - {}".format(self.description, misp_event.name)
            else:
                self.description = "{}".format(misp_event.name)

            # Convert the tags
            for tag in element.get("Tag", []):
                if config.ignore_localtags and tag["local"] == 1:
                    continue
                label = tag["name"].strip()
                if label not in self.labels:
                    self.labels.append(label)
                if "tlp:" in label.lower() and label.lower() in TLP_MARKING_OBJECT_DEFINITION:
                    tlp = label

                if MISP_CONFIDENCE["prefix"] in label.lower():
                    confidence_tag = label.lower().split("{}=".format(MISP_CONFIDENCE["prefix"]))[1].replace("\"", "")
                    for confidence in MISP_CONFIDENCE["matches"]:
                        if confidence == confidence_tag:
                            self.confidence = MISP_CONFIDENCE["matches"][confidence]
                if 'sentinel-threattype' in label:    # Override with attribute value
                    sentinel_threattype = label.split("sentinel-threattype:")[1].strip()
                    if sentinel_threattype not in self.indicator_types:
                        self.indicator_types.append(sentinel_threattype)
                if 'kill-chain:' in label:
                    kill_chain = label.split(':')[1]
                    if KILL_CHAIN_MARKING_OBJECT_DEFINITION.get(kill_chain):
                        self.kill_chain_phases.append({"kill_chain_name": "lockheed-martin-cyber-kill-chain", "phase_name": kill_chain})
                        #self.object_marking_refs.append(KILL_CHAIN_MARKING_OBJECT_DEFINITION[kill_chain])

            # Set a default Sentinel threat type
            if not sentinel_threattype:
                if misp_event.sentinel_threattype:
                    self.indicator_types.append(misp_event.sentinel_threattype)
                else:
                    self.indicator_types.append(SENTINEL_DEFAULT_THREATTYPE)

            # TLP marking, first the one from the attribute, then from the event
            if tlp:
                self.object_marking_refs.append(TLP_MARKING_OBJECT_DEFINITION[tlp])
            else:
                if misp_event.tlp:
                    self.object_marking_refs.append(TLP_MARKING_OBJECT_DEFINITION[misp_event.tlp])

            # Add event tags and cleanup
            for tag in misp_event.labels:
                if tag not in self.labels:
                    self.labels.append(tag)
            self._cleanup_labels()

            # Indicator name
            self.name = "{}".format(misp_event.info).strip()

            # Set references to MISP event
            self.external_references.append({
                                            "source_name": "MISP",
                                            "description": "MISP Event: {}".format(misp_event.info),
                                            "external_id": misp_event.uuid,
                                            "url": "{}/events/view/{}".format(config.misp_domain, misp_event.uuid)
                                            })
        
    def ts_to_iso(self, ts: int | str | None) -> str:
        if not ts:
            return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        try:
            ts = int(ts)
        except Exception:
            return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        return datetime.utcfromtimestamp(ts).replace(microsecond=0).isoformat() + "Z"

    def _esc(self, val: str) -> str:
        # STIX patterns use single quotes and require backslashes to be escaped
        return val.replace("\\", "\\\\").replace("'", "\\'")

    def convert_pattern(self, attr_type: str, value: str) -> tuple[str, str] | None:
        # Sentinel doesn't support STIX as it should by the standard. Hence we cannot use
        # a standard conversion library as MISP-STIX does and have to rely on this simple conversion
        # function. It only supports single values, no lists or complex patterns.
        # See: https://github.com/cudeso/misp2sentinel/issues/141#issuecomment-3194308193
        # and: https://github.com/Azure/Azure-Sentinel/issues/12075#issuecomment-3163195537

        attr_type = attr_type.lower()
        # Remove pipe from attribute type if configured
        if config.remove_pipe_from_misp_attribute and "|" in attr_type:
            value = value.split("|")[0].strip()
            attr_type = attr_type.split("|")[0].strip()

        # File name
        if attr_type in ("filename",):
            return f"[file:name = '{self._esc(value)}']"

        # File hashes
        if attr_type in ("md5", "sha1", "sha224", "sha256", "sha384", "sha512", "sha3-224", "sha3-256", "sha3-384", "sha3-512", "ssdeep"):
            algo_map = {
                "md5": "MD5",
                "sha1": "SHA1",
                "sha224": "SHA224",
                "sha256": "SHA256",
                "sha384": "SHA384",
                "sha512": "SHA512",
                "sha3-224": "SHA3-224",
                "sha3-256": "SHA3-256",
                "sha3-384": "SHA3-384",
                "sha3-512": "SHA3-512",
                "ssdeep": "SSDEEPWHIRLPOOL",
            }
            algo = algo_map[attr_type]
            return f"[file:hashes.'{algo}' = '{self._esc(value)}']"

        # JA3
        if attr_type in ("ja3-fingerprint-md5",):
            return f"[ja3:value = '{self._esc(value)}']"

        # URLs
        if attr_type in ("url",):
            return f"[url:value = '{self._esc(value)}']"

        # Hostname / domain
        if attr_type in ("hostname", "domain"):
            # Keep it simple: only domain-name for a single value
            return f"[domain-name:value = '{self._esc(value)}']"

        # IP addresses
        if attr_type in ("ip-src", "ip-dst"):
            try:
                ip = ipaddress.ip_address(value)
                if isinstance(ip, ipaddress.IPv4Address):
                    return f"[ipv4-addr:value = '{value}']"
                else:
                    return f"[ipv6-addr:value = '{value}']"
            except ValueError:
                return None

        # Fallback: treat as an observable string (not ideal, but keeps it simple)
        return None

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
        self.org_uuid = event["Orgc"]["uuid"]
        self.name = "{} ({}-{}) by {} on {}".format(self.info, self.id, self.uuid, self.org, self.eventdate)
