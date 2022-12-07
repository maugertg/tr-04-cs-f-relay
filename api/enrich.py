import requests
import ipaddress
import urllib.parse
from falconpy import APIHarness
from functools import partial
from datetime import datetime, timezone, timedelta

from flask import Blueprint

from api.schemas import ObservableSchema
from api.utils import get_json, get_jwt, jsonify_data

enrich_api = Blueprint("enrich", __name__)

get_observables = partial(get_json, schema=ObservableSchema(many=True))


def format_docs(docs):
    """Format CTIM Response"""
    return {"count": len(docs), "docs": docs}


def group_observables(relay_input):
    # Leave only unique pairs.

    result = []
    for obj in relay_input:
        obj["type"] = obj["type"].lower()

        # Get only supported types.
        if obj["type"] in (
            "domain",
            "email",
            "email_subject",
            "file_name",
            "file_path",
            "hostname",
            "ip",
            "ipv6",
            # "mac_address", # Doesn't exist in Detection fields
            "md5",
            "sha1",
            "sha256",
            "url",
            "user",
            # "user_agent", # Doesn't exist in Detection fields
        ):
            if obj in result:
                continue
            result.append(obj)

    return result


def group_behaviors_with_obervable(behaviors_list, observable):
    result = []
    for behavior in behaviors_list:
        ioc_value = behavior.get("ioc_value")
        if observable in ioc_value:
            if behavior in result:
                continue
            result.append(behavior)

    return result


def build_target_from_endpoint_obj(device, first_behavior, last_behavior):
    def get_ip_type(address):
        try:
            ip = ipaddress.ip_address(address)

            if isinstance(ip, ipaddress.IPv4Address):
                return "ip"

            if isinstance(ip, ipaddress.IPv6Address):
                return "ipv6"
        except ValueError:
            print(f"{address} is an invalid IP address")

    if device.get("hostname"):
        target = {
            "type": device.get("product_type_desc"),
            "observables": [{"value": device.get("hostname"), "type": "hostname"}],
            "observed_time": {"start_time": first_behavior, "end_time": last_behavior},
            "os": device.get("os_version", "MISSING"),
        }

        if device.get("local_ip"):
            target["observables"].append(
                {
                    "value": device.get("local_ip"),
                    "type": get_ip_type(device.get("local_ip")),
                }
            )

        if device.get("mac_address"):
            target["observables"].append(
                {
                    "value": device.get("mac_address"),
                    "type": ("mac_address"),
                }
            )

        if device.get("device_id"):
            target["observables"].append(
                {
                    "value": device.get("device_id"),
                    "type": ("ms_machine_id"),
                }
            )

    return target


def extract_sightings(output, observable, host):
    """Parse CrowdStrike Falcon detection object and build CTIM Sighting
    Detection Object from: /detects/entities/summaries/GET/v1
    DOCS: https://falcon.us-2.crowdstrike.com/documentation/86/detections-monitoring-apis#find-detections
    SWAGGER: https://assets.falcon.us-2.crowdstrike.com/support/api/swagger-us2.html#/detects/GetDetectSummaries
    """

    def _make_data_table(message):
        data = {"columns": [], "rows": [[]]}

        for key, value in message.items():
            if not (key.startswith(("opt1", "opt2", "opt3"))) and value:
                data["columns"].append({"name": key, "type": "string"})
                data["rows"][0].append(str(value))

        return data

    cid = output.get("cid")
    behaviors = output.get("behaviors")
    first_behavior = output.get("first_behavior")
    last_behavior = output.get("last_behavior")
    created_timestamp = output.get("created_timestamp")
    max_severity_displayname = output.get(
        "max_severity_displayname"
    )  # Values include Critical, High, Medium, and Low
    detection_id = output.get("detection_id")
    detection_id_split = detection_id.split(":")

    device = output.get("device", {})

    if behaviors:
        behaviors_with_observable_count = len(
            group_behaviors_with_obervable(behaviors, observable["value"])
        )

    doc = {
        "confidence": "High",
        "count": 1,
        "description": "CrowdStrike Falcon Detection",
        "short_description": f"Obvservable seen in {behaviors_with_observable_count} of {len(behaviors)} behaviors from detection",
        "external_ids": [detection_id],
        "id": f"transient:sighting-{detection_id}",
        "internal": True,
        "observables": [observable],
        "observed_time": {"start_time": first_behavior, "end_time": last_behavior},
        # "data": _make_data_table(output),
        # "relations": [],
        "schema_version": "1.1.12",
        # "sensor": "endpoint",
        # "resolution": "string",
        "severity": max_severity_displayname,
        "source": "CrowdStrike Falcon Detection",
        "source_uri": f"https://{host.replace('api', 'falcon')}/activity/detections/detail/{detection_id_split[1]}/{detection_id_split[2]}?_cid={cid}",
        "type": "sighting",
    }

    # doc["relations"].extend(extract_relations(threatInfo, observable))

    if device.get("hostname"):
        target = build_target_from_endpoint_obj(device, first_behavior, last_behavior)
        doc.setdefault("targets", []).append(target)

    return doc


def query_detections(falcon, query):
    response = falcon.command(
        "QueryDetects",
        offset=0,
        limit=100,
        # sort="string",
        # filter="string",
        q=query,
    )
    return response


def detection_details(falcon, id_list):
    response = falcon.command("GetDetectSummaries", body={"ids": id_list})
    return response


def get_detections_for(falcon, observable):
    response = query_detections(falcon, observable)
    ids = response.get("body", {}).get("resources", [])
    if not ids:
        return response

    response = detection_details(falcon, ids)

    return response


def get_falcon_outputs(falcon, observables):
    """Iterate over observables provided from Threat Reasponse and query Vision One"""
    outputs = []
    for obs in observables:
        observable = obs["value"]
        response = get_detections_for(falcon, observable)

        if response.get("body", {}).get("resources"):
            response["observable"] = obs
            outputs.append(response)

    return outputs


def extract_indicators(behaviors):
    docs = []

    for indicator in behaviors:
        category = indicator.get("category")
        description = indicator.get("description")
        behavior_id = indicator.get("behavior_id")
        tactic = indicator.get("tactic")
        technique = indicator.get("technique")
        # ids = indicator.get("ids")

        doc = {
            "confidence": "High",
            "external_ids": [behavior_id],
            "id": f"transient:indicator-{behavior_id}",
            "producer": "CrowdStrike",
            "schema_version": "1.1.12",
            "short_description": description,
            "title": f"{tactic} via {technique}",
            "source": "Falcon Detection Method",
            # "tags": [category],
            "type": "indicator",
            "valid_time": {},
        }

        # for indicator_id in ids:
        #     doc["external_ids"].append(str(indicator_id))

        docs.append(doc)

    return docs


def extract_relationships(detection, behaviors_with_observable):
    docs = []

    detection_id = detection.get("detection_id")

    for indicator in behaviors_with_observable:
        behavior_id = indicator.get("behavior_id")

        doc = {
            "id": f"transient:relationship-{detection_id}-{behavior_id}",
            "type": "relationship",
            "schema_version": "1.1.12",
            "relationship_type": "sighting-of",
            "source": "CrowdStrike",
            "source_ref": f"transient:sighting-{detection_id}",
            "target_ref": f"transient:indicator-{behavior_id}",
        }

        docs.append(doc)

    return docs


@enrich_api.route("/deliberate/observables", methods=["POST"])
def deliberate_observables():
    _ = get_jwt()
    _ = get_observables()
    return jsonify_data({})


@enrich_api.route("/observe/observables", methods=["POST"])
def observe_observables():
    jwt = get_jwt()
    host = jwt["host"]
    client_id = jwt["client_id"]
    client_secret = jwt["client_secret"]
    observables = group_observables(get_observables())

    if not observables:
        return jsonify_data({})

    falcon = APIHarness(
        client_id=client_id,
        client_secret=client_secret,
    )

    falcon_outputs = get_falcon_outputs(falcon, observables)

    if not falcon_outputs:
        return jsonify_data({})

    indicators = []
    sightings = []
    relationships = []

    for output in falcon_outputs:
        falcon_detections = output.get("body", {}).get("resources")
        observable = output.get("observable")

        for detection in falcon_detections:
            sightings.append(extract_sightings(detection, observable, host))
            behaviors = detection.get("behaviors")
            if behaviors:
                behaviors_with_observable = group_behaviors_with_obervable(
                    behaviors, observable["value"]
                )
            if behaviors_with_observable:
                indicators.extend(extract_indicators(behaviors_with_observable))
                relationships.extend(
                    extract_relationships(detection, behaviors_with_observable)
                )

    # return vision_one_outputs

    relay_output = {}

    if sightings:
        relay_output["sightings"] = format_docs(sightings)
    if indicators:
        relay_output["indicators"] = format_docs(indicators)
    if relationships:
        relay_output["relationships"] = format_docs(relationships)

    return jsonify_data(relay_output)


@enrich_api.route("/refer/observables", methods=["POST"])
def refer_observables():
    """Trend Micro UI Search URL Example:
    https://portal.xdr.trendmicro.com/#/app/search?start=1665417187&end=1665503587&search_query=1cd61a7744db06e750cb4e1cb1236e19
    """
    jwt = get_jwt()
    host = jwt["host"].replace("api", "portal")
    observables = get_observables()

    # Mapping taken from https://docs.trendmicro.com/en-us/enterprise/trend-micro-vision-one/common-apps/search-app/data-mapping-intro/data-mapping-sdl.aspx
    observable_to_general_search_mapping = {
        "md5": 'FileMD5:"{0}"',
        "sha1": 'FileSHA1:"{0}"',
        "sha256": 'FileSHA2:"{0}"',
        "domain": 'DomainName:"{0}"',
        "email": 'EmailSender:"{0}" OR EmailRecipient:"{0}"',
        "email_subject": 'EmailSubject:"{0}"',
        "file_name": 'FileName:"{0}"',
        "file_path": 'FileFullPath:"{0}"',
        "ip": 'IPv4:"{0}"',
        "ipv6": 'IPv6:"{0}"',
        "url": 'URL:"{0}"',
        "hostname": 'EndpointName:"{0}"',
        "user": 'UserAccount:"{0}"',
    }

    relay_output = []

    # Generate end (now - 30 days) and start (now UTC) epoch timestamps
    end = datetime.utcnow().replace(tzinfo=timezone.utc)
    end_timestamp = int(end.timestamp())
    start = end - timedelta(days=30)
    start_timestamp = int(start.timestamp())

    for obs in observables:

        refer_object = {
            "id": "ref-trend-micro-search-{0}-{1}",
            "title": "Open in Vision One Search",
            "description": "Open in Vision One Search",
            "categories": ["Trend Micro", "Vision One", "Search"],
            "url": None,
        }

        if obs["type"] in observable_to_general_search_mapping:
            refer_object["id"] = refer_object["id"].format(
                obs["type"], urllib.parse.quote(obs["value"])
            )
            search_query = observable_to_general_search_mapping[obs["type"]].format(
                obs["value"]
            )
            url_encoded_search_query = urllib.parse.quote(search_query)
            url = f"https://{host}/#/app/search?start={start_timestamp}&end={end_timestamp}&search_query={url_encoded_search_query}"
            refer_object["url"] = url
            relay_output.append(refer_object)

    return jsonify_data(relay_output)
