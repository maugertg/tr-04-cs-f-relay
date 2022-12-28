from falconpy import APIHarness
from functools import partial

from flask import Blueprint

from api.schemas import ObservableSchema, ActionFormParamsSchema
from api.utils import get_json, get_jwt, jsonify_data

respond_api = Blueprint("respond", __name__)


get_observables = partial(get_json, schema=ObservableSchema(many=True))
get_action_form_params = partial(get_json, schema=ActionFormParamsSchema())


def group_observables(relay_input):
    # Leave only unique pairs.

    result = []
    for obj in relay_input:
        obj["type"] = obj["type"].lower()

        # Get only supported types.
        if obj["type"] in ("domain", "ip", "ipv6", "md5", "sha256"):
            if obj in result:
                continue
            result.append(obj)

    return result


def find_indicator_ids(falcon, observable_value):
    """https://falcon.us-2.crowdstrike.com/documentation/85/detection-and-prevention-policies-apis#finding-indicator-ids
    GET /iocs/queries/indicators/v1
    Check CrowdStrike for existing indicators for a given observable
    """
    response = falcon.command(
        "indicator_search_v1",
        filter=f'value:"{observable_value}"',
    )
    return response


def delete_indicator(falcon, id):
    """https://falcon.us-2.crowdstrike.com/documentation/85/detection-and-prevention-policies-apis#deleting-indicators
    DELETE /iocs/entities/indicators/v1?ids=<ID>
    Delete an Indicator in CrowdStrike based on the unique Indicator ID
    """
    response = falcon.command(
        "indicator_delete_v1",
        comment="Deleted via Cisco SecureX Threat Response",  # Visible in the IOC management Audit Log - https://falcon.us-2.crowdstrike.com/iocs/audit-log/
        ids=id,
    )

    return response


def upload_indicator(falcon, params):
    """https://falcon.us-2.crowdstrike.com/documentation/85/detection-and-prevention-policies-apis#uploading-indicators
    POST /iocs/entities/indicators/v1
    Upload a new High severity Indicator to CrowdStrike
    Apply the indicator to all desktop platforms (mac, windows, and linux)
    Apply the indicator to all host groups
    """

    # The `ip` observable_type is the only one that doesn't map 1:1 with the indicator types in CrowdStrike
    observable_map = {
        "md5": "md5",
        "sha256": "sha256",
        "ip": "ipv4",
        "ipv6": "ipv6",
        "domain": "domain",
    }

    body = {
        "comment": "Uploaded via Cisco SecureX Threat Response",  # Visible in the IOC management Audit Log - https://falcon.us-2.crowdstrike.com/iocs/audit-log/
        "indicators": [
            {
                "action": params["api_action"],
                "description": "Uploaded via Cisco SecureX Threat Response",
                "host_groups": [],
                "metadata": {},
                "platforms": ["mac", "windows", "linux"],
                "severity": "high",
                "type": observable_map[params["observable_type"]],
                "value": params["observable_value"],
            }
        ],
    }

    return falcon.command("indicator_create_v1", body=body)


@respond_api.route("/respond/observables", methods=["POST"])
def respond_observables():
    jwt = get_jwt()
    observables = group_observables(get_observables())

    client_id = jwt["client_id"]
    client_secret = jwt["client_secret"]

    if not observables:
        return jsonify_data({})

    falcon = APIHarness(
        client_id=client_id,
        client_secret=client_secret,
    )

    observable_value = observables[0]["value"]

    check_if_exists = (
        find_indicator_ids(falcon, observable_value).get("body", {}).get("resources")
    )

    actions = []

    network_actions = [
        {
            "api_action": "detect",
            "ui_action": "Detect only",
            "ui_description": "Show as a detection and take no other action",
        },
        {
            "api_action": "no_action",
            "ui_action": "No action",
            "ui_description": "Block and show as detection",
        },
    ]

    hash_actions = [
        {
            "api_action": "prevent",
            "ui_action": "Block",
            "ui_description": "Block and show as detection",
        },
        {
            "api_action": "prevent_no_ui",
            "ui_action": "Block, hide detection",
            "ui_description": "Block and detect, but hide from Activity > Detections",
        },
        {
            "api_action": "allow",
            "ui_action": "Allow",
            "ui_description": "Allow, do not detect",
        },
    ]

    if check_if_exists:
        actions.append(
            {
                "id": "respond-crowdstrike-delete-indicator",
                "title": "Delete selected indicator",
                "description": "Permanently delete indicator. Delete indicators with caution. A deleted indicator cannot be recovered.",
                "categories": ["crowdstrike", "indicators"],
                "query-params": {
                    "observable_value": observables[0]["value"],
                    "observable_type": observables[0]["type"],
                    "observable_id": check_if_exists[0],
                },
            }
        )
    else:
        if observables[0]["type"] in ("ip", "ipv6", "domain"):
            for action in network_actions:
                actions.append(
                    {
                        "id": f'respond-crowdstrike-upload-indicator-{action["api_action"]}',
                        "title": f'Add indicator - {action["ui_action"]}',
                        "description": action["ui_description"],
                        "categories": ["crowdstrike", "indicators"],
                        "query-params": {
                            "observable_value": observables[0]["value"],
                            "observable_type": observables[0]["type"],
                            "api_action": action["api_action"],
                        },
                    }
                )
        else:
            for action in [
                hash_actions[0],
                hash_actions[1],
                network_actions[0],
                hash_actions[2],
                network_actions[1],
            ]:
                actions.append(
                    {
                        "id": f'respond-crowdstrike-upload-indicator-{action["api_action"]}',
                        "title": f'Add indicator - {action["ui_action"]}',
                        "description": action["ui_description"],
                        "categories": ["crowdstrike", "indicators"],
                        "query-params": {
                            "observable_value": observables[0]["value"],
                            "observable_type": observables[0]["type"],
                            "api_action": action["api_action"],
                        },
                    }
                )

    return jsonify_data(actions)


@respond_api.route("/respond/trigger", methods=["POST"])
def respond_trigger():
    jwt = get_jwt()
    params = get_action_form_params()
    action_id = params.get("action-id")

    client_id = jwt["client_id"]
    client_secret = jwt["client_secret"]

    falcon = APIHarness(
        client_id=client_id,
        client_secret=client_secret,
    )

    # Possible Action ID values
    # "respond-crowdstrike-upload-indicator-prevent"
    # "respond-crowdstrike-upload-indicator-prevent_no_ui"
    # "respond-crowdstrike-upload-indicator-detect"
    # "respond-crowdstrike-upload-indicator-allow"
    # "respond-crowdstrike-upload-indicator-no_action"
    # "respond-crowdstrike-delete-indicator"

    if action_id == "respond-crowdstrike-delete-indicator":
        response = delete_indicator(falcon, params["observable_id"])
        if response.get("status_code") == 200:
            return jsonify_data({"status": "success"})

    upload_actions = (
        "respond-crowdstrike-upload-indicator-prevent",
        "respond-crowdstrike-upload-indicator-prevent_no_ui",
        "respond-crowdstrike-upload-indicator-detect",
        "respond-crowdstrike-upload-indicator-allow",
        "respond-crowdstrike-upload-indicator-no_action",
    )

    if action_id in upload_actions:
        response = upload_indicator(falcon, params)
        if response.get("status_code") == 201:
            return jsonify_data({"status": "success"})

    return jsonify_data({"status": "failure"})
