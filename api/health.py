from falconpy import Detects
from flask import Blueprint

from api.utils import get_jwt, jsonify_data, jsonify

health_api = Blueprint("health", __name__)


@health_api.route("/health", methods=["POST"])
def health():
    jwt = get_jwt()
    host = jwt["host"]
    client_id = jwt["client_id"]
    client_secret = jwt["client_secret"]

    falcon = Detects(client_id=client_id, client_secret=client_secret)

    falcon_response = falcon.query_detects(offset=0, limit=1, q="string")

    falcon_status_code = falcon_response.get("status_code")

    response = {}

    if falcon_status_code == 200:
        response["data"] = {"status": "ok"}
    else:
        response["errors"] = [
            {
                "code": "crowdstrike-falcon-api-communication-error",
                "message": f"Something went wrong querying the API using Client ID: {client_id[:5]}...{client_id[-5:]}. The API returned status code {falcon_status_code}",
                "type": "error",
            }
        ]

    return jsonify(response)
