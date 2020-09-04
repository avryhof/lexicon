"""Module provider for Mail-in-a-Box"""
from __future__ import absolute_import

import json
import logging
from json.decoder import JSONDecodeError

import requests
from requests.auth import HTTPBasicAuth

from lexicon.providers.base import Provider as BaseProvider

LOGGER = logging.getLogger(__name__)

# Mail-in-a-Box is not tied to a specific domain, so there is nothing to specify here
NAMESERVER_DOMAINS = []


def provider_parser(subparser):
    """Configure provider parser for Mail-in-a-Box"""
    subparser.add_argument(
        "--auth-username", help="specify username for authentication"
    )
    subparser.add_argument("--auth-password", help="specify password for authentication")
    subparser.add_argument("--host", help="specify the Mail-in-a-Box host")


# See https://mailinabox.email/api-docs.html#tag/DNS for the specification of
# the URIs for the different operations
class Provider(BaseProvider):
    """Provider class for Mail-in-a-Box"""

    def __init__(self, config):
        super(Provider, self).__init__(config)
        self.host = self._get_provider_option("host")
        if self.host is None:
            raise Exception("Specify host of Mail-in-a-Box")

        self.domain_id = None
        self.api_endpoint = (
                self._get_provider_option("api_endpoint") or "https://{0}/admin/dns".format(self.host)
        )

    def _authenticate(self):
        try:
            response = self._get("/dump")
        except requests.exceptions.HTTPError as err:
            # A 403 error will be returned in case of incorrect or missing
            # credentials
            cause = err.response.json()["error"]
            raise Exception(cause)

        # The response is a list of lists containing [domain, [dicts_of_records]]
        domains = []
        for domain_record in response:
            domains.append(domain_record[0])

        try:
            self.domain_id = domains.index(self.domain)
        except BaseException:
            raise Exception("Domain {0} not found".format(self.domain))

    # Create record. If record already exists with the same content, do nothing

    def _create_record(self, rtype, name, content):
        response = {"": ""}
        try:
            resp = self._post("/custom/{0}/{1}".format(name, rtype), content)
        except requests.exceptions.HTTPError as error:
            retn = False
            if error.response.status_code == 400:
                response = {"fail": "Create Failed. Bad Request."}
            elif error.response.status_code == "403":
                response = {"fail": "Create Failed. Forbidden."}
        else:
            retn = True
            response = {"success": resp}
        LOGGER.debug("create_record: %s", response)

        return retn

    # List all records. Return an empty list if no records found
    # type, name and content are used to filter records.
    # If possible filter during the query, otherwise filter after response is received.
    def _list_records(self, rtype=None, name=None, content=None):
        records = []
        try:
            payload = self._get("/dump")
        except requests.exceptions.HTTPError as error:
            if error.response.status_code == "403":
                response = {"fail": "List Records failed. Forbidden."}
        else:
            id_counter = 0
            for domain_record in payload:
                domain, domain_records = domain_record

                for record in domain_records:
                    processed_record = {
                        "type": record.get("rtype"),
                        "name": record.get("qname"),
                        "ttl": record.get("ttl", 3600),
                        "content": record.get("value"),
                        "id": id_counter
                    }
                    records.append(processed_record)
                    id_counter = id_counter + 1

            if rtype:
                records = [record for record in records if record["type"] == rtype]
            if name:
                records = [
                    record for record in records if record["name"] == self._full_name(name)
                ]
            if content:
                records = [record for record in records if record["content"] == content]

        LOGGER.debug("list_records: %s", records)
        return records

    # Create or update a record.
    def _update_record(self, identifier, rtype=None, name=None, content=None):
        response = {"": ""}
        try:
            resp = self._put("/custom/{0}/{1}".format(name, rtype), content)
        except requests.exceptions.HTTPError as error:
            retn = False
            if error.response.status_code == 400:
                response = {"fail": "Update Failed. Bad Request."}
            elif error.response.status_code == "403":
                response = {"fail": "Update Failed. Forbidden."}
        else:
            retn = True
            response = {"success": resp}
        LOGGER.debug("create_record: %s", response)

        return retn

    # Delete an existing record.
    # If record does not exist, do nothing.
    def _delete_record(self, identifier=None, rtype=None, name=None, content=None):
        response = {"": ""}
        try:
            # False Must be specified for content for this request to succeed.
            resp = self._delete("/custom/{0}/{1}".format(name, rtype), False)
        except requests.exceptions.HTTPError as error:
            retn = False
            if error.response.status_code == 400:
                response = {"success": "Delete Failed. Bad Request."}
            elif error.response.status_code == "403":
                response = {"success": "Delete Failed. Forbidden."}
        else:
            retn = True
            response = {"success": resp}
        LOGGER.debug("create_record: %s", response)

        return retn

    # Helpers

    def _delete(self, url="/", data=None, query_params=None):
        # Since Mail-in-a-Box just varies function by request type,
        # DELETE needs to have the same parameters as PUT
        return self._request("DELETE", url, data=data, query_params=query_params)

    def _request(self, action="GET", url="/", data=None, query_params=None):
        if data is None:
            data = {}
        if query_params is None:
            query_params = {}
        if isinstance(query_params, dict):
            query_params["format"] = "json"

        default_headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        target_url = self.api_endpoint + url

        if isinstance(data, dict):
            data = json.dumps(data)

        username = self._get_provider_option("auth_username")
        password = self._get_provider_option("auth_password")

        if not data:
            # For the DELETE request to be valid for Mail-in-a-Box,
            # there must not be a payload.
            response = requests.request(
                action,
                target_url,
                auth=HTTPBasicAuth(username, password,),
                params=query_params,
                # data=data,
                headers=default_headers,
            )
        else:
            response = requests.request(
                action,
                target_url,
                auth=HTTPBasicAuth(username, password,),
                params=query_params,
                data=data,
                headers=default_headers,
            )

        # if the request fails for any reason, throw an error.
        response.raise_for_status()

        try:
            retn = response.json()
        except JSONDecodeError:
            retn = {"status": response.text}

        return retn
