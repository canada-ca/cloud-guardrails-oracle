import base64
import contextlib
import email.utils
import json
import logging
import random
import tempfile
import time
import urllib
import uuid
import os
import urllib3
import pathlib

import pytest
import requests
import uritools

from urllib.parse import urlunparse
from urllib.parse import urlparse

from . import credentials, fuzz, shapes
from .requests import SignedRequestAuth, http_retry, Status

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Indicates an omission of kwarg value
_missing = object()

OPC_PRINCIPAL_HEADER = json.dumps({"tenantId": "1", "subjectId": "1"})
OPC_IDEMPOTENCY_TOKEN_HEADER = "opc-retry-token"
BYPASS_HEADER = {"opc-principal": OPC_PRINCIPAL_HEADER}
ACCOUNTS_PRINCIPAL_HEADER = json.dumps({"tenantId": "tenant", "subjectId": "user",
                                        "claims": [{"key": "svc", "value": "accounts", "issuer": "null"},
                                                   {"key": "ptype", "value": "service", "issuer": "null"}]})
CURRENT_DIRECTORY = os.path.abspath(os.path.dirname(__file__))

def b64(string):
    as_bytes = string.encode("utf-8")
    b64_bytes = base64.b64encode(as_bytes)
    return b64_bytes.decode("utf-8")


def build_url(url, **query):
    """Manages the proper ordering and formatting of query params.  If a query value is None, its key is omitted"""
    if not url.endswith("?"):
        url += "?"
    for key, value in sorted(query.items()):
        if value is None:
            continue
        if not url.endswith("?"):
            url += "&"
        url += "{}={}".format(key, str(value))
    return url


def encode(string):
    """Used to escape path and query string params"""
    return uritools.uriencode(string).decode("utf-8")


def extract_compartment_id(key_id):
    """First portion of the key_id up to /"""
    return key_id.split("/")[0]


def cert_path(project, filename):
    return str(pathlib.Path(CURRENT_DIRECTORY) / ".." / project / "certs" / filename)


@pytest.fixture
def account_service(endpoints, keys):
    return AccountService(endpoints=endpoints["account-service"], keys=keys)


@pytest.fixture
def control_plane(endpoints, keys, run_config, request):
    return create_control_plane(endpoints, keys, run_config, request)


@pytest.fixture(scope="module")
def shared_control_plane(endpoints, shared_keys, run_config, request):
    return create_control_plane(endpoints, shared_keys, run_config, request)


def create_control_plane(endpoints, shared_keys, run_config, request):
    client = ControlPlane(endpoints=endpoints["control-plane"], keys=shared_keys)
    if run_config.get('ssl', {}).get('verify') is not None:  # if configured
        client.verify_ssl(run_config['ssl']['verify'])  # obey setting

    def delete_services():
        for control_plane, service in ControlPlane.services.copy():
            control_plane.delete_service(service)
        ControlPlane.services.clear()

    request.addfinalizer(delete_services)

    return client


@pytest.fixture
def echo_service(endpoints, keys):
    return EchoService(endpoints=endpoints["echo-service"], keys=keys)


@pytest.fixture
def data_plane(endpoints, keys, run_config):
    client = DataPlane(endpoints=endpoints["data-plane"], keys=keys)
    if run_config.get('ssl', {}).get('verify') is not None:  # if configured
        client.verify_ssl(run_config['ssl']['verify'])  # obey setting
    return client


@pytest.fixture
def scim_service(endpoints, keys):
    return ScimService(endpoints=endpoints["scim-service"], keys=keys)


@pytest.fixture
def properties_service_v2(endpoints, keys, tenancy, run_config):
    group_compartment = {
        "id": run_config["limits-group-compartment-id"]
    }
    return PropertiesServiceV2(endpoints=endpoints["properties-service"], keys=keys, tenancy=tenancy,
                               compartment=group_compartment)


@pytest.fixture
def service_classes():
    """Simplifies programmatic access to service classes by endpoint keys"""
    return {
        "control-plane": ControlPlane,
        "data-plane": DataPlane,
        "echo-service": EchoService,
        "key-vending-service": KeyVendingService,
        "scim-service": ScimService,
        "properties-service": PropertiesServiceV2,
        "properties-service-async": PropertiesServiceV2,
        "properties-service-ported": PropertiesServiceV2,
    }


@pytest.fixture
def swap_endpoints(service_classes, endpoints, keys):
    """Return a service with swapped internal and host endpoints.

    Example
    =======
    def test_cp_swapped(control_plane, swapped_service):
        # expect success
        control_plane.get_user(...)

        swapped_control_plane = swap_endpoints("control-plane")

        # expect failure
        swapped_control_plane.get_user(...)
    """

    def swap(service_name):
        # Create a copy so we aren't mutating the base endpoint dict
        swapped_endpoints = dict(endpoints[service_name])
        host = swapped_endpoints["host"]
        internal = swapped_endpoints["internal"]
        swapped_endpoints["host"] = internal
        swapped_endpoints["internal"] = host

        if "compartment-cp" in swapped_endpoints and "compartment-internal" in swapped_endpoints:
            compartment_cp = swapped_endpoints["compartment-cp"]
            compartment_internal = swapped_endpoints["compartment-internal"]
            swapped_endpoints["compartment-internal"] = compartment_cp
            swapped_endpoints["compartment-cp"] = compartment_internal

        cls = service_classes[service_name]
        return cls(endpoints=swapped_endpoints, keys=keys)

    return swap


@pytest.fixture
def swap_endpoints_devops(service_classes, endpoints, keys):
    """Return a service with swapped devops and host endpoints.

    Example
    =======
    def test_cp_swapped(control_plane, swapped_service):
        # expect success
        control_plane.get_user(...)

        swapped_control_plane = swap_endpoints("control-plane")

        # expect failure
        swapped_control_plane.get_user(...)
    """

    def swap(service_name):
        # Create a copy so we aren't mutating the base endpoint dict
        swapped_endpoints = dict(endpoints[service_name])
        host = swapped_endpoints["host"]
        devops = swapped_endpoints["devops"]

        swapped_endpoints["host"] = devops
        swapped_endpoints["devops"] = host

        cls = service_classes[service_name]
        return cls(endpoints=swapped_endpoints, keys=keys)

    return swap


@pytest.fixture
def swap_regions(service_classes, endpoints, keys):
    """Return a service with swapped host-slave-region and host endpoints.

    Example
    =======
    def test_cp_swapped(control_plane, swapped_service):
        # expect success
        control_plane.get_user(...)

        swapped_control_plane = swap_regions("control-plane")

        # expect failure
        swapped_control_plane.get_user(...)
    """

    def swap(service_name):
        # Create a copy so we aren't mutating the base endpoint dict
        swapped_endpoints = dict(endpoints[service_name])
        host = swapped_endpoints["host"]
        host_slave_region = swapped_endpoints["host-slave-region"]

        swapped_endpoints["host"] = host_slave_region
        swapped_endpoints["tagging-host"] = host_slave_region
        swapped_endpoints["host-slave-region"] = host

        cls = service_classes[service_name]
        return cls(endpoints=swapped_endpoints, keys=keys)

    return swap


@pytest.fixture
def swap_consoles(endpoints):
    """Return Console with swapped host-slave-region and host endpoints.

    Example
    =======
    def test_console_swapped():
        swapped_console = swap_consoles("http://127.0.0.1:9061/complete/opcauth/")
    """

    def swap(oauth_redirect):
        # Create a copy so we aren't mutating the base endpoint dict
        swapped_endpoints = dict(endpoints["asw"])
        host = swapped_endpoints["host"]
        host_slave_region = swapped_endpoints["host-slave-region"]

        swapped_endpoints["host"] = host_slave_region
        swapped_endpoints["host-slave-region"] = host

        return Console(endpoints=swapped_endpoints, keys="", oauth_redirect=oauth_redirect)

    return swap


@pytest.fixture
def console(endpoints, keys, run_config):
    return create_console(endpoints, keys, run_config)


def create_console(endpoints, shared_keys, run_config):
    client = Console(endpoints=endpoints["asw"], keys=shared_keys, oauth_redirect=run_config["oauth-redirect-url"])
    if run_config.get('ssl', {}).get('verify') is not None:  # if configured
        client.verify_ssl(run_config['ssl']['verify'])  # obey setting
    return client


@pytest.fixture(scope="module")
def endpoints(module_log, run_config):
    endpoints = run_config["endpoints"]
    module_log.debug("Service endpoints:")
    for service, matrix in sorted(endpoints.items()):
        module_log.debug("  {}:".format(service))
        for facet, endpoint in sorted(matrix.items()):
            module_log.debug("    {}: {}".format(facet, endpoint))
    return endpoints


@pytest.fixture
def slave_region(run_config):
    return run_config["slave-region"]


@pytest.fixture
def home_region_name(run_config):
    return run_config["home-region-name"]


@pytest.fixture
def accounts_basic_auth(run_config):
    return run_config["accounts-basic-auth"]


@pytest.fixture
def slave_region_name(run_config):
    return run_config["slave-region-name"]


@pytest.fixture
def keys():
    """Shared fingerprint -> private key mapping per test"""
    return credentials.Keys()


@pytest.fixture(scope="module")
def shared_keys():
    """Shared fingerprint -> private key mapping per test"""
    return credentials.Keys()


class Client:
    def __init__(self, endpoints, keys, compartment=None, tenancy=None, key=None):
        self.endpoints = endpoints
        self.keys = keys
        self._bound_compartment = compartment
        self._bound_tenancy = tenancy
        self._bound_key = key
        self._bound_cross_tenancy_intent = None
        self._bound_cross_tenancy_intent_as_signed_header = True
        self._bound_obo_call = False
        self.verify = True

    def __enter__(self):
        """
        By implementing the context manager interface, we can do things like:

        with old_client.bound_to(tenancy=new_value) as new_client:
            ...

        without requiring that the `bound_to` method be used as a context.  We can equally use it as:

        new_client = old_client.bound_to(tenancy=new_tenancy)
        new_client.get_user(...)
        """
        return self

    def __exit__(self, *exc_details):
        pass

    def verify_ssl(self, verify):
        self.verify = verify

    def headers(self, *other_headers):
        """other_headers is any number of dicts of additional headers"""
        base = {
            "Content-Type": "application/json",
            "date": email.utils.formatdate(usegmt=True),
            # use the same opc-request-id format as in
            # https://bitbucket.oci.oraclecorp.com/projects/COMMONS/repos/request-id/browse
            "opc-request-id": str(uuid.uuid4()).replace("-", "").upper()
        }
        for other_header in other_headers:
            # Quietly drop empty dicts or default Nones
            if other_header:
                base.update(other_header)
        return base

    @property
    def auth(self):
        if self.auth_key_id is None:
            raise RuntimeError("No auth_key_id provided to api call, and no auth_key_id or tenancy bound to the client")
        private_key = self.keys[self.auth_key_id]["private"]
        return SignedRequestAuth(self.auth_key_id, private_key, self.cross_tenancy_intent,
                                 self.cross_tenancy_intent_as_signed_header, self.obo_call)

    def bind(self, *, compartment=_missing, tenancy=_missing, key=_missing):
        """Bind some configuration to the client.  Chainable"""
        if compartment is not _missing:
            self._bound_compartment = compartment
        if tenancy is not _missing:
            self._bound_tenancy = tenancy
            if self.auth_key_id not in self.keys and tenancy["default_key"] is not None:
                self.keys.register({**tenancy["default_key"], "keyId": tenancy["adminKeyId"]})
        if key is not _missing:
            self._bound_key = key
        return self

    def bound_to(self, *, compartment=_missing, tenancy=_missing, key=_missing):
        """Return a new client with some different configuration"""
        return self.__class__(
            endpoints=self.endpoints, keys=self.keys,
            compartment=self._bound_compartment, tenancy=self._bound_tenancy,
            key=self._bound_key).bind(compartment=compartment, tenancy=tenancy, key=key)

    @property
    def auth_key_id(self):
        if self._bound_key is not None:
            return self._bound_key["keyId"]
        return self._bound_tenancy["adminKeyId"]

    @property
    def compartment_id(self):
        if self._bound_compartment is not None:
            return self._bound_compartment["id"]
        return extract_compartment_id(self.auth_key_id)

    @compartment_id.setter
    def compartment_id(self, value):
        if not self._bound_compartment:
            self._bound_compartment = dict()

        self._bound_compartment["id"] = value

    @property
    def cross_tenancy_intent(self):
        return self._bound_cross_tenancy_intent

    @cross_tenancy_intent.setter
    def cross_tenancy_intent(self, value):
        self._bound_cross_tenancy_intent = value

    @property
    def cross_tenancy_intent_as_signed_header(self):
        return self._bound_cross_tenancy_intent_as_signed_header

    @cross_tenancy_intent_as_signed_header.setter
    def cross_tenancy_intent_as_signed_header(self, value):
        self._bound_cross_tenancy_intent_as_signed_header = value

    @property
    def obo_call(self):
        return self._bound_obo_call

    @obo_call.setter
    def obo_call(self, value):
        self._bound_obo_call = value

    @property
    def tenancy(self):
        return self._bound_tenancy


class AccountService(Client):
    def create_account(self, account, headers=None, accounts_auth=None):
        if headers is None:
            headers = {}
        headers["Content-Type"] = "application/json"
        headers["Authorization"] = "Basic " + b64(accounts_auth)
        sm_url = self.endpoints["sm"] + "/sm/accounts"

        # Create Tenancy in account service with SM endpoint
        result = requests.post(sm_url, headers=self.headers(BYPASS_HEADER, headers), auth=None,
                               data=json.dumps(account))

        # Retrieve the statusUri
        status_uri = result.json()["statusUri"]

        # Polling on the statusUri until the operation status is 200 with targetUri showing up.
        retries = 0
        backoff = 2
        status_uri = status_uri.replace('27484', '8484')
        status_uri = status_uri.replace('https', 'http')

        # statusUri response can contain hostname without port information
        unparsed_uri = urlparse(status_uri)
        if unparsed_uri.port is None:
            hostname = unparsed_uri.hostname
            replacedUri = unparsed_uri._replace(netloc=hostname + ':8484')
            status_uri = urlunparse(replacedUri)

        while retries < 25:
            result = requests.get(status_uri, headers=self.headers(BYPASS_HEADER, headers), auth=None)

            if result.json()["status"] == 200 and result.json()["targetUri"] is not None:
                break
            else:
                print("sleep for %s seconds" % backoff)
                time.sleep(backoff)
                backoff = backoff * 1.5 if backoff <= 30 else 30

            retries += 1

        # Get the targetUri
        target_uri = result.json()["targetUri"]

        # Use the targetUri to get internal accountId since SM API response does not return tenancy Ocid.
        result = requests.get(target_uri, headers=self.headers(BYPASS_HEADER, headers), auth=None)
        account_id = result.json()["id"]
        internal_url = self.endpoints["host"] + "/accounts"

        # Polling on the account api until state is still bootstrapping
        retries = 0
        backoff = 2
        while retries < 10:
            # Use the internal accounts API to retrieve the tenancy ocid
            result = requests.get(internal_url + "/" + account_id + "?serviceEntitlements=true",
                                  headers=self.headers(BYPASS_HEADER, headers), auth=None)
            accounts_json = result.json()
            if "state" not in accounts_json or accounts_json["state"] != "BOOTSTRAPPING":
                break
            else:
                print("Account state is still bootstrapping...sleeping for %s seconds" % backoff)
                time.sleep(backoff)
                backoff = backoff * 1.5 if backoff <= 30 else 30

            retries += 1

        # return the account payload
        return result

    def subscribe_new_region(self, slave_region_name, tenant_id, headers=None):
        url = self.endpoints["host"] + "/tenants/" + tenant_id + "/regions"
        new_region = {"regionKey": slave_region_name}

        # opc-retry-token is a required header
        if not headers:
            headers = dict()
        headers[OPC_IDEMPOTENCY_TOKEN_HEADER] = fuzz.string()

        return requests.post(url, headers=self.headers(BYPASS_HEADER, headers), auth=None, data=json.dumps(new_region))


class ControlPlane(Client):
    services = set()

    def set_policy_and_bind_to_user_key(self, admin_key, user_key, statement):
        policy = shapes.entities.policy(statements=[statement])
        self.bind(key=admin_key)
        with http_retry(Status.OK):
            self.add_policy(policy=policy)

        self.bind(key=user_key)

    # TENANCY ================================================================================================= TENANCY
    def bootstrap_tenancy_service_principal(self, tenancy, isUpiFlag=None, headers=None):
        url = build_url(self.endpoints["compartment-cp"] + "/tenants/accountbootstrap",
                        upi=isUpiFlag)
        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(tenancy),
                             verify=self.verify)

    def bootstrap_tenancy(self, tenancy, headers=None):
        url = self.endpoints["compartment-internal"] + "/tenants/bootstrap"
        return requests.post(url, headers=self.headers(BYPASS_HEADER, headers), auth=None, data=json.dumps(tenancy),
                             verify=self.verify)

    def get_tenancy(self, tenancy, headers=None):
        url = self.endpoints["compartment-internal"] + "/tenants/" + tenancy["tenantId"]
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def get_tenancies(self, limit=None, page=None, headers=None):
        url = build_url(self.endpoints["compartment-internal"] + "/tenants", limit=limit, page=page)
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def update_tenancy(self, tenancy, headers=None):
        data = {"description": tenancy["description"], "name": tenancy["name"]}
        url = self.endpoints["compartment-internal"] + "/tenants/" + tenancy["tenantId"]
        return requests.put(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                            verify=self.verify)

    def update_tenancy_tags(self, tenancy, headers=None):
        # bypass_header = {"opc-principal": ACCOUNTS_PRINCIPAL_HEADER}
        url = self.endpoints["compartment-cp"] + "/compartments/" + tenancy["tenantId"]
        data = {}
        if "freeformTags" in tenancy:
            data["freeformTags"] = tenancy["freeformTags"]
        if "definedTags" in tenancy:
            data["definedTags"] = tenancy["definedTags"]
        return requests.put(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                            verify=self.verify)

    def delete_tenancy(self, tenancy, headers=None):
        url = self.endpoints["compartment-internal"] + "/tenants/" + tenancy["tenantId"]
        return requests.delete(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def list_region_subscriptions(self, tenant_id, headers=None):
        url = self.endpoints["compartment-cp"] + "/tenancies/" + tenant_id + "/regionSubscriptions"
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def create_region_subscription(self, tenant_id, region_id, headers=None):
        new_region = {"regionKey": region_id}
        url = self.endpoints["compartment-cp"] + "/tenancies/" + tenant_id + "/regionSubscriptions"
        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(new_region),
                             verify=self.verify)

    def list_regions(self, headers=None):
        url = self.endpoints["compartment-cp"] + "/regions"
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def get_account_tenancy(self, tenant_id, headers=None):
        url = self.endpoints["compartment-cp"] + "/tenancies/" + tenant_id
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def update_tenant_state(self, tenancy, state, headers=None):
        bypass_header = {"opc-principal": ACCOUNTS_PRINCIPAL_HEADER}
        data = {"entityState": state}
        url = self.endpoints["compartment-internal"] + "/tenants/" + tenancy["tenantId"] + "/state"
        return requests.post(url, headers=self.headers(bypass_header, headers), auth=None, data=json.dumps(data),
                             verify=self.verify)

    def update_tenant_state_with_auth(self, tenancy, block, headers=None):
        data = {"blocked": block}
        url = self.endpoints["compartment-internal"] + "/tenants/" + tenancy["tenantId"] + "/state"
        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                             verify=self.verify)

    def rename_tenancy(self, tenancy, newName, headers=None):
        data = {"newName": newName}
        url = self.endpoints["compartment-internal"] + "/tenants/" + tenancy["tenantId"] + "/rename"
        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                             verify=self.verify)

    # TAG_DEFAULT ================================================================================== TAG_DEFAULT

    # for creation, the compartmentId is the same as the tenancy because of cross tenancy checks
    def add_tag_default(self, tag_default, tag_definition, headers=None):
        data = {
            "compartmentId": tag_default["compartmentId"],
            "tagDefinitionId": tag_definition["id"],
            "value": tag_default["value"]
        }

        url = self.endpoints["tagging-host"] + "/tagDefaults/"
        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                             verify=self.verify)

    def add_tag_default_in_compartment(self, compartment, tag_default, tag_definition, headers=None):
        data = {
            "compartmentId": compartment["id"],
            "tagDefinitionId": tag_definition["id"],
            "value": tag_default["value"]
        }

        url = self.endpoints["tagging-host"] + "/tagDefaults/"
        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                             verify=self.verify)

    def add_required_tag(self, required_tag, tag_definition, headers=None):
        data = {
            "compartmentId": required_tag["compartmentId"],
            "tagDefinitionId": tag_definition["id"],
            "value": required_tag["value"],
            "isRequired": required_tag["isRequired"]
        }

        url = self.endpoints["tagging-host"] + "/tagDefaults/"
        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                             verify=self.verify)

    def add_required_tag_in_compartment(self, compartment, required_tag, tag_definition, headers=None):
        data = {
            "compartmentId": compartment["id"],
            "tagDefinitionId": tag_definition["id"],
            "value": required_tag["value"],
            "isRequired": required_tag["isRequired"]
        }

        url = self.endpoints["tagging-host"] + "/tagDefaults/"
        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                             verify=self.verify)

    def get_tag_default(self, tag_default, headers=None):
        url = self.endpoints["tagging-host"] + "/tagDefaults/" + tag_default["id"]
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def get_tag_defaults(self, limit=None, page=None, headers=None):
        url = build_url(
            self.endpoints["tagging-host"] + "/tagDefaults/",
            compartmentId=self.compartment_id, limit=limit, page=page)
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def get_tag_defaults_in_compartment(self, compartment, limit=None, page=None, headers=None):
        url = build_url(
            self.endpoints["tagging-host"] + "/tagDefaults/",
            compartmentId=compartment["id"], limit=limit, page=page)
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def assemble_effective_tag_set_in_compartment(self, compartmentId, limit=None, page=None, headers=None):
        url = build_url(
            self.endpoints["tagging-host"] + "/tagDefaults/actions/assembleEffectiveTagSet",
            compartmentId=compartmentId, limit=limit, page=page)
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def update_tag_default(self, tag_default, headers=None):
        url = self.endpoints["tagging-host"] + "/tagDefaults/" + tag_default["id"]
        data = {}
        if "value" in tag_default:
            data["value"] = tag_default["value"]
        return requests.put(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                            verify=self.verify)

    def update_required_tag_default(self, tag_default, headers=None):
        url = self.endpoints["tagging-host"] + "/tagDefaults/" + tag_default["id"]
        data = {}
        if "value" in tag_default:
            data["value"] = tag_default["value"]
        if "isRequired" in tag_default:
            data["isRequired"] = tag_default["isRequired"]
        else:
            data["isRequired"] = bool(random.getrandbits(1))  # crud test randomizes isRequired if not provided
        return requests.put(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                            verify=self.verify)

    def delete_tag_default(self, tag_default, headers=None):
        url = self.endpoints["tagging-host"] + "/tagDefaults/" + tag_default["id"]
        return requests.delete(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    # TAG_WORK_REQUESTS ==================================================================================

    def get_tag_work_request(self, id, headers=None):
        url = self.endpoints["tagging-host"] + "/taggingWorkRequests/" + id
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def list_tag_work_requests(self, limit=None, page=None, headers=None, compartment_id=None,
                               resource_identifier=None):
        query = dict()
        query['limit'] = limit
        query['page'] = page
        query['compartmentId'] = compartment_id or self.compartment_id
        if resource_identifier is not None:
            query['resourceIdentifier'] = resource_identifier

        url = build_url(self.endpoints["tagging-host"] + "/taggingWorkRequests", **query)
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def list_tag_work_requests_logs(self, limit=None, page=None, headers=None, id=None):
        query = dict()
        query['limit'] = limit
        query['page'] = page

        url = build_url(self.endpoints["tagging-host"] + "/taggingWorkRequests/" + id + "/logs", **query)
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def list_tag_work_requests_errors(self, limit=None, page=None, headers=None, id=None):
        query = dict()
        query['limit'] = limit
        query['page'] = page

        url = build_url(self.endpoints["tagging-host"] + "/taggingWorkRequests/" + id + "/errors", **query)
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    # TAG_DEFINITION ================================================================================== TAG_DEFINITION

    # for creation, the compartmentId is the same as the tenancy because of cross tenancy checks
    def add_tag_definition(self, tag_definition, headers=None):
        data = {
            "name": tag_definition["name"],
            "description": tag_definition["description"],
        }
        if "is_cost_tracking" in tag_definition:
            data["isCostTracking"] = tag_definition["is_cost_tracking"]
        if "validator" in tag_definition:
            data["validator"] = tag_definition["validator"]

        url = self.endpoints["tagging-host"] + "/tagNamespaces/" + tag_definition["ownerId"] + "/tags/"
        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                             verify=self.verify)

    def add_tag_definition_with_tags(self, tag_definition, headers=None):
        data = {
            "name": tag_definition["name"],
            "description": tag_definition["description"],
        }
        url = self.endpoints["tagging-host"] + "/tagNamespaces/" + tag_definition["ownerId"] + "/tags/"

        if "freeformTags" in tag_definition:
            data["freeformTags"] = tag_definition["freeformTags"]
        if "definedTags" in tag_definition:
            data["definedTags"] = tag_definition["definedTags"]
        if "validator" in tag_definition:
            data["validator"] = tag_definition["validator"]
        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                             verify=self.verify)

    # Note that after creation, the scope / compartmentId is the namespace
    def get_tag_definition(self, tag_definition, headers=None):
        url = self.endpoints["tagging-host"] + "/tagNamespaces/" + tag_definition["tagNamespaceId"] + "/tags/" + \
            tag_definition["id"]
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def get_tag_definitions_for_namespace(self, tag_namespace_id, limit=None, page=None, headers=None):
        url = build_url(
            self.endpoints["tagging-host"] + "/tagNamespaces/" + tag_namespace_id + "/tags/",
            compartmentId=self.compartment_id, limit=limit, page=page)
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def get_tag_definitions(self, limit=None, page=None, headers=None):
        response = self.get_tag_namespaces(limit=None, page=None, headers=headers)
        actual_ids = set(entity["id"] for entity in response.json())

        # Although this is a loop, we return after we get first one
        for tag_namespace_id in actual_ids:
            return self.get_tag_definitions_for_namespace(tag_namespace_id, limit=limit, page=page, headers=headers)

    def get_cost_tracking_tag_definitions(self, compartment_id, limit=None, headers=None):
        url = build_url(
            self.endpoints["tagging-host"] + "/tagNamespaces/actions/listCostTrackingTags",
            compartmentId=compartment_id, limit=limit, page=None)
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def update_tag_definition_tags(self, tag_definition, headers=None):
        url = self.endpoints["tagging-host"] + "/tagNamespaces/" + tag_definition["tagNamespaceId"] + "/tags/" + \
            tag_definition["id"]
        data = {}
        if "freeformTags" in tag_definition:
            data["freeformTags"] = tag_definition["freeformTags"]
        if "definedTags" in tag_definition:
            data["definedTags"] = tag_definition["definedTags"]
        return requests.put(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                            verify=self.verify)

    def update_tag_definition(self, tag_definition, headers=None):
        url = self.endpoints["tagging-host"] + "/tagNamespaces/" + tag_definition["tagNamespaceId"] + "/tags/" + \
            tag_definition["id"]
        data = {}
        if "description" in tag_definition:
            data["description"] = tag_definition["description"]
        if "isRetired" in tag_definition:
            data['isRetired'] = tag_definition["isRetired"]
        if "is_cost_tracking" in tag_definition:
            data["isCostTracking"] = tag_definition["is_cost_tracking"]
        if "validator" in tag_definition:
            data["validator"] = tag_definition["validator"]
        return requests.put(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                            verify=self.verify)

    def retire_tag_definition(self, tag_definition, headers=None):
        url = self.endpoints["tagging-host"] + "/tagNamespaces/" + tag_definition["tagNamespaceId"] + "/tags/" + \
            tag_definition["id"]
        data = {
            "description": tag_definition["description"],
            "isRetired": True,
        }
        if "validator" in tag_definition:
            data["validator"] = tag_definition["validator"]

        return requests.put(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                            verify=self.verify)

    def activate_tag_definition(self, tag_definition, headers=None):
        url = self.endpoints["tagging-host"] + "/tagNamespaces/" + tag_definition["tagNamespaceId"] + "/tags/" + \
            tag_definition["id"]
        data = {
            "description": tag_definition["description"],
            "isRetired": False,
        }
        return requests.put(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                            verify=self.verify)

    def delete_tag_definition(self, tag_definition, headers=None):
        url = self.endpoints["tagging-host"] + "/tagNamespaces/" + tag_definition["tagNamespaceId"] + "/tags/" + \
            tag_definition["id"]
        return requests.delete(url, headers=self.headers(headers), auth=self.auth,
                               verify=self.verify)

    # TAG_NAMESPACE ===================================================================================== TAG_NAMESPACE
    def add_tag_namespace(self, tag_namespace, headers=None):
        data = {**tag_namespace, "compartmentId": self.compartment_id}
        url = self.endpoints["tagging-host"] + "/tagNamespaces"

        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                             verify=self.verify)

    def add_tag_namespace_with_tags(self, tag_namespace, headers=None):
        data = {**tag_namespace, "compartmentId": self.compartment_id}
        url = self.endpoints["tagging-host"] + "/tagNamespaces"

        if "freeformTags" in tag_namespace:
            data["freeformTags"] = tag_namespace["freeformTags"]
        if "definedTags" in tag_namespace:
            data["definedTags"] = tag_namespace["definedTags"]
        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                             verify=self.verify)

    def add_tag_namespace_in_compartment_with_tags(self, tag_namespace, compartment, headers=None):
        data = {**tag_namespace, "compartmentId": compartment["id"]}
        url = self.endpoints["tagging-host"] + "/tagNamespaces"

        if "freeformTags" in tag_namespace:
            data["freeformTags"] = tag_namespace["freeformTags"]
        if "definedTags" in tag_namespace:
            data["definedTags"] = tag_namespace["definedTags"]
        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                             verify=self.verify)

    def add_tag_namespace_in_compartment(self, tag_namespace, compartment, headers=None):
        # get the compartment and pass the compartmentID To create tag namespace in compartment
        data = {**tag_namespace, "compartmentId": compartment["id"]}
        url = self.endpoints["tagging-host"] + "/tagNamespaces"

        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                             verify=self.verify)

    def get_tag_namespaces_for_tenancy(self, listparmeter=None, limit=None, page=None, headers=None):
        if listparmeter is not None:
            url = build_url(
                self.endpoints["tagging-host"] + "/tagNamespaces",
                compartmentId=self.compartment_id, limit=limit, page=page) + "&includeSubcompartments" + listparmeter
        else:
            url = build_url(
                self.endpoints["tagging-host"] + "/tagNamespaces",
                compartmentId=self.compartment_id, limit=limit, page=page) + "&includeSubcompartments"
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def get_tag_namespace(self, tag_namespace, headers=None):
        url = self.endpoints["tagging-host"] + "/tagNamespaces/" + tag_namespace["id"]
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def get_tag_namespaces_in_compartment(self, compartment, limit=None, page=None, headers=None):
        url = build_url(
            self.endpoints["tagging-host"] + "/tagNamespaces",
            compartmentId=compartment["id"], limit=limit, page=page)
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def get_tag_namespaces(self, limit=None, page=None, headers=None):
        url = build_url(
            self.endpoints["tagging-host"] + "/tagNamespaces",
            compartmentId=self.compartment_id, limit=limit, page=page)
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def update_tag_namespace_tags(self, tag_namespace, headers=None):
        url = self.endpoints["tagging-host"] + "/tagNamespaces/" + tag_namespace["id"]
        data = {}
        if "freeformTags" in tag_namespace:
            data["freeformTags"] = tag_namespace["freeformTags"]
        if "definedTags" in tag_namespace:
            data["definedTags"] = tag_namespace["definedTags"]
        return requests.put(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                            verify=self.verify)

    def change_tag_namespace_compartment(self, tag_namespace, new_compartment_id, headers=None):
        url = self.endpoints["tagging-host"] + "/tagNamespaces/" + tag_namespace["id"] + "/actions/changeCompartment"
        data = {
            "compartmentId": new_compartment_id
        }
        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data))

    def update_tag_namespace(self, tag_namespace, headers=None):
        url = self.endpoints["tagging-host"] + "/tagNamespaces/" + tag_namespace["id"]
        data = {}
        if "description" in tag_namespace:
            data["description"] = tag_namespace["description"]
        if "isRetired" in tag_namespace:
            data['isRetired'] = tag_namespace["isRetired"]
        if "definedTags" in tag_namespace:
            data["definedTags"] = tag_namespace["definedTags"]
        return requests.put(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                            verify=self.verify)

    def update_tag_namespace_with_tags(self, tag_namespace, headers=None):
        url = self.endpoints["tagging-host"] + "/tagNamespaces/" + tag_namespace["id"]
        data = {}
        if "description" in tag_namespace:
            data["description"] = tag_namespace["description"]
        if "isRetired" in tag_namespace:
            data["isRetired"] = tag_namespace["isRetired"]
        if "definedTags" in tag_namespace:
            data["definedTags"] = tag_namespace["definedTags"]
        if "freeformTags" in tag_namespace:
            data["freeformTags"] = tag_namespace["freeformTags"]
        return requests.put(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                            verify=self.verify)

    def retire_tag_namespace(self, tag_namespace, headers=None):
        url = self.endpoints["tagging-host"] + "/tagNamespaces/" + tag_namespace["id"]
        data = {
            "description": tag_namespace["description"],
            "isRetired": True,
        }
        return requests.put(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                            verify=self.verify)

    def activate_tag_namespace(self, tag_namespace, headers=None):
        url = self.endpoints["tagging-host"] + "/tagNamespaces/" + tag_namespace["id"]
        data = {
            "description": tag_namespace["description"],
            "isRetired": False,
        }
        return requests.put(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                            verify=self.verify)

    def delete_tag_namespace(self, tag_namespace, headers=None):
        url = self.endpoints["tagging-host"] + "/tagNamespaces/" + tag_namespace["id"]
        return requests.delete(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    # TAG_RULE ======================================================================================= TAG_RULE
    def add_tag_rule(self, tag_rule, compartment=None, headers=None):
        data = {**tag_rule, "compartmentId": self.compartment_id}
        url = self.endpoints["tagging-host"] + "/tagRules"

        if compartment is not None:
            data["compartmentId"] = compartment["id"]

        if "description" in tag_rule:
            data["description"] = tag_rule["description"]
        if "ruleText" in tag_rule:
            data["ruleText"] = tag_rule["ruleText"]

        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                             verify=self.verify)

    def add_tag_rule_with_tags(self, tag_rule, headers=None):
        data = {**tag_rule, "compartmentId": self.compartment_id}
        url = self.endpoints["tagging-host"] + "/tagRules"

        if "ruleText" in tag_rule:
            data["ruleText"] = tag_rule["ruleText"]
        if "freeformTags" in tag_rule:
            data["freeformTags"] = tag_rule["freeformTags"]
        if "definedTags" in tag_rule:
            data["definedTags"] = tag_rule["definedTags"]

        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                             verify=self.verify)

    def get_tag_rules(self, compartment=None, limit=None, page=None, headers=None):
        compartment_id = self.compartment_id if compartment is None else compartment["id"]

        url = build_url(
            self.endpoints["tagging-host"] + "/tagRules",
            compartmentId=compartment_id, limit=limit, page=page)
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def get_tag_rule(self, tag_rule, headers=None):
        url = self.endpoints["tagging-host"] + "/tagRules/" + tag_rule["id"]
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def update_tag_rule_tags(self, tag_rule, headers=None):
        url = self.endpoints["tagging-host"] + "/tagRules/" + tag_rule["id"]
        data = {}

        if "freeformTags" in tag_rule:
            data["freeformTags"] = tag_rule["freeformTags"]
        if "definedTags" in tag_rule:
            data["definedTags"] = tag_rule["definedTags"]
        return requests.put(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                            verify=self.verify)

    def update_tag_rule(self, tag_rule, headers=None):
        url = self.endpoints["tagging-host"] + "/tagRules/" + tag_rule["id"]
        data = {}

        if "ruleText" in tag_rule:
            data["ruleText"] = tag_rule["ruleText"]
        if "freeformTags" in tag_rule:
            data["freeformTags"] = tag_rule["freeformTags"]
        if "definedTags" in tag_rule:
            data["definedTags"] = tag_rule["definedTags"]
        if "description" in tag_rule:
            data["description"] = tag_rule["description"]
        if "isDisabled" in tag_rule:
            data['isDisabled'] = tag_rule["isDisabled"]
        return requests.put(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                            verify=self.verify)

    def deactivate_tag_rule(self, tag_rule, headers=None):
        url = self.endpoints["tagging-host"] + "/tagRules/" + tag_rule["id"]
        data = {}

        if "ruleText" in tag_rule:
            data["ruleText"] = tag_rule["ruleText"]
        if "description" in tag_rule:
            data["description"] = tag_rule["description"]
        data["isDisabled"] = True
        return requests.put(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                            verify=self.verify)

    def activate_tag_rule(self, tag_rule, headers=None):
        url = self.endpoints["tagging-host"] + "/tagRules/" + tag_rule["id"]
        data = {}

        if "ruleText" in tag_rule:
            data["ruleText"] = tag_rule["ruleText"]
        if "description" in tag_rule:
            data["description"] = tag_rule["description"]
        data["isDisabled"] = False
        return requests.put(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                            verify=self.verify)

    def delete_tag_rule(self, tag_rule, headers=None):
        url = self.endpoints["tagging-host"] + "/tagRules/" + tag_rule["id"]
        return requests.delete(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    # BOOTSTRAP_TAGS =================================================================================== BOOTSTRAP_TAGS
    def bootstrap_tags(self, tenant_id, idempotency_token=None):
        url = self.endpoints["tagging-host-internal"] + "/tags/bootstrap/"
        data = {"tenantId": tenant_id}
        headers = {}
        if idempotency_token:
            headers[OPC_IDEMPOTENCY_TOKEN_HEADER] = idempotency_token
        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                             verify=False)

    # USER ======================================================================================================= USER
    def add_user(self, user, headers=None):
        data = {**user, "compartmentId": self.compartment_id}
        return self.add_user_with_data(json.dumps(data), headers)

    def add_user_with_tags(self, user, headers=None):
        data = {**user, "compartmentId": self.compartment_id}

        if "freeformTags" in user:
            data["freeformTags"] = user["freeformTags"]
        if "definedTags" in user:
            data["definedTags"] = user["definedTags"]
        return self.add_user_with_data(json.dumps(data), headers)

    def add_user_with_data(self, raw_data, headers=None):
        url = self.endpoints["host"] + "/users"
        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=raw_data, verify=self.verify)

    def get_user(self, user, headers=None):
        url = self.endpoints["host"] + "/users/" + user["id"]
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def get_users(self, limit=None, page=None, headers=None, sort_by=None, sort_order=None, name=None,
                  lifecycle_state=None, identity_provider_id=None, external_identifier_id=None):
        query = dict()
        query['sortBy'] = sort_by
        query['sortOrder'] = sort_order
        query['name'] = name
        query['lifecycleState'] = lifecycle_state
        query['limit'] = limit
        query['page'] = page
        query['compartmentId'] = self.compartment_id
        query['identityProviderId'] = identity_provider_id
        query['externalIdentifierID'] = external_identifier_id
        url = build_url(
            self.endpoints["host"] + "/users", **query)
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def get_users_with_certs(self, limit=None, page=None, headers=None, sort_by=None, sort_order=None, name=None,
                             lifecycle_state=None, identity_provider_id=None, external_identifier_id=None):
        query = dict()
        query['sortBy'] = sort_by
        query['sortOrder'] = sort_order
        query['name'] = name
        query['lifecycleState'] = lifecycle_state
        query['limit'] = limit
        query['page'] = page
        query['compartmentId'] = self.compartment_id
        query['identityProviderId'] = identity_provider_id
        query['externalIdentifierID'] = external_identifier_id
        url = build_url(
            self.endpoints["host"] + "/users", **query)
        return requests.get(url, headers=self.headers(headers), auth=self.auth,
                            verify=cert_path("identity", "devopsCa.crt"),
                            cert=(cert_path("identity", "devopsClient.crt"),
                                  cert_path("identity", "devopsClient.key")))

    def get_users_tag_filter(self, tagName=None, tagValue=None, limit=None, page=None, headers=None):
        query = {
            "compartmentId": self.compartment_id,
            "limit": limit,
            "page": page,
            tagName: tagValue,
        }
        url = build_url(self.endpoints["host"] + "/users", **query)
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def update_user(self, user, headers=None):
        data = {}
        if "description" in user:
            data["description"] = user["description"]
        if "freeformTags" in user:
            data["freeformTags"] = user["freeformTags"]
        if "definedTags" in user:
            data["definedTags"] = user["definedTags"]
        if "email" in user:
            data["email"] = user["email"]
        return self.update_user_with_data(user, json.dumps(data), headers)

    def update_user_tags(self, user, headers=None):
        data = {}
        if "freeformTags" in user:
            data["freeformTags"] = user["freeformTags"]
        if "definedTags" in user:
            data["definedTags"] = user["definedTags"]
        logging.debug(data)
        return self.update_user_with_data(user, json.dumps(data), headers)

    def update_user_with_data(self, user, raw_data, headers=None):
        url = self.endpoints["host"] + "/users/" + user["id"]
        return requests.put(url, headers=self.headers(headers), auth=self.auth, data=raw_data, verify=self.verify)

    def delete_user(self, user, headers=None):
        url = self.endpoints["host"] + "/users/" + user["id"]
        return requests.delete(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def unblock_user(self, user, headers=None):
        data = {"blocked": False}
        return self.unblock_user_with_data(user, json.dumps(data), headers)

    def unblock_user_with_data(self, user, raw_data, headers=None):
        url = self.endpoints["host"] + "/users/" + user["id"] + "/state"
        return requests.put(url, headers=self.headers(headers), auth=self.auth, data=raw_data, verify=self.verify)

    def update_user_capabilities(self, user, capabilities, headers=None):
        url = self.endpoints["host"] + "/users/" + user["id"] + "/capabilities"
        return requests.put(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(capabilities),
                            verify=self.verify)

    def send_verification_email(self, user_id, headers=None):
        url = self.endpoints["host"] + "/users/" + user_id + "/actions/sendVerificationEmail"
        return requests.post(url, headers=self.headers(headers), auth=self.auth)

    def get_user_api_keys(self, user, headers=None):
        url = self.endpoints["host"] + "/users/" + user["id"] + "/apiKeys/"
        return requests.get(url, headers=self.headers(headers), auth=self.auth)

    def delete_user_api_key(self, user, user_key, headers=None):
        url = self.endpoints["host"] + "/users/" + user["id"] + "/apiKeys/" + user_key["fingerprint"]
        return requests.delete(url, headers=self.headers(headers), auth=self.auth)

    # User Support Account ======================================================================= User Support Account
    def link_support_account(self, user, link_support_account_request, headers=None):
        return self.link_support_account_with_data(user, json.dumps(link_support_account_request), headers)

    def link_support_account_with_data(self, user, raw_data, headers=None):
        url = self.endpoints["host"] + "/users/" + user['id'] + "/actions/linkSupportAccount/"
        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=raw_data,
                             verify=self.verify)

    def unlink_support_account(self, user, unlink_support_account_request, headers=None):
        return self.unlink_support_account_with_data(user, json.dumps(unlink_support_account_request), headers)

    def unlink_support_account_with_data(self, user, raw_data, headers=None):
        url = self.endpoints["host"] + "/users/" + user['id'] + "/actions/unlinkSupportAccount/"
        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=raw_data,
                             verify=self.verify)

    # SWIFT ===================================================================================================== SWIFT
    def add_swift_password(self, swift, user, headers=None):
        return self.add_swift_password_with_data(user, json.dumps(swift), headers)

    def add_swift_password_with_data(self, user, raw_data, headers=None):
        url = self.endpoints["host"] + "/users/" + user['id'] + "/swiftPasswords/"
        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=raw_data, verify=self.verify)

    def list_swift_passwords(self, user, headers=None):
        url = self.endpoints["host"] + "/users/" + user['id'] + "/swiftPasswords/"
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def update_swift_password(self, user, swift, headers=None):
        update_swift_request = {}
        if "description" in swift:
            update_swift_request = {"description": swift['description']}
        return self.update_swift_password_with_data(user, swift, json.dumps(update_swift_request), headers)

    def update_swift_password_with_data(self, user, swift, raw_data, headers=None):
        url = self.endpoints["host"] + "/users/" + user['id'] + "/swiftPasswords/" + swift['id']
        return requests.put(url, headers=self.headers(headers), auth=self.auth, data=raw_data, verify=self.verify)

    def delete_swift_password(self, user, swift, headers=None):
        url = self.endpoints["host"] + "/users/" + user['id'] + "/swiftPasswords/" + swift['id']
        return requests.delete(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    # AUTH TOKEN ==================================================================================== AUTH TOKEN

    def add_auth_token(self, token, user, headers=None):
        return self.add_auth_token_with_data(user, json.dumps(token), headers)

    def add_auth_token_with_data(self, user, raw_data, headers=None):
        url = self.endpoints["host"] + "/users/" + user['id'] + "/authTokens/"
        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=raw_data, verify=self.verify)

    def list_auth_tokens(self, user, headers=None):
        url = self.endpoints["host"] + "/users/" + user['id'] + "/authTokens/"
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def update_auth_token(self, user, token, headers=None):
        update_token_request = {}
        if "description" in token:
            update_token_request = {"description": token['description']}
        return self.update_auth_token_with_data(user, token, json.dumps(update_token_request), headers)

    def update_auth_token_with_data(self, user, token, raw_data, headers=None):
        url = self.endpoints["host"] + "/users/" + user['id'] + "/authTokens/" + token['id']
        return requests.put(url, headers=self.headers(headers), auth=self.auth, data=raw_data, verify=self.verify)

    def delete_auth_token(self, user, token, headers=None):
        url = self.endpoints["host"] + "/users/" + user['id'] + "/authTokens/" + token['id']
        return requests.delete(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    # Service limits =================================================================================== Service limits

    def get_servicelimits_groups(self, compartment=None, headers=None):
        if compartment is None:
            compartment = self.compartment_id
        url = build_url(
            self.endpoints["host"] + "/serviceLimitGroups",
            compartmentId=compartment)
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def get_servicelimits(self, group, compartment=None, headers=None):
        if compartment is None:
            compartment = self.compartment_id
        url = build_url(
            self.endpoints["host"] + "/serviceLimits",
            compartmentId=compartment,
            group=group)
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    # SIGV4 ===================================================================================================== SIGV4
    def add_customer_secret_key(self, secret_key, user, headers=None):
        return self.add_customer_secret_key_with_data(user, json.dumps(secret_key), headers)

    def add_customer_secret_key_with_data(self, user, raw_data, headers=None):
        url = self.endpoints["host"] + "/users/" + user['id'] + "/customerSecretKeys/"
        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=raw_data, verify=self.verify)

    def list_customer_secret_keys(self, user, headers=None):
        url = self.endpoints["host"] + "/users/" + user['id'] + "/customerSecretKeys/"
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def update_customer_secret_key(self, user, secret_key, headers=None):
        update_secret_key_request = {}
        if "displayName" in secret_key:
            update_secret_key_request = {"displayName": secret_key['displayName']}
        return self.update_customer_secret_key_with_data(user, secret_key, json.dumps(update_secret_key_request),
                                                         headers)

    def update_customer_secret_key_with_data(self, user, secret_key, raw_data, headers=None):
        url = self.endpoints["host"] + "/users/" + user['id'] + "/customerSecretKeys/" + secret_key['id']
        return requests.put(url, headers=self.headers(headers), auth=self.auth, data=raw_data, verify=self.verify)

    def delete_customer_secret_key(self, user, secret_key, headers=None):
        url = self.endpoints["host"] + "/users/" + user['id'] + "/customerSecretKeys/" + secret_key['id']
        return requests.delete(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    # MFA totp devices ===================================================================================================== Mfa totp devices
    def add_mfa_totp_device(self, user, headers=None):
        url = self.endpoints["host"] + "/users/" + user['id'] + "/mfaTotpDevices/"
        return requests.post(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def list_mfa_totp_devices(self, user, headers=None):
        url = self.endpoints["host"] + "/users/" + user['id'] + "/mfaTotpDevices/"
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def delete_mfa_totp_device(self, user, totp_device, headers=None):
        url = self.endpoints["host"] + "/users/" + user['id'] + "/mfaTotpDevices/" + totp_device['id']
        return requests.delete(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def get_mfa_totp_device(self, user, totp_device, headers=None):
        url = self.endpoints["host"] + "/users/" + user['id'] + "/mfaTotpDevices/" + totp_device['id']
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def generate_totp_seed(self, user, totp_device, headers=None):
        url = self.endpoints["host"] + "/users/" + user['id'] + "/mfaTotpDevices/" + totp_device[
            'id'] + "/actions/generateSeed"
        return requests.post(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def activate_mfa_totp_device(self, user, totp_device, totp_token, headers=None):
        return self.activate_mfa_totp_device_with_data(user, totp_device, json.dumps(totp_token), headers)

    def activate_mfa_totp_device_with_data(self, user, totp_device, raw_data, headers=None):
        url = self.endpoints["host"] + "/users/" + user['id'] + "/mfaTotpDevices/" + totp_device[
            'id'] + "/actions/activate"
        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=raw_data, verify=self.verify)

    # SMTP ===================================================================================================== SMTP
    def add_smtp_credential(self, smtp, user, headers=None):
        return self.add_smtp_credential_with_data(user, json.dumps(smtp), headers)

    def add_smtp_credential_with_data(self, user, raw_data, headers=None):
        url = self.endpoints["host"] + "/users/" + user['id'] + "/smtpCredentials/"
        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=raw_data, verify=self.verify)

    def list_smtp_credentials(self, user, headers=None):
        url = self.endpoints["host"] + "/users/" + user['id'] + "/smtpCredentials/"
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def update_smtp_credential(self, user, smtp, headers=None):
        update_swift_request = {}
        if "description" in smtp:
            update_swift_request = {"description": smtp['description']}
        return self.update_smtp_credential_with_data(user, smtp, json.dumps(update_swift_request), headers)

    def update_smtp_credential_with_data(self, user, smtp, raw_data, headers=None):
        url = self.endpoints["host"] + "/users/" + user['id'] + "/smtpCredentials/" + smtp['id']
        return requests.put(url, headers=self.headers(headers), auth=self.auth, data=raw_data, verify=self.verify)

    def delete_smtp_credential(self, user, smtp, headers=None):
        url = self.endpoints["host"] + "/users/" + user['id'] + "/smtpCredentials/" + smtp['id']
        return requests.delete(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    # OAUTH2 Client Credential =============================================================================== OAUTH2 Client Credential
    def add_oauth2_client_credential(self, oauth2_client_cred, user, headers=None):
        return self.add_oauth2_client_credential_with_data(user, json.dumps(oauth2_client_cred), headers)

    def add_oauth2_client_credential_with_data(self, user, raw_data, headers=None):
        url = self.endpoints["host"] + "/users/" + user['id'] + "/oauth2ClientCredentials/"
        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=raw_data, verify=self.verify)

    def list_oauth2_client_credentials(self, user, headers=None):
        url = self.endpoints["host"] + "/users/" + user['id'] + "/oauth2ClientCredentials/"
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def update_oauth2_client_credential(self, user, oauth2_client_cred, headers=None):
        update_oauth2_client_cred_request = {}
        if "description" in oauth2_client_cred:
            update_oauth2_client_cred_request['description'] = oauth2_client_cred['description']
        if "scopes" in oauth2_client_cred:
            update_oauth2_client_cred_request['scopes'] = oauth2_client_cred['scopes']
        if "isResetPassword" in oauth2_client_cred:
            update_oauth2_client_cred_request['isResetPassword'] = oauth2_client_cred['isResetPassword']
        return self.update_oauth2_client_credential_with_data(user, oauth2_client_cred,
                                                              json.dumps(update_oauth2_client_cred_request), headers)

    def update_oauth2_client_credential_with_data(self, user, oauth2_client_cred, raw_data, headers=None):
        url = self.endpoints["host"] + "/users/" + user['id'] + "/oauth2ClientCredentials/" + oauth2_client_cred['id']
        return requests.put(url, headers=self.headers(headers), auth=self.auth, data=raw_data, verify=self.verify)

    def delete_oauth2_client_credential(self, user, oauth2_client_cred, headers=None):
        url = self.endpoints["host"] + "/users/" + user['id'] + "/oauth2ClientCredentials/" + oauth2_client_cred['id']
        return requests.delete(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    # API KEY ================================================================================================= API KEY
    def add_key(self, user, key, headers=None):
        data = {"key": key["public"]}
        return self.add_key_with_data(user, json.dumps(data), headers)

    def add_key_with_data(self, user, raw_data, headers=None):
        url = self.endpoints["host"] + "/users/" + user["id"] + "/apiKeys"
        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=raw_data, verify=self.verify)

    def get_keys(self, user, headers=None):
        url = self.endpoints["host"] + "/users/" + user["id"] + "/apiKeys"
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def delete_key(self, user, key, headers=None):
        url = self.endpoints["host"] + "/users/" + user["id"] + "/apiKeys/" + key["fingerprint"]
        return requests.delete(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    # GROUP ===================================================================================================== GROUP
    def add_group(self, group, headers=None):
        data = {**group, "compartmentId": self.compartment_id}
        url = self.endpoints["host"] + "/groups"
        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                             verify=self.verify)

    def add_group_with_tags(self, group, headers=None):
        data = {**group, "compartmentId": self.compartment_id}
        url = self.endpoints["host"] + "/groups"

        if "freeformTags" in group:
            data["freeformTags"] = group["freeformTags"]
        if "definedTags" in group:
            data["definedTags"] = group["definedTags"]
        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                             verify=self.verify)

    def get_group(self, group, headers=None):
        url = self.endpoints["host"] + "/groups/" + group["id"]
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def get_groups(self, limit=None, page=None, headers=None, sort_by=None, sort_order=None, name=None,
                   lifecycle_state=None):
        query = dict()
        query['sortBy'] = sort_by
        query['sortOrder'] = sort_order
        query['name'] = name
        query['lifecycleState'] = lifecycle_state
        query['limit'] = limit
        query['page'] = page
        query['compartmentId'] = self.compartment_id
        url = build_url(
            self.endpoints["host"] + "/groups", **query)
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def get_groups_tag_filter(self, tagName=None, tagValue=None, limit=None, page=None, headers=None):
        query = {
            "compartmentId": self.compartment_id,
            "limit": limit,
            "page": page,
            tagName: tagValue,
        }
        url = build_url(self.endpoints["host"] + "/groups", **query)
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def update_group(self, group, headers=None):
        url = self.endpoints["host"] + "/groups/" + group["id"]
        data = {}
        if "description" in group:
            data = {"description": group["description"]}
        return requests.put(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                            verify=self.verify)

    def update_group_tags(self, group, headers=None):
        url = self.endpoints["host"] + "/groups/" + group["id"]
        data = {}
        if "freeformTags" in group:
            data["freeformTags"] = group["freeformTags"]
        if "definedTags" in group:
            data["definedTags"] = group["definedTags"]
        return requests.put(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                            verify=self.verify)

    def delete_group(self, group, headers=None):
        url = self.endpoints["host"] + "/groups/" + group["id"]
        return requests.delete(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    # GROUP MEMBERSHIP =============================================================================== GROUP MEMBERSHIP
    def add_group_user(self, group, user, headers=None):
        data = {"userId": user["id"], "groupId": group["id"]}
        url = self.endpoints["host"] + "/userGroupMemberships"
        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                             verify=self.verify)

    def get_group_membership(self, membership_id, headers=None):
        url = self.endpoints["host"] + "/userGroupMemberships/" + membership_id
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def get_group_user(self, group, user, headers=None):
        # TODO: This method returns a list, not an object.
        # Json standards are pretty clear that top-level lists should be
        # disallowed.
        url = build_url(
            self.endpoints["host"] + "/userGroupMemberships",
            compartmentId=self.compartment_id, groupId=group["id"],
            userId=user["id"])
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def get_groups_for_user(self, user, limit=None, page=None, headers=None):
        url = build_url(
            self.endpoints["host"] + "/userGroupMemberships",
            compartmentId=self.compartment_id,
            limit=limit, page=page, userId=user["id"])
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def get_users_for_group(self, group, limit=None, page=None, headers=None):
        url = build_url(
            self.endpoints["host"] + "/userGroupMemberships",
            compartmentId=self.compartment_id,
            limit=limit, page=page, groupId=group["id"])
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def get_group_user_overload(self, user_group, headers=None):
        url = self.endpoints["host"] + "/userGroupMemberships/" + user_group["id"]
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def delete_group_user(self, user_group, headers=None):
        url = self.endpoints["host"] + "/userGroupMemberships/" + user_group["id"]
        return requests.delete(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    # network source ================================================================================= network source
    def add_network_source(self, network_source, headers=None):
        data = {**network_source, "compartmentId": self.compartment_id}
        url = self.endpoints["host"] + "/networkSources"
        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                             verify=self.verify)

    def get_network_source(self, network_source, headers=None):
        url = self.endpoints["host"] + "/networkSources/" + network_source["id"]
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def update_network_source(self, network_source, headers=None):
        url = self.endpoints["host"] + "/networkSources/" + network_source["id"]

        data = {}
        if "publicSourceList" in network_source:
            data["publicSourceList"] = network_source["publicSourceList"]
        if "virtualSourceList" in network_source:
            data["virtualSourceList"] = network_source["virtualSourceList"]
        if "services" in network_source:
            data["services"] = network_source["services"]
        if "description" in network_source:
            data["description"] = network_source["description"]
        if "freeformTags" in network_source:
            data["freeformTags"] = network_source["freeformTags"]
        if "definedTags" in network_source:
            data["definedTags"] = network_source["definedTags"]

        return requests.put(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                            verify=self.verify)

    def delete_network_source(self, network_source, headers=None):
        url = self.endpoints["host"] + "/networkSources/" + network_source["id"]
        return requests.delete(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    # dynamic GROUP ====================================================================================== GROUP
    def add_dynamic_group(self, dynamic_group, headers=None):
        data = {**dynamic_group, "compartmentId": self.compartment_id}
        url = self.endpoints["host"] + "/dynamicGroups"
        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                             verify=self.verify)

    def add_dynamic_group_with_tags(self, dynamic_group, headers=None):
        data = {**dynamic_group, "compartmentId": self.compartment_id}
        url = self.endpoints["host"] + "/dynamicGroups"
        data["matchingRule"] = "instance.id='someocid'"
        if "freeformTags" in dynamic_group:
            data["freeformTags"] = dynamic_group["freeformTags"]
        if "definedTags" in dynamic_group:
            data["definedTags"] = dynamic_group["definedTags"]
        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data))

    def get_dynamic_group(self, group, headers=None):
        url = self.endpoints["host"] + "/dynamicGroups/" + group["id"]
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def get_dynamic_groups(self,
                           limit=None,
                           page=None,
                           headers=None,
                           sort_by=None,
                           sort_order=None,
                           name=None,
                           lifecycle_state=None):
        query = dict()
        query['sortBy'] = sort_by
        query['sortOrder'] = sort_order
        query['name'] = name
        query['lifecycleState'] = lifecycle_state
        query['limit'] = limit
        query['page'] = page
        query['compartmentId'] = self.compartment_id
        url = build_url(self.endpoints["host"] + "/dynamicGroups", **query)
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def update_dynamic_group(self, group, headers=None):
        url = self.endpoints["host"] + "/dynamicGroups/" + group["id"]
        data = {}
        if "description" in group:
            data["description"] = group["description"]
        if "matchingRules" in group:
            data["matchingRules"] = group["matchingRules"]

        return requests.put(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                            verify=self.verify)

    def update_dynamic_group_tags(self, group, headers=None):
        url = self.endpoints["host"] + "/dynamicGroups/" + group["id"]
        data = {}
        if "freeformTags" in group:
            data["freeformTags"] = group["freeformTags"]
        if "definedTags" in group:
            data["definedTags"] = group["definedTags"]
        return requests.put(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data))

    def delete_dynamic_group(self, group, headers=None):
        url = self.endpoints["host"] + "/dynamicGroups/" + group["id"]
        return requests.delete(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    # IDENTITY PROVIDER ======================================================================= IDENTITY PROVIDER
    def add_saml2_identity_provider(self, provider, headers=None):
        data = {**provider, "compartmentId": self.compartment_id}
        url = self.endpoints["host"] + "/identityProviders/"
        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                             verify=self.verify)

    def add_saml2_identity_provider_with_tags(self, provider, headers=None):
        data = {**provider, "compartmentId": self.compartment_id}
        url = self.endpoints["host"] + "/identityProviders/"

        if "freeformTags" in provider:
            data["freeformTags"] = provider["freeformTags"]
        if "definedTags" in provider:
            data["definedTags"] = provider["definedTags"]
        if "metadata" in provider:
            data["metadata"] = provider["metadata"]
        data["protocol"] = "SAML2"
        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                             verify=self.verify)

    def get_saml2_identity_provider(self, provider, headers=None):
        url = self.endpoints["host"] + "/identityProviders/" + provider["id"]
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def get_saml2_identity_providers(self, limit=None, page=None, headers=None, sort_by=None, sort_order=None,
                                     name=None, lifecycle_state=None):
        query = dict()
        query['sortBy'] = sort_by
        query['sortOrder'] = sort_order
        query['name'] = name
        query['lifecycleState'] = lifecycle_state
        query['limit'] = limit
        query['page'] = page
        query['compartmentId'] = self.compartment_id
        query['protocol'] = 'SAML2'

        url = build_url(
            self.endpoints["host"] + "/identityProviders/", **query)
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def update_saml2_identity_provider(self, provider, headers=None):
        url = self.endpoints["host"] + "/identityProviders/" + provider["id"]

        data = dict()
        data["protocol"] = "SAML2"
        properties = ["description", "metadata", "metadataUrl", "encryptAssertion", "freeformAttributes",
                      "forceAuthentication", "authnContextClassRefs"]
        for p in properties:
            if p in provider:
                data[p] = provider[p]

        return requests.put(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                            verify=self.verify)

    def update_saml2_identity_provider_tags(self, provider, headers=None):
        url = self.endpoints["host"] + "/identityProviders/" + provider["id"]
        data = {}
        if "freeformTags" in provider:
            data["freeformTags"] = provider["freeformTags"]
        if "definedTags" in provider:
            data["definedTags"] = provider["definedTags"]
        data["protocol"] = "SAML2"
        return requests.put(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                            verify=self.verify)

    def delete_saml2_identity_provider(self, provider, headers=None):
        url = self.endpoints["host"] + "/identityProviders/" + provider["id"]
        return requests.delete(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def add_saml2_idp_group_mapping(self, idp, idp_group_name, bmc_group, headers=None):
        data = {"idpGroupName": idp_group_name, "groupId": bmc_group["id"]}
        return self.add_saml2_idp_group_mapping_with_data(idp, json.dumps(data), headers)

    def add_saml2_idp_group_mapping_with_data(self, idp, raw_data, headers=None):
        url = self.endpoints["host"] + "/identityProviders/" + idp["id"] + "/groupMappings/"
        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=raw_data, verify=self.verify)

    def delete_saml2_idp_group_mapping(self, idp, mapping_id, headers=None):
        url = self.endpoints["host"] + "/identityProviders/" + idp["id"] + "/groupMappings/" + mapping_id
        return requests.delete(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def update_saml2_idp_group_mapping(self, idp, mappingId, mapping, headers=None):
        return self.update_saml2_idp_group_mapping_with_data(idp, mappingId, json.dumps(mapping), headers)

    def update_saml2_idp_group_mapping_with_data(self, idp, mappingId, raw_data, headers=None):
        url = self.endpoints["host"] + "/identityProviders/" + idp["id"] + "/groupMappings/" + mappingId
        return requests.put(url, data=raw_data, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def get_saml2_idp_group_mapping(self, idp, mappingId, headers=None):
        url = self.endpoints["host"] + "/identityProviders/" + idp["id"] + "/groupMappings/" + mappingId
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def get_saml2_idp_group_mappings(self, idp, limit=None, page=None, headers=None):
        url = build_url(self.endpoints["host"] + "/identityProviders/" + idp["id"] + "/groupMappings/",
                        limit=limit, page=page)
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def add_idp_user(self, idp, raw_data, headers=None):
        url = build_url(self.endpoints["host"] + "/identityProviders/" + idp["id"] + "/users")
        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=raw_data, verify=self.verify)

    def delete_idp_user(self, idp, user, headers=None):
        url = build_url(self.endpoints["host"] + "/identityProviders/" + idp["id"] + "/users/" + user["id"])
        return requests.delete(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def add_idp_group(self, idp, raw_data, headers=None):
        url = build_url(self.endpoints["host"] + "/identityProviders/" + idp["id"] + "/groups")
        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=raw_data, verify=self.verify)

    def get_idp_group(self, idp, group, headers=None):
        url = build_url(self.endpoints["host"] + "/identityProviders/" + idp["id"] + "/groups/" + group["id"])
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def get_idp_groups(self, idp, limit=None, page=None, headers=None, sort_by=None, sort_order=None, name=None,
                       lifecycle_state=None):
        query = dict()
        query['sortBy'] = sort_by
        query['sortOrder'] = sort_order
        query['name'] = name
        query['lifecycleState'] = lifecycle_state
        query['limit'] = limit
        query['page'] = page
        query['compartmentId'] = self.compartment_id
        url = build_url(
            self.endpoints["host"] + "/identityProviders/" + idp["id"] + "/groups", **query)
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def delete_idp_group(self, idp, group, headers=None):
        url = build_url(self.endpoints["host"] + "/identityProviders/" + idp["id"] + "/groups/" + group["id"])
        return requests.delete(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def add_user_to_idp_group(self, idp, groupId, raw_data, headers=None):
        url = build_url(
            self.endpoints["host"] + "/identityProviders/" + idp["id"] + "/groups/" + groupId + "/actions/addUser")
        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=raw_data, verify=self.verify)

    def remove_user_from_idp_group(self, idp, groupId, raw_data, headers=None):
        url = build_url(
            self.endpoints["host"] + "/identityProviders/" + idp["id"] + "/groups/" + groupId + "/actions/removeUser")
        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=raw_data, verify=self.verify)

    def list_user_idp_group_memberships(self, idp, userId, groupId, headers=None):
        query = dict()
        if userId:
            query["userId"] = userId
        if groupId:
            query["groupId"] = groupId
        url = build_url(self.endpoints["host"] + "/identityProviders/" + idp["id"] + "/userIdpGroupMemberships",
                        **query)
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def reset_scim_client(self, idp, headers=None):
        data = {}
        url = self.endpoints["host"] + "/identityProviders/" + idp["id"] + "/actions/resetScimClient/"
        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                             verify=self.verify)

    # POLICY =================================================================================================== POLICY
    def add_policy(self, policy, compartment=None, headers=None):
        if compartment:
            data = {**policy, "compartmentId": compartment}
        else:
            data = {**policy, "compartmentId": self.compartment_id}
        url = self.endpoints["host"] + "/policies"
        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                             verify=self.verify)

    def add_policy_with_tags(self, policy, compartment=None, headers=None):
        if compartment:
            data = {**policy, "compartmentId": compartment}
        else:
            data = {**policy, "compartmentId": self.compartment_id}
        url = self.endpoints["host"] + "/policies"

        if "freeformTags" in policy:
            data["freeformTags"] = policy["freeformTags"]
        if "definedTags" in policy:
            data["definedTags"] = policy["definedTags"]
        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                             verify=self.verify)

    def get_policy(self, policy, headers=None):
        url = self.endpoints["host"] + "/policies/" + policy["id"]
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def get_policies(self,
                     compartment_id=None,
                     limit=None,
                     page=None,
                     headers=None,
                     sort_by=None,
                     sort_order=None,
                     name=None,
                     lifecycle_state=None):
        if not compartment_id:
            compartment_id = self.compartment_id

        query = dict()
        query['sortBy'] = sort_by
        query['sortOrder'] = sort_order
        query['name'] = name
        query['lifecycleState'] = lifecycle_state
        query['limit'] = limit
        query['page'] = page
        query['compartmentId'] = compartment_id

        url = build_url(
            self.endpoints["host"] + "/policies", **query)
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def get_policies_tag_filter(self, tagName=None, tagValue=None, limit=None, page=None, headers=None):
        query = {
            "compartmentId": self.compartment_id,
            "limit": limit,
            "page": page,
            tagName: tagValue,
        }
        url = build_url(self.endpoints["host"] + "/policies", **query)
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def update_policy(self, policy, headers=None):
        url = self.endpoints["host"] + "/policies/" + policy["id"]
        data = {}
        # If either the description or statements or both are present (whether empty or not) in the policy object,
        # send request normally. This covers the empty cases:
        # - empty description, non-empty statements
        # - non-empty description, empty statements
        # - empty description, empty statements
        # - non-empty description, non-empty statements
        # - null description, non-empty/empty statements
        # - non-empty/empty description, null statements
        if "description" in policy:
            data["description"] = policy["description"]
        if "statements" in policy:
            data["statements"] = policy["statements"]
        return requests.put(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                            verify=self.verify)

    def update_policy_tags(self, policy, headers=None):
        url = self.endpoints["host"] + "/policies/" + policy["id"]
        data = {}
        # If either the description or statements or both are present (whether empty or not) in the policy object,
        # send request normally. This covers the empty cases:
        # - empty description, non-empty statements
        # - non-empty description, empty statements
        # - empty description, empty statements
        # - non-empty description, non-empty statements
        # - null description, non-empty/empty statements
        # - non-empty/empty description, null statements
        if "freeformTags" in policy:
            data["freeformTags"] = policy["freeformTags"]
        if "definedTags" in policy:
            data["definedTags"] = policy["definedTags"]
        return requests.put(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                            verify=self.verify)

    def delete_policy(self, policy, headers=None):
        url = self.endpoints["host"] + "/policies/" + policy["id"]
        return requests.delete(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    # PASSWORD =============================================================================================== PASSWORD
    def set_user_password(self, user, current_password, new_password, password_reset_token=None, headers=None):
        data = {"newPassword": new_password, 'currentPassword': current_password}
        if password_reset_token is not None:
            data["passwordResetToken"] = password_reset_token
        return self.set_user_password_with_data(user, json.dumps(data), headers)

    def set_user_password_with_data(self, user, raw_data, headers=None):
        url = self.endpoints["internal"] + "/users/" + user["id"] + "/uiPassword"
        return requests.put(url, headers=self.headers(headers), auth=self.auth, data=raw_data, verify=self.verify)

    def reset_user_password(self, user, headers=None):
        url = self.endpoints["host"] + "/users/" + user["id"] + "/uiPassword"
        return requests.post(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def get_user_password(self, user, headers=None):
        url = self.endpoints["host"] + "/users/" + user["id"] + "/uiPassword"
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    # COMPARTMENT ========================================================================================= COMPARTMENT
    # https://jira.oci.oraclecorp.com/browse/COMP-1101
    def add_compartment(self, compartment, headers=None):
        data = {**compartment, "compartmentId": self.compartment_id}
        url = self.endpoints["compartment-cp"] + "/compartments"
        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                             verify=self.verify)

    def add_nested_compartment(self, compartment, nested_compartment, headers=None):
        data = {**nested_compartment, "compartmentId": compartment["id"]}
        url = self.endpoints["compartment-cp"] + "/compartments"
        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data))

    def bootstrap_managed_compartment(self, parent_compartment_id, name, headers=None):
        data = {
            "compartmentId": parent_compartment_id,
            "name": name,
            "serviceName": "PSM",
            "description": "this is the managed compartment",
            "propertyMap": {"manageStatus": "MANAGED"}
        }
        url = self.endpoints["compartment-cp"] + "/managedCompartments/bootstrap"
        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                             verify=self.verify)

    def delete_compartment_admin_task(self, compartment_ids, headers=None):

        data = {
            "operationName": "DELETE_COMPARTMENTS_REGARDLESS",
            "param": {"CM": "N/A"},
            "data": {
                "compartmentIds": compartment_ids
            }
        }
        url = self.endpoints["compartment-admin"] + "/tasks/deleteCompartmentsTask"
        return requests.post(url, headers=self.headers(headers), auth=None, data=json.dumps(data), verify=self.verify)

    def s2s_create_managed_compartment(self, tenancy_id, name, service_entitlement_id, service_name, headers=None):
        data = {
            "compartmentId": tenancy_id,
            "name": name,
            "serviceName": service_name,
            "description": "this is the managed compartment",
            "serviceEntitlementId": service_entitlement_id
        }
        url = self.endpoints["compartment-cp"] + "/managedCompartments"
        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                             verify=self.verify)

    def s2s_list_managed_compartment(self, tenancy_id, service_name, headers=None):
        url = build_url(self.endpoints["compartment-cp"] + "/managedCompartments", serviceName=service_name,
                        tenancyId=tenancy_id)
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def add_compartment_with_tags(self, compartment, headers=None):
        data = {**compartment, "compartmentId": self.compartment_id}
        url = self.endpoints["compartment-cp"] + "/compartments"

        if "freeformTags" in compartment:
            data["freeformTags"] = compartment["freeformTags"]
        if "definedTags" in compartment:
            data["definedTags"] = compartment["definedTags"]
        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                             verify=self.verify)

    def get_compartment(self, compartment, headers=None):
        url = self.endpoints["compartment-cp"] + "/compartments/" + compartment["id"]
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def get_compartments(self, limit=None, page=None, headers=None, compartmentid=None, sort_by=None, sort_order=None,
                         name=None, lifecycle_state=None):
        query = dict()
        query['sortBy'] = sort_by
        query['sortOrder'] = sort_order
        query['name'] = name
        query['lifecycleState'] = lifecycle_state
        query['limit'] = limit
        query['page'] = page
        query['compartmentId'] = compartmentid or self.compartment_id

        url = build_url(self.endpoints["compartment-cp"] + "/compartments", **query)
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def get_tenancy_compartments(self, limit=None, page=None, headers=None, compartmentid=None, sort_by=None,
                                 sort_order=None, name=None, lifecycle_state=None, compartmentid_in_subtree=None):
        query = dict()
        query['sortBy'] = sort_by
        query['sortOrder'] = sort_order
        query['name'] = name
        query['lifecycleState'] = lifecycle_state
        query['limit'] = limit
        query['page'] = page
        query['compartmentId'] = compartmentid or self.compartment_id
        query['compartmentIdInSubtree'] = compartmentid_in_subtree or True

        url = build_url(self.endpoints["compartment-cp"] + "/compartments", **query)
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def get_compartments_with_access_level(self, limit=None, page=None, headers=None, compartment_id=None,
                                           access_level="ANY", compartment_id_in_subtree=None):
        url = build_url(self.endpoints["compartment-cp"] + "/compartments",
                        compartmentId=compartment_id or self.compartment_id, limit=limit, page=page,
                        accessLevel=access_level,
                        compartmentIdInSubtree=compartment_id_in_subtree)
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def get_accessible_only_compartments(self, limit=None, page=None, headers=None, compartment_id=None,
                                         compartment_id_in_subtree=None):
        return self.get_compartments_with_access_level(limit, page, headers, compartment_id, "ACCESSIBLE",
                                                       compartment_id_in_subtree)

    def get_all_accessible_only_compartments(self, limit=None, headers=None, compartment_id=None,
                                             compartment_id_in_subtree=None):
        page_token = None
        result = []
        while True:
            response = self.get_accessible_only_compartments(limit=limit, page=page_token, headers=headers,
                                                             compartment_id=compartment_id,
                                                             compartment_id_in_subtree=compartment_id_in_subtree)
            comps = response.json()
            result.extend(comps)
            if "opc-next-page" not in response.headers:
                break
            page_token = response.headers["opc-next-page"]
        return result

    def list_compartments_for_tenant_internal(self, tenancy_id, limit=None, page=None, headers=None):
        url = build_url(
            self.endpoints["compartment-internal"] + "/tenants/" + tenancy_id + "/compartments", limit=limit, page=page)
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def list_all_tenancy_compartments_internal(self, tenancy_id, key):
        self.bind(key=key)
        compartments = []
        pageToken = None
        while True:
            with http_retry(Status.OK):
                response = self.list_compartments_for_tenant_internal(tenancy_id, 5, pageToken)
            comps = response.json()
            if len(comps) == 0 or response.headers["opc-next-page"] is None:
                break
            pageToken = response.headers["opc-next-page"]
            compartments.extend(comps)
        return compartments

    def get_compartments_tag_filter(self, tagName=None, tagValue=None, limit=None, page=None, headers=None):
        query = {
            "compartmentId": self.compartment_id,
            "limit": limit,
            "page": page,
            tagName: tagValue,
        }
        url = build_url(self.endpoints["compartment-cp"] + "/compartments", **query)
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def get_capabilities(self, id, headers=None):
        url = self.endpoints["compartment-cp"] + "/compartments/" + id + "/capabilities"
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def update_compartment(self, compartment, headers=None):
        url = self.endpoints["compartment-cp"] + "/compartments/" + compartment["id"]
        data = {}
        if "description" in compartment:
            data = {"description": compartment["description"]}
        return requests.put(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                            verify=self.verify)

    def update_compartment_tags(self, compartment, headers=None):
        url = self.endpoints["compartment-cp"] + "/compartments/" + compartment["id"]
        data = {}
        if "freeformTags" in compartment:
            data["freeformTags"] = compartment["freeformTags"]
        if "definedTags" in compartment:
            data["definedTags"] = compartment["definedTags"]
        return requests.put(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                            verify=self.verify)

    def rename_compartment(self, compartment, headers=None):
        url = self.endpoints["compartment-cp"] + "/compartments/" + compartment["id"]
        data = {}
        if "name" in compartment:
            data = {"name": compartment["name"]}
        return requests.put(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                            verify=self.verify)

    def get_work_request(self, id, headers=None):
        url = self.endpoints["compartment-cp"] + "/workRequests/" + id
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def list_work_requests(self, limit=None, page=None, headers=None, compartment_id=None, resource_identifier=None):
        query = dict()
        query['limit'] = limit
        query['page'] = page
        query['compartmentId'] = compartment_id or self.compartment_id
        if resource_identifier is not None:
            query['resourceIdentifier'] = resource_identifier

        url = build_url(self.endpoints["compartment-cp"] + "/workRequests", **query)
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def delete_compartment(self, compartment, headers=None):
        url = self.endpoints["compartment-cp"] + "/compartments/" + compartment["id"]
        return requests.delete(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def move_compartment(self, compartment, targetCompartment, headers=None):
        url = self.endpoints["compartment-cp"] + "/compartments/" + compartment["id"] + "/actions/moveCompartment"
        data = {"targetCompartmentId": targetCompartment["id"]}
        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                             verify=self.verify)

    def recover_compartment(self, compartment, headers=None):
        url = self.endpoints["compartment-cp"] + "/compartments/" + compartment["id"] + "/actions/recoverCompartment"
        return requests.post(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    # AD =========================================================================================================== AD
    def get_availability_domains(self, compartment_id=None, headers=None):
        query = dict()
        query['compartmentId'] = compartment_id or self.compartment_id
        url = build_url(self.endpoints["compartment-cp"] + "/availabilityDomains", **query)
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def get_fault_domains(self, availability_domain, compartment_id=None, headers=None):
        query = dict()
        query['availabilityDomain'] = availability_domain
        query['compartmentId'] = compartment_id or self.compartment_id
        url = build_url(self.endpoints["compartment-cp"] + "/faultDomains", **query)
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def get_services(self, headers=None):
        url = self.endpoints["devops"] + "/serviceManagers/"
        return requests.get(url, headers=self.headers(headers), auth=self.auth,
                            verify=False,
                            cert=(cert_path("identity", "devopsClient.crt"),
                                  cert_path("identity", "devopsClient.key")))

    def add_service(self, service, headers=None):
        ControlPlane.services.add((self, service["tenantId"]))
        return self.add_service_with_data(json.dumps(service), headers)

    def add_service_with_data(self, raw_data, headers=None):
        url = self.endpoints["devops"] + "/serviceManagers/"
        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=raw_data,
                             verify=False,
                             cert=(cert_path("identity", "devopsClient.crt"),
                                   cert_path("identity", "devopsClient.key")))

    def delete_service(self, tenant_id, headers=None):
        if (self, tenant_id) in ControlPlane.services:
            ControlPlane.services.remove((self, tenant_id))
        url = self.endpoints["internal"] + "/serviceManagers/" + tenant_id
        return requests.delete(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def set_compartment_rename_service(self, enabled):
        query = {"action": "setEnabled", "enabled": enabled}
        url = build_url(
            self.endpoints["admin"] + "/tasks/setCompartmentRenameService",
            **query)
        return requests.post(url, verify=self.verify)

    # Authentication policy ======================================================================Authentication policy
    def get_authentication_policy(self, compartmentid):
        url = build_url(
            self.endpoints["host"] + "/authenticationPolicies/" + compartmentid)
        response = requests.get(url, headers=None, auth=self.auth)
        assert response is not None
        return response

    def update_authentication_policy(self, compartmentid, authentication_policy):
        url = self.endpoints["host"] + "/authenticationPolicies/" + compartmentid
        response = requests.put(url, data=json.dumps(authentication_policy), headers=self.headers(None), auth=self.auth)
        assert response is not None
        return response

    # Account recovery =========================================================================================================== Account recovery
    def get_verification_token_by_user_id(self, user_id):
        query = {"action": "getVerificationTokenByUserId", "userId": user_id}
        url = build_url(
            self.endpoints["admin"] + "/tasks/accountRecovery",
            **query)
        return requests.post(url, verify=self.verify)

    def delete_verification_token(self, token, tenant_id):
        query = {"action": "deleteVerificationToken", "tokenId": token, "tenantId": tenant_id}
        url = build_url(
            self.endpoints["admin"] + "/tasks/accountRecovery",
            **query)
        return requests.post(url, verify=self.verify)

    def verify_user_email(self, user, token, headers=None):
        data = {"emailVerificationToken": token}

        url = self.endpoints["host"] + "/users/" + user["id"] + "/actions/verifyEmail"
        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                             verify=self.verify)

    def send_password_reset(self, email, tenantName, headers=None):
        data = {"email": email, "tenantName": tenantName}

        url = self.endpoints["internal"] + "/users/actions/sendPasswordReset"
        return requests.post(url, headers=self.headers(BYPASS_HEADER, headers), data=json.dumps(data),
                             verify=self.verify)

    def get_user_email_verification_tokens(self, user, headers=None):
        url = self.endpoints["internal"] + "/users/" + user["id"] + "/emailVerificationTokens"
        return requests.get(url, headers=self.headers(BYPASS_HEADER, headers), verify=self.verify)

    def delete_user_email_verification_token(self, user, token, headers=None):
        url = self.endpoints["internal"] + "/users/" + user["id"] + "/emailVerificationTokens/" + token
        return requests.delete(url, headers=self.headers(BYPASS_HEADER, headers), verify=self.verify)

    # Stripe =========================================================================================================== Stripe

    def create_stripe(self, compartmentId, region, headers=None):
        data = {"compartmentId": compartmentId, "region": region}
        url = self.endpoints["host"] + "/stripes/"
        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                             verify=self.verify)


class EchoService(Client):
    def echo(self, message, headers=None):
        url = self.endpoints["host"] + "/echo/" + message
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def head_echo(self, message, headers=None):
        url = self.endpoints["host"] + "/echo/head" + message
        return requests.head(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def get_internal_ad_mapping(self, external_name, headers=None):
        url = build_url(
            self.endpoints["host"] + "/metadata/adMapping/" + self.compartment_id,
            externalAdName=encode(external_name))
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def get_external_ad_mapping(self, internal_name, headers=None):
        url = build_url(
            self.endpoints["host"] + "/metadata/adMapping/" + self.compartment_id,
            internalAdName=encode(internal_name))
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def post_s2s(self, valid_leaf, valid_int, tenant_id, headers=None):
        data = {"validLeaf": valid_leaf, "validInt": valid_int, "tenantId": tenant_id}
        url = build_url(self.endpoints["host"] + "/s2s")
        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                             verify=self.verify)

    def probe_casper(self, compartment_id, permission, instance_compartment_id, instance_id=None, headers=None):
        url = self.endpoints["host"] + "/echo/probe_casper/%s/bucket/%s/%s" % (
            compartment_id, permission, instance_compartment_id)
        if instance_id:
            url += '?instanceId=' + instance_id

        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    # simulate an "add tag namespace" request to the echo service "/echo/tagNamespaces"
    # to verify the data plane can authorize adding tagging contained in the new tag namespace object
    def probe_add_tag_namespace_tagging_authorization(self, tag_namespace, compartment, headers=None):
        data = {**tag_namespace, "compartmentId": compartment["id"]}
        url = self.endpoints["host"] + "/echo/tagNamespaces"
        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data))

    def probe(self, compartment, headers=None):
        return self._probe_simple("probe", compartment, headers)

    def probe_1(self, compartment, headers=None):
        return self._probe_simple("probe_1", compartment, headers)

    def probe_2(self, compartment, headers=None):
        return self._probe_simple("probe_2", compartment, headers)

    def probe_3(self, compartment, headers=None):
        return self._probe_simple("probe_3", compartment, headers)

    def probe_reviewed(self, compartment, headers=None):
        return self._probe_simple("probe_reviewed", compartment, headers)

    def probe_reviewed_1(self, compartment, headers=None):
        return self._probe_simple("probe_reviewed_1", compartment, headers)

    def probe_reject_true(self, compartment, headers=None):
        return self._probe_simple("probe_reject_true", compartment, headers)

    def probe_reject_false(self, compartment, headers=None):
        return self._probe_simple("probe_reject_false", compartment, headers)

    def probe_reject_default(self, compartment, headers=None):
        return self._probe_simple("probe_reject_default", compartment, headers)

    def _probe_simple(self, path, compartment, headers=None):
        url = self.endpoints["host"] + "/echo/" + path + "/" + compartment
        return requests.Session().head(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def probe_m(self, compartment1, compartment2, headers=None):
        url = build_url(self.endpoints["host"] + "/echo/probe_m/",
                        compartmentId1=compartment1,
                        compartmentId2=compartment2)
        return requests.head(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def probe_permission(self, permission, headers=None):
        url = self.endpoints["host"] + "/echo/probe_p/" + permission
        return requests.head(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def probe_resource_kind(self, resource_kinds, headers=None):
        url = build_url(self.endpoints["host"] + "/echo/probe_resource_kind", resourceKinds=resource_kinds)
        return requests.head(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def probe_context_variable(self, type, name, value, permission, headers=None):
        url = self.endpoints["host"] + "/echo/probe_cv/" + "/".join([type, name, value, permission])
        return requests.head(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def probe_network_source(self, network_source_type, vcn_ocid, ip, permission, headers=None):
        url = build_url(
            self.endpoints["host"] + "/echo/probe_networkSource/" + "/".join([network_source_type, ip, permission]),
            vcnOcid=vcn_ocid)
        return requests.head(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def get_idp_metadata(self, headers=None):
        url = build_url(
            self.endpoints["host"] + "/saml/metadata")
        return requests.get(url, headers=self.headers(headers), verify=self.verify).content.decode('utf-8')

    def get_idp_metadata_enc(self, headers=None):
        url = build_url(
            self.endpoints["host"] + "/saml/metadata/enc")
        return requests.get(url, headers=self.headers(headers), verify=self.verify).content.decode('utf-8')

    def get_idp_metadata_hok(self, headers=None):
        url = build_url(
            self.endpoints["host"] + "/saml/metadata/hok")
        return requests.get(url, headers=self.headers(headers), verify=self.verify).content.decode('utf-8')

    def get_idp_metadata_enc_hok(self, headers=None):
        url = build_url(
            self.endpoints["host"] + "/saml/metadata/hokenc")
        return requests.get(url, headers=self.headers(headers), verify=self.verify).content.decode('utf-8')

    def get_idp_metadata_2(self, headers=None):
        url = build_url(
            self.endpoints["host"] + "/saml/metadata/2")
        return requests.get(url, headers=self.headers(headers), verify=self.verify).content.decode('utf-8')

    def authenticate_smtp(self, username, password, headers=None):
        data = {"userName": username, "password": password}
        return self.authenticate_smtp_with_data(json.dumps(data), headers)

    def authenticate_smtp_with_data(self, raw_data, headers=None):
        url = self.endpoints["host"] + "/credential/smtp"
        return requests.post(url, headers=self.headers(headers), data=raw_data, verify=self.verify)

    def cross_tenancy_check(self,
                            permission_1, compartment_1, resource_kind_1, expected_permission_result_1,
                            permission_2, compartment_2, resource_kind_2, expected_permission_result_2,
                            expected_association_result, headers=None):
        url = build_url(self.endpoints["host"] + "/crossTenancy/verify/")

        data = {
            "resourceKind1": resource_kind_1,
            "compartmentId1": compartment_1,
            "permission1": permission_1,
            "resourceKind2": resource_kind_2,
            "compartmentId2": compartment_2,
            "permission2": permission_2,
            "expectedPermissionResult1": expected_permission_result_1,
            "expectedPermissionResult2": expected_permission_result_2,
            "expectedAssociationResult": expected_association_result,
        }
        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                             verify=self.verify)


class KeyVendingService(Client):
    def create_customer_secret_key(self, user_id, tenant_id, headers=None):
        url = build_url(self.endpoints["host"] + "/keys/" + user_id + "/" + tenant_id)
        return requests.post(url, headers=self.headers(headers), auth=None)

    def get_derived_key(self, key_id, region, date, service_name, headers=None):
        url = build_url(self.endpoints["host"] + "/derivedKey/" + key_id + "/" + region + "/" +
                        date + "/" + service_name)
        return requests.get(url, headers=self.headers(headers), auth=None)


class DataPlane(Client):
    def get_tenant(self, compartment_id, include_properties=None, headers=None):
        if not compartment_id:
            compartment_id = self.compartment_id

        url = build_url(
            self.endpoints["host"] + "/compartments/" + compartment_id + "/tenant",
            includeExtendedProperties=include_properties)
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def get_tenant_by_name(self, tenant_name, include_properties=None, headers=None):
        url = build_url(
            self.endpoints["host"] + "/tenants/" + tenant_name,
            includeExtendedProperties=include_properties)
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def get_tenancy_by_service_instance_guid(self, service_instance_guid, headers=None):
        url = build_url(
            self.endpoints["host"] + "/tenants/", serviceInstanceGuid=service_instance_guid)
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def get_compartments_under_parent(self, compartment_id, compartment_name, headers=None):
        if not compartment_id:
            compartment_id = self.compartment_id
        url = build_url(
            self.endpoints["host"] + "/compartments/" + compartment_id + "/children", name=compartment_name)
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def get_compartment(self, compartment_id, include_properties=None, headers=None):
        if not compartment_id:
            compartment_id = self.compartment_id

        url = build_url(
            self.endpoints["host"] + "/compartments/" + compartment_id, includeExtendedProperties=include_properties)
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def get_parent_compartment(self, compartment_id, headers=None):
        if not compartment_id:
            compartment_id = self.compartment_id
        url = build_url(
            self.endpoints["host"] + "/compartments/" + compartment_id + "/parent")
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def is_compartment_managed(self, headers=None):
        url = build_url(self.endpoints["host"] + "/compartments/" + self.compartment_id + "/managedStatus")
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def get_compartment_tree(self, tenant_id, headers=None):
        url = build_url(self.endpoints["host"] + "/compartments/" + tenant_id + "/compartmentTree")
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def get_cost_tracking_tags(self, headers=None):
        url = build_url(self.endpoints["host"] + "/compartments/" + self.compartment_id + "/costTrackingTags")
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def get_availability_domains(self, headers=None):
        url = build_url(
            self.endpoints["host"] + "/metadata/availabilityDomains",
            compartmentId=self.compartment_id)
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def get_fault_domains(self, availability_domain, headers=None):
        url = build_url(
            self.endpoints["host"] + "/metadata/faultDomains",
            compartmentId=self.compartment_id,
            availabilityDomain=availability_domain)
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def get_backup(self, headers=None):
        url = self.endpoints["internal"] + "/backup"
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def authenticate(self, user, password, tenant_name=None, tenant_id=None, mode=None, headers=None):
        data = {"userName": user['name'], "tenantName": tenant_name, "tenantId": tenant_id, "password": password}
        return self.authenticate_with_data(json.dumps(data), mode, headers)

    def authenticate_with_data(self, raw_data, mode=None, headers=None):
        url = build_url(self.endpoints["host"] + "/authentication", mode=mode)
        return requests.post(url, headers=self.headers(headers), data=raw_data, verify=self.verify)

    def authenticate_and_return_result_object(self, user, password, tenant_name=None, tenant_id=None, mode=None,
                                              headers=None):
        data = {"userName": user['name'], "tenantName": tenant_name, "tenantId": tenant_id, "password": password}
        return self.authenticate_and_return_result_object_with_data(json.dumps(data), mode, headers)

    def authenticate_and_return_result_object_with_data(self, raw_data, mode=None, headers=None):
        url = build_url(self.endpoints["host"] + "/authentication/authenticate", mode=mode)
        return requests.post(url, headers=self.headers(headers), data=raw_data, verify=self.verify)

    def get_credential_parameters_with_data(self, raw_data, headers=None):
        url = build_url(self.endpoints["host"] + "/authentication/credential/parameter")
        return requests.post(url, headers=self.headers(headers), data=raw_data, verify=self.verify)

    def authenticate_credential_with_data(self, raw_data, headers=None):
        url = build_url(self.endpoints["host"] + "/authentication/credential")
        return requests.post(url, headers=self.headers(headers), data=raw_data, verify=self.verify)

    def get_api_key_over_public(self, key_id, auth=False):
        url = build_url(self.endpoints["public"] + "/SR/keys/" + key_id)
        return requests.get(url, auth=self.auth if auth else None, verify=self.verify)

    def get_token_for_x509_certificate(
            self,
            certificate,
            intermediates,
            public_key,
            headers=None,
            purpose_of_using_instance_principal_cert=None):
        url = self.endpoints["public"] + "/x509"
        data = {"certificate": certificate, "publicKey": public_key, "intermediateCertificates": intermediates}

        # when purpose_of_using_instance_principal_cert is "SERVICE_PRINCIPAL",
        # we will issue service-principal token instead of instance-principal token for instance-principal certs
        if purpose_of_using_instance_principal_cert is not None:
            data["purpose"] = purpose_of_using_instance_principal_cert

        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                             verify=self.verify)

    def get_service_principal_session_token(self,
                                            target_service_principal_name,
                                            target_tenant_id,
                                            service_principal_session_token,
                                            session_key_pair=None,
                                            request_headers=None,
                                            headers=None):

        url = self.endpoints["public"] + "/servicePrincipalSessionToken"

        data = {
            "requestHeaders": request_headers,
            "targetServicePrincipalName": target_service_principal_name,
            "targetTenantId": target_tenant_id,
            "targetSessionPublicKey": credentials.sanitize(session_key_pair['public']),
            "requesterCredentialType": 'SERVICE_PRINCIPAL_SESSION_TOKEN',
            "requesterCredential": service_principal_session_token
        }
        response = requests.post(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                                 verify=self.verify)
        if response.ok:
            token = response.json()['token']
            assert token
            rpst_key_set = shapes.valid.key(
                public=session_key_pair['public'],
                private=session_key_pair['private'],
                keyId='ST$' + token)
            return rpst_key_set
        return None

    def get_resource_principal_session_token(self,
                                             resource_principal_token,
                                             service_principal_session_token,
                                             session_key_pair=None,
                                             request_headers=None,
                                             headers=None):
        if session_key_pair is None:
            session_key_pair = shapes.valid.key(2048)
        url = self.endpoints["public"] + "/resourcePrincipalSessionToken"
        data = {
            "requestHeaders": request_headers,
            "resourcePrincipalToken": resource_principal_token,
            "servicePrincipalSessionToken": service_principal_session_token,
            "sessionPublicKey": credentials.sanitize(session_key_pair['public'])
        }
        response = requests.post(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                                 verify=self.verify)
        if response.ok:
            token = response.json()['token']
            assert token
            rpst_key_set = shapes.valid.key(
                public=session_key_pair['public'],
                private=session_key_pair['private'],
                keyId='ST$' + token)
            return rpst_key_set
        return None

    def get_instance_roots(self, headers=None, auth=True):
        url = self.endpoints["public"] + "/instancePrincipalRootCACertificates"

        return requests.get(url, headers=self.headers(headers), auth=self.auth if auth else None)

    def get_obo_token(self, request_headers, service_name, obo_token=None, headers=None):
        url = self.endpoints["public"] + "/obo"
        data = {"targetServiceName": service_name, "requestHeaders": request_headers, 'oboToken': obo_token}

        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                             verify=self.verify)

    def authenticate_client(self, request_headers, headers=None):
        url = self.endpoints["public"] + "/authentication/authenticateClient"
        data = {"requestHeaders": request_headers}

        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data))

    def filter_group_membership(self, principal, groups, headers=None):
        url = self.endpoints["public"] + "/filterGroupMembership"
        data = {"principal": principal,
                "groupIds": groups}

        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data))

    def get_obo_token_multi_target(self, request_headers, service_names, obo_token=None, headers=None):
        url = self.endpoints["public"] + "/obo"
        data = {"targetServiceNames": service_names, "requestHeaders": request_headers, 'oboToken': obo_token}

        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                             verify=self.verify)

    def get_delegation_token(self, request_headers, service_names, delegate_groups,
                             expiration=None, obo_token=None, headers=None):
        url = self.endpoints["public"] + "/obo"
        data = {"targetServiceNames": service_names,
                "requestHeaders": request_headers,
                'oboToken': obo_token,
                'requestType': 'DELEGATION',
                'expiration': expiration,
                'delegateGroups': delegate_groups}

        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                             verify=self.verify)

    def get_jwt_token(self, client_id, client_secret, scope, headers=None):
        if headers is None:
            headers = {}
        headers['Content-Type'] = "application/x-www-form-urlencoded"
        headers['Authorization'] = 'Basic ' + \
                                   base64.b64encode((client_id + ':' + client_secret).encode()).decode('utf-8')

        url = self.endpoints["public"][:-3] + "/oauth2/token"
        data = {"grant_type": "client_credentials", "scope": scope}

        return requests.post(url, headers=self.headers(headers), data=data, verify=self.verify)

    def get_identity_providers(self, tenant_name, provider_name=None, headers=None):
        url = build_url(
            self.endpoints["host"] +
            "/identityProviders/" + tenant_name,
            providerName=provider_name)
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def get_sp_metadata(self, tenant_id, headers=None):
        url = build_url(
            self.endpoints["host"] + "/saml/" + tenant_id + "/metadata.xml")
        return requests.get(url, headers=self.headers(headers), verify=self.verify).content.decode('utf-8')

    def refresh_login_token(self, token, new_key=None, renewable_duration=None, expiry_duration=None, headers=None):
        url = self.endpoints["public"] + "/authentication/refresh"
        data = {"currentToken": token, "newPublicKey": new_key, "sessExpDurationInMinutes": renewable_duration,
                "expDurationInMinutes": expiry_duration}
        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                             verify=self.verify)

    def mfa_totp_authenticate(self, idtoken, totptoken, headers=None):
        url = self.endpoints["host"] + "/authentication/mfa/totpVerify"
        data = {"idToken": idtoken, "totpToken": totptoken}

        return requests.post(url, headers=self.headers(headers), data=json.dumps(data), verify=self.verify)

    def get_key_for_signed_request_verification(self, key_id, region, date, service_name, headers=None):
        url = build_url(
            self.endpoints["host"] + "/keys/" + key_id + "/" + region + "/" + date + "/" + service_name)
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def authorize_request(self, data, headers=None):
        url = build_url(
            self.endpoints["host"] + "/authorization/authorizerequest")
        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=json.dumps(data),
                             verify=self.verify)

    def authorize_request_handler_with_data(self, raw_data, headers=None):
        url = self.endpoints["host"] + "/subscription/subscriberequest"
        return requests.post(url, headers=self.headers(headers), auth=self.auth, data=raw_data, verify=self.verify)

    def get_user(self, user_id, headers=None):
        url = build_url(
            self.endpoints["host"] + "/users/" + user_id)
        return requests.get(url, headers=self.headers(headers), auth=self.auth, verify=self.verify)

    def get_credentials_for_authentication(self, user, tenant_name=None, tenant_id=None, mode=None, headers=None):
        data = {"userName": user['name'], "tenantName": tenant_name, "tenantId": tenant_id}
        return self.get_credentials_for_authentication_with_data(json.dumps(data), mode, headers)

    def get_credentials_for_authentication_with_data(self, raw_data, mode=None, headers=None):
        url = build_url(self.endpoints["host"] + "/authentication/credentials", mode=mode)
        return requests.post(url, headers=self.headers(headers), data=raw_data)

    def get_authentication_policy(self, comaprtmentid, log):
        log.info("getting authentication policy from the dataplane for the compartment id %s", comaprtmentid)
        url = build_url(
            self.endpoints["host"] + "/authenticationPolicies/" + comaprtmentid)
        log.info("The url formed is %s", url)
        response = requests.get(url, headers=None, auth=self.auth)
        return response

    def authenticate_password_reset_token(self, user_id, token):
        data = {"userId": user_id, "passwordResetToken": token}
        url = self.endpoints["host"] + "/authentication/authenticate/passwordResetToken"
        return requests.post(url, data=json.dumps(data), headers=None, auth=self.auth)


class ScimService(Client):
    def get(self, url, headers=None):
        return requests.get(url, headers=self.headers(headers), auth=None)

    def post(self, url, data=None, headers=None):
        return requests.post(url, headers=self.headers(headers), data=json.dumps(data), auth=None)

    def create_user(self, data, headers=None):
        url = build_url(self.endpoints["host"] + "/Users")

        return requests.post(url, headers=self.headers(headers), data=json.dumps(data), auth=None)

    def get_user(self, user_id, headers=None):
        url = build_url(self.endpoints["host"] + "/Users/" + user_id)
        return requests.get(url, headers=self.headers(headers), auth=None)

    def list_users(self, params=None, headers=None):
        url = build_url(self.endpoints["host"] + "/Users", **params)
        return requests.get(url, headers=self.headers(headers), auth=None)

    def delete_user(self, user_id, headers=None):
        url = build_url(self.endpoints["host"] + "/Users/" + user_id)
        return requests.delete(url, headers=self.headers(headers), auth=None)

    def activate_user(self, user_id, headers=None):
        url = build_url(self.endpoints["host"] + "/Users/" + user_id)
        data = {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{
                "op": "replace",
                "value": {
                    "active": "True"
                }
            }]
        }
        return requests.patch(url, headers=self.headers(headers), data=json.dumps(data), auth=None)

    def deactivate_user(self, user_id, headers=None):
        url = build_url(self.endpoints["host"] + "/Users/" + user_id)
        data = {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{
                "op": "replace",
                "value": {
                    "active": "False"
                }
            }]
        }
        return requests.patch(url, headers=self.headers(headers), data=json.dumps(data), auth=None)

    def create_group(self, data, headers=None):
        url = build_url(self.endpoints["host"] + "/Groups")
        return requests.post(url, headers=self.headers(headers), data=json.dumps(data), auth=None)

    def get_group(self, group_id, headers=None):
        url = build_url(self.endpoints["host"] + "/Groups/" + group_id)
        return requests.get(url, headers=self.headers(headers), auth=None)

    def delete_group(self, group_id, headers=None):
        url = build_url(self.endpoints["host"] + "/Groups/" + group_id)
        return requests.delete(url, headers=self.headers(headers), auth=None)

    def add_user_to_group(self, group_id, user_id, headers=None):
        data = {'schemas': ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
                'Operations': [
                    {'op': 'add',
                     'path': 'members',
                     'value': [{'value': user_id}]
                     }]}
        url = build_url(self.endpoints["host"] + "/Groups/" + group_id)
        return requests.patch(url, headers=self.headers(headers), data=json.dumps(data), auth=None)

    def remove_user_from_group(self, group_id, user_id, headers=None):
        data = {'schemas': ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
                'Operations': [
                    {
                        'op': 'remove',
                        'path': 'members[value eq "' + user_id + '"]'
                    }]}
        url = build_url(self.endpoints["host"] + "/Groups/" + group_id)
        return requests.patch(url, headers=self.headers(headers), data=json.dumps(data), auth=None)

    def get_schemas(self, headers=None):
        url = build_url(self.endpoints["host"] + "/Schemas/")
        return requests.get(url, headers=self.headers(headers), auth=None)

    def get_resource_types(self, headers=None):
        url = build_url(self.endpoints["host"] + "/ResourceTypes/")
        return requests.get(url, headers=self.headers(headers), auth=None)

    def get_service_provider_config(self, headers=None):
        url = build_url(self.endpoints["host"] + "/ServiceProviderConfig/")
        return requests.get(url, headers=self.headers(headers), auth=None)


class PropertiesServiceV2(Client):
    def get_capabilities(self, compartment=None, headers=None):
        if compartment is None:
            compartment = self.compartment_id
        url = self.endpoints["host"] + "/compartments/" + compartment + "/capabilities"
        return requests.get(url, headers=self.headers(headers), auth=self.auth)

    def get_servicelimits_groups(self, compartment=None, headers=None):
        if compartment is None:
            compartment = self.compartment_id
        url = build_url(
            self.endpoints["host"] + "/serviceLimitGroups",
            compartmentId=compartment)
        return requests.get(url, headers=self.headers(headers), auth=self.auth)

    def get_servicelimits(self, group, compartment=None, headers=None):
        if compartment is None:
            compartment = self.compartment_id
        url = build_url(
            self.endpoints["host"] + "/serviceLimits",
            compartmentId=compartment,
            group=group)
        return requests.get(url, headers=self.headers(headers), auth=self.auth)

    def get_property_overrides_for_tag(self, log, ocid, group, region=None, ad=None):
        properties_host = self.endpoints["host"]
        log.info("Getting property overrides for account: '%s' in group '%s' from '%s'." %
                 (ocid, group, properties_host))
        url = properties_host + "/properties/overrides/tag/" + ocid
        if group is not None:
            url += "?group=" + group
            if region is not None:
                url += "&region=" + region
                if ad is not None:
                    url += "&ad=" + ad

        response = requests.get(url, headers=None, auth=None)

        if response.status_code == 200:
            result = response.json()
            log.info("Successfully found '%s' overrides." % len(result))
            return result
        else:
            log.info("Received http status code: '%s'!" % response.status_code)
            return None

    def get_property_overrides(self, log, group, property, tag, region=None, ad=None):
        log.info("Getting property override")
        properties_host = self.endpoints["host"]
        url = properties_host + "/properties/overrides/group/" + group + "/property/" + property + "/tag/" + tag
        if region is not None:
            url += "?region=" + region
            if ad is not None:
                url += "&ad=" + ad

        return requests.get(url, headers=None, auth=None)

    def get_limit_overrides(self, log, group, limit, tag, region=None, ad=None):
        log.info("Getting limit overrides")
        properties_host = self.endpoints["host"]
        url = properties_host + "/limits/overrides/group/" + group + "/limit/" + limit + "/tag/" + tag
        if region is not None:
            url += "?region=" + region
            if ad is not None:
                url += "&ad=" + ad

        return requests.get(url, headers=None, auth=None)

    def get_work_request(self, log, work_request_id, is_valid):
        properties_host = self.endpoints["host"]
        log.info("Getting work request '%s' from '%s'." % (work_request_id, properties_host))
        url = properties_host + "/workRequests/" + work_request_id
        response = requests.get(url, headers=None, auth=None)
        log.info("Getting work request returned '%s'." % response.status_code)
        if is_valid:
            assert response.status_code == 200
        else:
            assert response.status_code == 404
        return response

    def create_property_override(self, log, group, property, value, tag, region="all", ad=None):
        if log is not None:
            log.info("Creating property override")
        properties_host = self.endpoints["host"]
        url = properties_host + "/properties/overrides"
        data = {
            "group": group,
            "name": property,
            "tag": tag,
            "region": region,
            "value": value,
            "ad": ad
        }

        # making request
        response = requests.post(url, data=json.dumps(data), headers=self.headers(None), auth=self.auth)

        assert response is not None

        return response

    def create_limit_override(self, log, group, limit, value, tag, region=None, ad=None):
        log.info("Creating limit override")
        properties_host = self.endpoints["host"]
        url = properties_host + "/limits/overrides"
        data = {
            "group": group,
            "name": limit,
            "tag": tag,
            "region": region,
            "value": value,
            "ad": ad
        }

        # making request
        response = requests.post(url, data=json.dumps(data), headers=self.headers(None), auth=self.auth)

        assert response is not None

        return response

    def create_limit_override_with_min_max_values(self, log, group, limit, min, max, tag, region=None, ad=None):
        log.info("Creating limit override")
        properties_host = self.endpoints["host"]
        url = properties_host + "/limits/overrides"
        data = {
            "group": group,
            "name": limit,
            "tag": tag,
            "region": region,
            "min": min,
            "max": max,
            "ad": ad
        }

        # making request
        response = requests.post(url, data=json.dumps(data), headers=self.headers(None), auth=self.auth)

        assert response is not None

        return response

    def update_property_override(self, log, group, property, value, tag, region="all", ad=None):
        log.info("Updating property override")
        properties_host = self.endpoints["host"]
        url = properties_host + "/properties/overrides"
        data = {
            "group": group,
            "name": property,
            "tag": tag,
            "region": region,
            "ad": ad,
            "value": value
        }

        # making request
        response = requests.put(url, data=json.dumps(data), headers=self.headers(None), auth=self.auth)

        assert response is not None

        return response

    def update_limit_override(self, log, group, limit, value, tag, region=None, ad=None):
        log.info("Updating limit override")
        properties_host = self.endpoints["host"]
        url = properties_host + "/limits/overrides"
        data = {
            "group": group,
            "name": limit,
            "tag": tag,
            "region": region,
            "ad": ad,
            "value": value
            # "template": "template_limit_default"
        }

        # making request
        response = requests.put(url, data=json.dumps(data), headers=self.headers(None), auth=self.auth)

        assert response is not None

        return response

    def delete_property_override(self, log, group, property, tag, region=None, ad=None):
        if log is not None:
            log.info("Deleting property override")
        properties_host = self.endpoints["host"]
        url = properties_host + "/properties/overrides/group/" + group + "/property/" + property + "/tag/" + tag
        if region is not None:
            url = url + "?region=" + region
            if ad is not None:
                url = url + "&ad=" + ad
        return requests.delete(url, auth=self.auth)

    def delete_limit_override(self, log, group, limit, tag, region=None, ad=None):
        log.info("Deleting limit override")
        properties_host = self.endpoints["host"]
        url = properties_host + "/limits/overrides/group/" + group + "/limit/" + limit + "/tag/" + tag
        if region is not None:
            url = url + "?region=" + region
            if ad is not None:
                url = url + "&ad=" + ad
        return requests.delete(url, auth=self.auth)

    def get_property_value(self, log, group, property, tag):
        log.info("Getting property override")
        properties_host = self.endpoints["host"]
        url = properties_host + "/properties/overrides/group/" + group + "/property/" + property + "/tag/" + tag
        return requests.get(url, headers=None, auth=None)

    def create_group(self, log, group):
        log.info("Creating group")
        properties_host = self.endpoints["host"]
        url = properties_host + "/groups"
        data = {
            "name": group,
            "authZCompartmentId": self._bound_compartment["id"]
        }
        return requests.post(url, json.dumps(data), headers=self.headers(None), auth=self.auth)

    def delete_group(self, log, group):
        log.info("Deleting group")
        properties_host = self.endpoints["host"]
        url = properties_host + "/groups/" + group
        return requests.delete(url, headers=None, auth=self.auth)

    def get_groups(self, log):
        log.info("Getting groups")
        properties_host = self.endpoints["host"]
        url = properties_host + "/groups"
        return requests.get(url, headers=None, auth=None)

    def delete_property(self, log, property, group, region=None):
        log.info("Deleting property")
        properties_host = self.endpoints["host"]
        url = properties_host + "/properties/group/" + group + "/property/" + property
        if region is not None:
            url = url + "?region=" + region
        return requests.delete(url, headers=None, auth=self.auth)

    def delete_limit(self, log, limit, group, region=None):
        log.info("Deleting limit")
        properties_host = self.endpoints["host"]
        url = properties_host + "/limits/group/" + group + "/limit/" + limit
        if region is not None:
            url = url + "?region=" + region
        return requests.delete(url, headers=None, auth=self.auth)

    def get_properties(self, log, group, region=None):
        log.info("Getting properties")
        properties_host = self.endpoints["host"]
        url = properties_host + "/properties/group/" + group
        if region is not None:
            url = url + "?region=" + region
        return requests.get(url, headers=None, auth=None)

    def get_limits(self, log, group, region=None):
        log.info("Getting limits")
        properties_host = self.endpoints["host"]
        url = properties_host + "/templates/template_limit_default/group/" + group + "/limits/"
        if region is not None:
            url = url + "?region=" + region
        return requests.get(url, headers=None, auth=None)

    def create_property(self, log, property, group, value):
        return self.create_regional_property(log, property, group, value, None)

    def create_regional_property(self, log, property, group, value, region):
        if log is not None:
            log.info("Creating property")
        properties_host = self.endpoints["host"]
        url = properties_host + "/properties"
        data = {
            "visibility": "TENANT",
            "label": "Property created by integ test",
            "type": "STRING",
            "group": group,
            "name": property,
            "value": value,
            "region": region
        }
        return requests.post(url, json.dumps(data), headers=self.headers(None), auth=self.auth)

    def create_limit(self, log, limit, group, value, region=None):
        log.info("Creating limit")
        properties_host = self.endpoints["host"]
        url = properties_host + "/limits"
        data = {
            "visibility": "TENANT",
            "label": "Limit created by integ test",
            "type": "STRING",
            "group": group,
            "name": limit,
            "value": value,
            "region": region
        }
        return requests.post(url, json.dumps(data), headers=self.headers(None), auth=self.auth)

    def set_limit_scope(self, log, limit, group, scope):
        log.info("Set limit scope")
        properties_host = self.endpoints["host"]
        url = properties_host + "/templates/scopes/"
        data = {
            "group": group,
            "name": limit,
            "scope": scope
        }
        return requests.put(url, json.dumps(data), headers=self.headers(None), auth=self.auth)

    def set_limit_visibility(self, log, limit, group, visibility):
        log.info("Set limit scope")
        properties_host = self.endpoints["host"]
        url = properties_host + "/templates/visibilities/"
        data = {
            "group": group,
            "name": limit,
            "visibility": visibility
        }
        return requests.put(url, json.dumps(data), headers=self.headers(None), auth=self.auth)

    def set_limit_label(self, log, limit, group, label):
        log.info("Set limit scope")
        properties_host = self.endpoints["host"]
        url = properties_host + "/templates/labels/"
        data = {
            "group": group,
            "name": limit,
            "label": label
        }
        return requests.put(url, json.dumps(data), headers=self.headers(None), auth=self.auth)

    def update_property(self, log, property, group, value, region=None):
        if log is not None:
            log.info("Update property")
        properties_host = self.endpoints["host"]
        url = properties_host + "/properties"
        data = {
            "group": group,
            "name": property,
            "value": value,
            "region": region
        }
        return requests.put(url, json.dumps(data), headers=self.headers(None), auth=self.auth)

    def update_limit(self, log, limit, group, value, region=None):
        log.info("Update limit")
        properties_host = self.endpoints["host"]
        url = properties_host + "/templates/template_limit_default/limit"
        data = {
            "group": group,
            "name": limit,
            "value": value,
            "region": region
        }
        return requests.put(url, json.dumps(data), headers=self.headers(None), auth=self.auth)

    def get_whitelist_services(self, log):
        log.info("Getting console whitelist services")
        properties_host = self.endpoints["host"]
        url = properties_host + "/consolewhitelists/services"
        return requests.get(url, headers=self.headers(None), auth=None)

    def create_whitelist_service(self, log, name):
        log.info("Create whitelist service")
        properties_host = self.endpoints["host"]
        url = properties_host + "/consolewhitelists"
        data = {
            "service": name,
            "value": "{}",
            "label": "test whitelist"
        }
        return requests.post(url, json.dumps(data), headers=self.headers(None), auth=self.auth)

    def delete_whitelist_service(self, log, service, region=None):
        log.info("Deleting whitelist service")
        properties_host = self.endpoints["host"]
        url = properties_host + "/consolewhitelists/service/" + service
        if region is not None:
            url = url + "?=" + region
        return requests.delete(url, headers=None, auth=self.auth)

    def update_whitelist(self, log, service, value, region=None):
        log.info("Update whitelist")
        properties_host = self.endpoints["host"]
        url = properties_host + "/consolewhitelists"
        data = {
            "service": service,
            "value": json.dumps(value),
            "label": "test whitelist"
        }
        if region is not None:
            url = url + "?=" + region
        return requests.put(url, json.dumps(data), headers=self.headers(None), auth=self.auth)

    def get_whitelist_service(self, log, service, region=None):
        log.info("Getting console whitelist service")
        properties_host = self.endpoints["host"]
        url = properties_host + "/consolewhitelists/service/" + service
        if region is not None:
            url = url + "?=" + region
        return requests.get(url, headers=self.headers(None), auth=None)


class Console(Client):
    def __init__(self, endpoints, oauth_redirect, keys, compartment=None, tenancy=None, key=None):
        self.endpoints = endpoints
        self.decryption_key = credentials.public_token
        # This needs to resolve to an endpoint that will accept and respond
        # even if that response is always a 400.  PhantomJS will not
        # follow a redirect if the redirect target won't open a connection.

        # See REGION.STAGE config files, "oauth-redirect-url"
        self.oauth_redirect = oauth_redirect
        self.keys = keys
        self._bound_compartment = compartment
        self._bound_tenancy = tenancy
        self._bound_key = key
        self._bound_cross_tenancy_intent = None
        self._bound_cross_tenancy_intent_as_signed_header = True
        self._bound_obo_call = False
        self.verify = True

    @property
    def params(self):
        return {
            "nonce": str(uuid.uuid4()),
            "state": b64(fuzz.string()),
            # This needs to resolve to an endpoint that will accept and respond
            # even if that response is always a 400.  PhantomJS will not
            # follow a redirect if the redirect target won't open a connection.
            "redirect_uri": self.oauth_redirect,
            "response_type": "id_token token",
            "client_id": "iaas_console",
            "scope": "openid"
        }

    @property
    def openid_params(self):
        return {
            "nonce": str(uuid.uuid4()),
            "state": b64(fuzz.string()),
            # This needs to resolve to an endpoint that will accept and respond
            # even if that response is always a 400.  PhantomJS will not
            # follow a redirect if the redirect target won't open a connection.
            "client_id": "oidc_client",
            "scope": "openid"
        }

    @property
    def link_support_account_params(self):
        return {
            "nonce": str(uuid.uuid4()),
            "support_provider": "MOS"
        }

    def link_support_account_header(self, other_headers):
        return self.headers(other_headers)

    def parameterize(self, url, **params):
        params = {**self.params, **params}
        return url + "?" + urllib.parse.unquote(urllib.parse.urlencode(params))

    def login_url(self, **params):
        url = self.endpoints["host"] + "/oauth2/authorize"
        return self.parameterize(url, **params)

    def logout_url(self, **params):
        url = self.endpoints["host"] + "/logout"
        return self.parameterize(url, **params)

    def change_password_url(self, **params):
        url = self.endpoints["host"] + "/password/change"
        return self.parameterize(url, **params)

    def mfa_verify_url(self, **params):
        url = self.endpoints["host"] + "/mfa/verify"
        return self.parameterize(url, **params)

    def generate_auth_code(self, params):
        url = self.endpoints["host"] + "/oauth2/auth_code"
        url_with_params = url + "?" + urllib.parse.unquote(urllib.parse.urlencode(params))
        return requests.post(url_with_params, auth=self.auth, headers=self.headers(None), verify=self.verify)

    def generate_tokens(self, params):
        url = self.endpoints["host"] + "/oauth2/token"
        url_with_params = url + "?" + urllib.parse.unquote(urllib.parse.urlencode(params))
        return requests.post(url_with_params, auth=self.auth, headers=self.headers(None), verify=self.verify)

    def mfa_verify_url_slave_region(self, **params):
        url = self.endpoints["host-slave-region"] + "/mfa/verify"
        return self.parameterize(url, **params)

    def saml_request_to_link_support_account(self, formParam, headers):
        url = self.endpoints["host"] + "/supportAccount/samlRequest"
        print("link support account saml request:%s" % url)
        return requests.post(url, data=formParam, headers=headers, verify=False)

    @property
    def forgot_password_url(self):
        return self.endpoints["host"] + "/password/forgot"

    @contextlib.contextmanager
    def clickjack_for(self, url):
        """
        Generate an html file to test clickjack protection.
        Returns the filename, which can be loaded with the prefix file://

        Usage
        -----

            url = console.change_password_url
            with console.clickjack_for(url) as filename:
                browser.switch_to.frame("clickjack-frame")
                # Verify elements can't be found here

        """
        template = """
        <html><head><title>Clickjack test page</title></head>
        <body><iframe
                id="clickjack-frame"
                src="{url}"
                style="width:100%;height:90%">
        </iframe></body>
        </html>
        """
        with tempfile.NamedTemporaryFile(mode="w+", suffix=".html") as payload:
            payload.write(template.format(url=url))
            payload.flush()
            yield payload.name