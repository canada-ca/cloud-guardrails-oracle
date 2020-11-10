# Ludovic Dessemon, Enterprise Cloud Strategist (Oracle Canada)
# July, 2020
# Python client for Oracle Cloud Infrastructure
from utils import myprint
from modules.requests import http_retry, Status

import xml.etree.ElementTree as ET
import oci
import time
import requests

import base64
import email.utils
import hashlib

# pip install httpsig_cffi requests six
import httpsig_cffi.sign
import requests
import six
import warnings
warnings.filterwarnings("default", category=DeprecationWarning)


sentinel = object()

class SignedRequestAuth(requests.auth.AuthBase):
    """A requests auth instance that can be reused across requests"""
    generic_headers = [
        "date",
        "(request-target)",
        "host"
    ]
    body_headers = [
        "content-length",
        "content-type",
        "x-content-sha256",
    ]
    required_headers = {
        "get": generic_headers,
        "head": generic_headers,
        "delete": generic_headers,
        "put": generic_headers + body_headers,
        "post": generic_headers + body_headers
    }

    def __init__(self, key_id, private_key):
        # Build a httpsig_cffi.requests_auth.HTTPSignatureAuth for each
        # HTTP method's required headers
        self.signers = {}
        for method, headers in six.iteritems(self.required_headers):
            signer = httpsig_cffi.sign.HeaderSigner(
                key_id=key_id, secret=private_key,
                algorithm="rsa-sha256", headers=headers[:])
            use_host = "host" in headers
            self.signers[method] = (signer, use_host)

    def inject_missing_headers(self, request, sign_body):
        # Inject date, content-type, and host if missing
        request.headers.setdefault(
            "date", email.utils.formatdate(usegmt=True))
        request.headers.setdefault("content-type", "application/json")
        request.headers.setdefault(
            "host", six.moves.urllib.parse.urlparse(request.url).netloc)

        # Requests with a body need to send content-type,
        # content-length, and x-content-sha256
        if sign_body:
            body = request.body or ""
            if "x-content-sha256" not in request.headers:
                m = hashlib.sha256(body.encode("utf-8"))
                base64digest = base64.b64encode(m.digest())
                base64string = base64digest.decode("utf-8")
                request.headers["x-content-sha256"] = base64string
            request.headers.setdefault("content-length", len(body))

    def __call__(self, request):
        verb = request.method.lower()
        # nothing to sign for options
        if verb == "options":
            return request
        signer, use_host = self.signers.get(verb, (None, None))
        if signer is None:
            raise ValueError(
                "Don't know how to sign request verb {}".format(verb))

        # Inject body headers for put/post requests, date for all requests
        sign_body = verb in ["put", "post"]
        self.inject_missing_headers(request, sign_body=sign_body)

        if use_host:
            host = six.moves.urllib.parse.urlparse(request.url).netloc
        else:
            host = None

        signed_headers = signer.sign(
            request.headers, host=host,
            method=request.method, path=request.path_url)
        request.headers.update(signed_headers)
        return request

class OciClient(object):
    """Client abstraction for all interactions with OCI identity"""

    def __init__(self, settings):
        """constructor for OciClient"""
        self.settings = settings
        self.tenant = settings.sp_tenant
        # -----BEGIN RSA PRIVATE KEY-----
        # ...
        # -----END RSA PRIVATE KEY-----
        with open(settings.private_key_file) as f:
            private_key = f.read().strip()

        # This is the keyId for a key uploaded through the console
        api_key = "/".join([
            settings.sp_tenant['config']['tenancy'],
            settings.sp_tenant['config']['user'],
            settings.sp_tenant['config']['fingerprint']
        ])

        self.auth = SignedRequestAuth(api_key, private_key)

        self.headers = {
            "content-type": "application/json",
            "date": email.utils.formatdate(usegmt=True),
            # Uncomment to use a fixed date
            # "date": "Thu, 05 Jan 2014 21:31:40 GMT"
        }

    def b64(string):
        as_bytes = string.encode("utf-8")
        b64_bytes = base64.b64encode(as_bytes)
        return b64_bytes.decode("utf-8")    


    def get_federation_metadata(self, tenant_id):
        """retrieves the federation metadata for this tenancy"""
        return self.retrieve_oci_metadata(tenant_id)

    def find_identity_providers(self, compartment_id, idp_name):
        """retrieves the identity providers from the tenancy"""
        response = self.tenant["ociIdentityClient"].list_identity_providers(protocol="SAML2", compartment_id=compartment_id)
        for idp in response.data:
            if idp.name == idp_name:
                return idp
        return None

    def get_identity_providers(self, compartment_id):
        """retrieves the identity providers from the tenancy"""
        response = self.tenant["ociIdentityClient"].list_identity_providers(protocol="SAML2", compartment_id=compartment_id)

        return response.data

    def add_saml2_identity_provider(self, provider):
        return self.tenant["ociIdentityClient"].create_identity_provider(provider)

    def create_identity_provider(self, name, idp_metadata, metadata_url, app_id, client_id, client_secret, compartment_id):
        """creates a new identity provider in bound tenancy"""
        idp = {"metadata": idp_metadata,
               "productType": "IDCS",
               "metadataUrl": metadata_url,
               "name": name,
               "description": "IDCS in pool 0",
               "protocol": "SAML2",
               "compartmentId": compartment_id,
               "freeformAttributes": {'federationVersion': '2', 'externalAppId': app_id,
                                                     'externalClientId': client_id,
                                                     'externalClientSecret': client_secret}
        }

        with http_retry(Status.OK):
            response = self.add_saml2_identity_provider(idp)
        idp = response.data
        myprint("Identity Provider %s" % name, "Created") 
        return idp

    def delete_identity_provider(self, idp_id, compartment_id, idp_name):
        """Deletes the specified identity provider"""
        response = self.tenant["ociIdentityClient"].delete_identity_provider(identity_provider_id=idp_id)
        while self.find_identity_providers(compartment_id, idp_name) != None:
            time.sleep(5)
        myprint("Identity Provider %s" % idp_name, "Deleted")
        return None

    def reset_scim_client(self, idp):
        with http_retry(Status.OK):
            credentials_response = self.tenant["ociIdentityClient"].reset_idp_scim_client(idp.id)
            return credentials_response.data.client_id, credentials_response.data.client_secret

    def get_user(self, user_name, compartment_id):
        """Retrieve user with given name"""
        with http_retry(Status.OK):
            response = self.tenant["ociIdentityClient"].list_users(compartment_id=compartment_id)
            users = response.data
            for user in users:
                if user.name == user_name:
                    return user
        return None

    def find_group(self, group_name, compartment_id):
        """Searches for group with given name in OCI"""
        _groups = self.tenant["ociIdentityClient"].list_groups(compartment_id=compartment_id)
        for _group in _groups.data:
            if _group.name == group_name:
                return _group
        return None

    def add_group(self, group, compartment_id):
        response = self.tenant["ociIdentityClient"].create_group(oci.identity.models.CreateGroupDetails(compartment_id=compartment_id, description=group['description'], name=group['name']))
        return response.data

    def create_group(self, group_name, compartment_id):
        _group = self.find_group(group_name, compartment_id)
        if _group == None:
            with http_retry(Status.OK):
                response = self.add_group({'name': group_name, 'description': group_name}, compartment_id)
                myprint("(OCI) Group %s" % group_name,"Created")
                return response
        else:
            myprint("(OCI) Group %s" % group_name,"Already Exists")
            return _group

    def delete_group_by_name(self, group_name, compartment_id):
        _group = self.find_group(group_name, compartment_id)
        if _group != None:
            response = self.delete_group(_group.id)
            while self.find_group(group_name, compartment_id) != None:
                time.sleep(5)
            myprint("(OCI) Group %s" % group_name,"Deleted")
            return None 
        else:
            myprint("(OCI) Group %s" % group_name,"Not Found")

    def delete_group(self, group_id):
        """Deletes the group from OCI tenancy"""
        response = self.tenant["ociIdentityClient"].delete_group(group_id)
        return response

    def add_saml2_idp_group_mapping(self, idp, idp_group_name, oci_group):
        response = self.tenant["ociIdentityClient"].create_idp_group_mapping(oci.identity.models.CreateIdpGroupMappingDetails(group_id=oci_group.id, idp_group_name=idp_group_name), identity_provider_id=idp.id)
        return response.data

    def find_group_mapping(self, idp, idp_group_name, oci_group):
        response = self.tenant["ociIdentityClient"].list_idp_group_mappings(identity_provider_id=idp.id)
        for _map in response.data:
            if _map.idp_group_name == idp_group_name and _map.group_id == oci_group.id:
                return _map
        return None

    def create_group_mapping(self, idp, idp_group_name, oci_group):
        """Create a group mapping between an IdP group and an OCI group"""
        response = self.find_group_mapping(idp, idp_group_name, oci_group)
        if response == None:
            with http_retry(Status.OK):
                self.add_saml2_idp_group_mapping(idp, idp_group_name, oci_group)
                myprint("Group Mapping IdP <-> SP","Created")
        else:
            myprint("Group Mapping IdP <-> SP","Already Exists")

    def delete_group_mapping(self, idp, idp_group_name, oci_group):
        _mappings = self.tenant["ociIdentityClient"].list_idp_group_mappings(identity_provider_id=idp.id)
        for _mapping in _mappings:
            if _mapping.idp_group_name == idp_group_name and group_id == oci_group:
                response = self.tenant["ociIdentityClient"].delete_idp_group_mapping(identity_provider_id=idp.id, mapping_id=_mapping.id)
                myprint("Group Mapping %s %s" % (idp_group_name, oci_group),"Deleted")

    def get_sp_metadata(self, tenant_id):
        url = self.settings.oci_metadata_endpoint + "/saml/" + tenant_id + "/metadata.xml"
        #return requests.get(url, auth=self.auth, headers=self.headers).content.decode('utf-8')            
        return requests.get(url).content.decode('utf-8')            

    def retrieve_oci_metadata(self, tenant_id):
        """Retrieves federation meta data document from data plane and extracts certificate and entity id"""
        sp_metadata = self.get_sp_metadata(tenant_id)
        metadata_doc = ET.fromstring(sp_metadata)
        namespaces = {'md': 'urn:oasis:names:tc:SAML:2.0:metadata',
                      'ds': 'http://www.w3.org/2000/09/xmldsig#'}
        for e in metadata_doc.findall('md:SPSSODescriptor/md:KeyDescriptor/ds:KeyInfo/ds:X509Data/ds:X509Certificate',
                                      namespaces=namespaces):
            sp_certificate = e.text
        assert sp_certificate

        for e in metadata_doc.findall('.', namespaces=namespaces):
            entity_id = e.attrib.get('entityID')
        assert entity_id

        return entity_id, sp_certificate

    def find_policy(self, policy_name, tenant_id):
        response = self.tenant["ociIdentityClient"].list_policies(compartment_id=tenant_id)
        for _policy in response.data:
            if _policy.name == policy_name:
                return _policy
        return None        

    def list_policies(self, compartment_id):
        response = self.tenant["ociIdentityClient"].list_policies(compartment_id=compartment_id)
        return response

    def list_api_keys(self, user_id):
        response = self.tenant["ociIdentityClient"].list_api_keys(user_id=user_id)
        return response
    
    def create_policy(self, policy_name, policy_statements, tenant_id):
        _policy = self.find_policy(policy_name, tenant_id)
        if _policy == None:
            policyDetail = oci.identity.models.CreatePolicyDetails(compartment_id=tenant_id, description=policy_name, name=policy_name, statements=policy_statements)
            result = self.tenant["ociIdentityClient"].create_policy(policyDetail)
            if result.data.lifecycle_state and result.data.lifecycle_state == 'ACTIVE':
                myprint("Policy %s" % policy_name,"Created")
        else:
            myprint("Policy %s" % policy_name,"Already Exists")
            return _policy

    def delete_policy_by_name(self, policy_name, tenant_id):
        _policy = self.find_policy(policy_name, tenant_id)    
        if _policy != None:
            result = self.tenant["ociIdentityClient"].delete_policy(policy_id=_policy.id)
            myprint("Policy %s" % policy_name,"Deleted")
            return True
        else:
            myprint("Policy %s" % policy_name,"Not Found")
            return False

    def find_marketplace_listings(self):
        return self.tenant["ociMarketplaceClient"].list_listings()