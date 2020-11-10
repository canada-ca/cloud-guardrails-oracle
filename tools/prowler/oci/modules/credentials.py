import os
import pathlib
import time

from OpenSSL import crypto
from OpenSSL.crypto import load_certificate

from . import shapes
from .requests import http_retry, Status

import jwt

HERE = os.path.abspath(os.path.dirname(__file__))


def path(filename):
    return pathlib.Path(HERE) / "../keys" / filename


"""Saved from https://confluence.oraclecorp.com/confluence/x/OMqUBQ"""
with path("priv.pem").open("r") as f:
    private_key = f.read().strip()

"""Saved from https://confluence.oraclecorp.com/confluence/x/OMqUBQ"""
with path("pub.pem").open("r") as f:
    public_key = f.read().strip()

"""https://jira.oci.oraclecorp.com/browse/ID-7322"""
with path("limits_private.pem").open("r") as f:
    limits_private_key = f.read().strip()

"""https://jira.oci.oraclecorp.com/browse/ID-7322"""
with path("limits_public.pem").open("r") as f:
    limits_public_key = f.read().strip()

"""jwk format for public_key"""
with path("jwk").open("r") as f:
    public_jwk = f.read().strip()

"""For token-based auth (browser)"""
with path("priv_token.pem").open("r") as f:
    private_token = f.read().strip()

"""For token-based auth (browser)"""
with path("pub_token.pem").open("r") as f:
    public_token = f.read().strip()

"""Public JWT (base64 encoded)"""
with path("pub.jwt").open("r") as f:
    public_jwt = "".join(line.strip() for line in f.readlines())

key = {
    "private": private_key,
    "public": public_key
}

limits_key = {
    "private": limits_private_key,
    "public": limits_public_key
}

""" This is the dp signing key in dev and r0"""
with path("pub_token.pem").open("r") as f:
    dp_public = f.read().strip()

""" This is the dp signing key in dev and r0"""
with path("private.pem").open("r") as f:
    dp_private = f.read().strip()

"""New Public JWT (base64 encoded) for refresh"""
with path("new_pub.jwt").open("r") as f:
    new_public_jwt = "".join(line.strip() for line in f.readlines())

"""New Private key for refresh"""
with path("new_priv.pem").open("r") as f:
    new_private_key = f.read().strip()

"""New Public Key for refresh"""
with path("new_pub.pem").open("r") as f:
    new_public_key = f.read().strip()

with path("service_cert.pem").open("r") as f:
    service_cert = f.read().strip()

with path("service_cert_int.pem").open("r") as f:
    service_cert_int = f.read().strip()

with path("service_root_cert.pem").open("r") as f:
    service_root_cert = f.read().strip()

with path("service_cert_int_key.pem").open("r") as f:
    service_cert_int_key = f.read().strip()

with path("instance_cert.pem").open("r") as f:
    instance_cert = f.read().strip()

with path("instance_cert_key.pem").open("r") as f:
    instance_cert_key = f.read().strip()

with path("instance_cert_tags.pem").open("r") as f:
    instance_cert_tag = f.read().strip()

with path("instance_cert_tags_key.pem").open("r") as f:
    instance_cert_tag_key = f.read().strip()

with path("instance_cert_2.pem").open("r") as f:
    instance_cert_2 = f.read().strip()

# Instance cert 3 has the same private key as instance_cert
with path("instance_cert_3.pem").open("r") as f:
    instance_cert_3 = f.read().strip()

with path("instance_cert_key_2.pem").open("r") as f:
    instance_cert_key_2 = f.read().strip()

with path("service_cert_key.pem").open("r") as f:
    service_cert_key = f.read().strip()

# cert of the resource-providing service for resource principals
with path("resource_service_cert.pem").open("r") as f:
    resource_service_cert = f.read().strip()

# private key of the resource-providing service for resource principals
with path("resource_service_key.pem").open("r") as f:
    resource_service_cert_key = f.read().strip()

with path("saml_idp_metadata_1").open("r") as f:
    saml_idp_metadata_1 = f.read().strip()

with path("saml_idp_metadata_2").open("r") as f:
    saml_idp_metadata_2 = f.read().strip()

with path("saml_adfs_metadata_1").open("r") as f:
    saml_adfs_metadata_1 = f.read().strip()


def extract_fingerprint(key_id):
    """Last portion of the key_id after /"""
    return key_id.split("/")[-1]


def sanitize(string):
    assert string
    return string \
        .replace('-----BEGIN CERTIFICATE-----', '') \
        .replace('-----END CERTIFICATE-----', '') \
        .replace('-----BEGIN PUBLIC KEY-----', '') \
        .replace('-----END PUBLIC KEY-----', '') \
        .replace('\n', '')


def to_naked_jwt(input_jwt):
    if input_jwt.startswith('ST$'):
        return input_jwt[3:]
    return input_jwt


class Keys:
    def __init__(self):
        self.keys = {}

    def __getitem__(self, key_id):
        """always lookup by fingerprint"""
        fingerprint = extract_fingerprint(key_id)
        return self.keys[fingerprint]

    def __contains__(self, key_id):
        """always lookup by fingerprint"""
        fingerprint = extract_fingerprint(key_id)
        return fingerprint in self.keys

    def register(self, key):
        if "fingerprint" not in key:
            key["fingerprint"] = extract_fingerprint(key["keyId"])
        self.keys[key["fingerprint"]] = key


def get_service_session_key_with_DGID(tenant_id, keys, data_plane,
                                      certificate=None, certificate_key=None,
                                      purpose_of_using_instance_principal_cert=None,
                                      retryCount=10,
                                      expected_response_code=Status.OK):
    # generate a token and verify that there is a dynamic group id in the token
    if not certificate:
        certificate = service_cert

    if not certificate_key:
        certificate_key = service_cert_key

    int_certificate = sanitize(service_cert_int)
    session_key_pair = shapes.valid.key(2048)
    session_private_key = session_key_pair['private']
    session_public_key = sanitize(session_key_pair['public'])

    key = shapes.valid.key(
        private=certificate_key,
        public=sanitize(certificate),
        keyId=tenant_id + '/fed-x509/' + fingerprint(certificate))
    keys.register(key)
    data_plane.bind(key=key)

    # Get a security token from the STS to make future s2s calls
    trial = 0
    dynamicGroupIDValue = ''
    while trial < retryCount:
        with http_retry(expected_response_code):
            federation_response = data_plane.get_token_for_x509_certificate(
                certificate=sanitize(certificate),
                intermediates=[int_certificate],
                public_key=session_public_key,
                purpose_of_using_instance_principal_cert=purpose_of_using_instance_principal_cert)

            if expected_response_code != Status.OK:
                return None

            federated_token = federation_response.json()['token']
            assert federated_token
            if retryCount > 1:
                jwt_token = jwt.decode(jwt=federated_token, verify=False)
                # for service-principal tokens, we don't need further check wrt dynamic-groups.
                if jwt_token['ptype'] == 'service':
                    dynamicGroupIDValue = 'not required for service-principal'
                    break
                dg_claim_type = 'opc-tag'
                if dg_claim_type in jwt_token and jwt_token[dg_claim_type] != '':
                    dynamicGroupIDValue = jwt_token[dg_claim_type]
                    break
                else:
                    time.sleep(1)  # sleeping for 1 second before trying again
        trial += 1

    if retryCount > 1:
        assert dynamicGroupIDValue != ''

    session_key = shapes.valid.key(
        private=session_private_key,
        public=session_public_key,
        keyId='ST$' + federated_token)

    return session_key


def get_service_session_key(tenant_id, keys, data_plane, certificate=None, certificate_key=None,
                            purpose_of_using_instance_principal_cert=None):
    return get_service_session_key_with_DGID(tenant_id,
                                             keys,
                                             data_plane,
                                             certificate,
                                             certificate_key,
                                             retryCount=1,
                                             purpose_of_using_instance_principal_cert=purpose_of_using_instance_principal_cert)


def fingerprint(cert_string):
    cert = load_certificate(crypto.FILETYPE_PEM, cert_string)
    return cert.digest('sha1').decode('utf-8')


def compute_fingerprint_of_public_key(public_key_base64):
    import base64
    import hashlib
    key_bytes = base64.b64decode(sanitize(public_key_base64))
    fingerprint_bytes = hashlib.md5(key_bytes)
    fingerprint_hex = fingerprint_bytes.hexdigest()
    return ':'.join(a + b for a, b in zip(fingerprint_hex[::2], fingerprint_hex[1::2]))


def create_self_signed_cert():
    return create_signed_cert()


def create_signed_cert(ca_cert=None, ca_key=None, ou=None):
    # create a key pair
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)

    # create a self-signed cert
    cert = crypto.X509()
    cert.get_subject().C = "US"
    cert.get_subject().O = "Compute"  # noqa
    if ou:
        # This thing does not support adding multiple OU
        # And it DOES have a size limit
        cert.get_subject().OU = ou
    else:
        cert.get_subject().OU = "Admin"
    cert.get_subject().CN = "CN=fake"
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)

    if ca_cert and ca_key:
        cert.set_issuer(ca_cert.get_subject())
        cert.sign(ca_key, "sha1")
    else:
        cert.sign(k, 'sha1')

    private_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, k)
    certificate = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
    return certificate.decode('utf-8'), private_key.decode('utf-8')