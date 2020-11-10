from Crypto.PublicKey import RSA
from . import Container
from . import fuzz, credentials
from onetimepass import get_totp

MAXIMUM_PASSWORD_LENGTH = 20
MINIMUM_PASSWORD_LENGTH = 12

NAME_BLACKLIST = [
    "ALLOW",
    "COMPARTMENT",
    "DENY",
    "DESCRIPTION",
    "GROUP",
    "ID",
    "IN",
    "NAME",
    "ON",
    "POLICY",
    "ROLE",
    "TENANCY",
    "TO",
    "USER",
    "USERNAME",
    "WHERE",
    "WITH"
]


def _name(charsets="a-z A-Z 0-9"):
    """
    A valid name:
    1) starts with an alphabetic character
    2) is between 1 and 100 characters
    3) doesn't match NAME_BLACKLIST
    """
    while True:
        name = fuzz.char("a-z A-Z") + fuzz.string(charsets=charsets)
        if name.upper() not in NAME_BLACKLIST:
            return name


def _password(length=MAXIMUM_PASSWORD_LENGTH):
    if length < MINIMUM_PASSWORD_LENGTH or length > MAXIMUM_PASSWORD_LENGTH:
        raise ValueError("Password must be between {} and {} (was {})".format(
            MINIMUM_PASSWORD_LENGTH, MAXIMUM_PASSWORD_LENGTH, length))

    rules = {
        # At least one punctuation, lowercase, uppercase, digit
        "!": 1, "a-z": 1, "A-Z": 1, "0-9": 1,
        # Fill the rest (20 - 4) with any valid character
        "a-z A-Z 0-9 !": length - 4
    }
    return fuzz.string_from_constraints(**rules)


def _key(length=2048, **additional):
    # If public or private is missing we can't proceed - either a pair is provided, or none at all
    provided_keys = 0
    if "private" in additional:
        provided_keys += 1
    if "public" in additional:
        provided_keys += 1

    if provided_keys == 1:
        raise RuntimeError(
            "Can't provide (private XOR public), either provide both or neither: {}".format(additional))

    if not provided_keys:
        key = RSA.generate(length)
        return {
            **additional,
            "private": key.exportKey().decode("utf-8"),
            "public": key.publickey().exportKey().decode("utf-8")
        }
    return dict(additional)


def _entity(**additional):
    """Most entities require a leading alphabetic character"""
    return {
        "name": valid.name(),
        "description": fuzz.description_string(),
        **additional
    }


def _user(**additional):
    entity = _entity(**additional)
    entity["email"] = fuzz.string() + "@domain.com"
    return entity


def _entity_lowercase(**additional):
    """Most entities require a leading alphabetic character"""
    return {
        "name": valid.name().lower(),
        "description": fuzz.description_string(),
        **additional
    }


def _tag_definition(tag_namespace, **additional):
    entity = _entity_lowercase(**additional)
    entity["ownerId"] = tag_namespace["id"]
    return entity


def _tag_default(tag_definition, **additional):
    return {
        "compartmentId": tag_definition["compartmentId"],
        "ownerId": tag_definition["id"],
        "value": valid.name().lower(),
        **additional
    }


def _tag_default_with_value(tag_definition, value, **additional):
    return {
        "compartmentId": tag_definition["compartmentId"],
        "ownerId": tag_definition["id"],
        "value": value,
        **additional
    }


def _required_tag(tag_definition, **additional):
    return {
        "compartmentId": tag_definition["compartmentId"],
        "ownerId": tag_definition["id"],
        "value": valid.name().lower(),
        "isRequired": True,
        **additional
    }


def _tag_validator(type, **additional):
    """type is only required field"""
    additional.setdefault("values", [])
    return {
        "validatorType": type,
        **additional
    }


def _default_tag_validator():
    return {
        "validatorType": "DEFAULT"
    }


def _tenancy(**additional):
    """name must be <= 15 characters and only contain lower case letters and numbers"""
    additional.setdefault("adminUserName", valid.name())
    entity = _entity(**additional)
    entity["name"] = entity["name"][:15].lower()
    return entity


def _system_policy_tenancy(**additional):
    """name must be <= 15 characters and only contain lower case letters and numbers"""
    additional.setdefault("adminUserName", valid.name())
    entity = _entity(**additional)
    entity["name"] = "oci_system_policy".lower()
    return entity


def _system_policy_managed_compartment_tenancy(**additional):
    """name must be <= 15 characters and only contain lower case letters and numbers"""
    additional.setdefault("adminUserName", valid.name())
    entity = _entity(**additional)
    entity["name"] = "oci_mgd_compt_system_policy".lower()
    return entity


def _swift(**additional):
    """swift passwords don't have a name"""
    return {
        "description": fuzz.description_string(),
        **additional
    }


def _authtoken(**additional):
    """auth tokens don't have a name"""
    return {
        "description": fuzz.description_string(),
        **additional
    }


def _mfatotptoken(totp_token, **additional):
    return {
        "totpToken": totp_token,
        **additional
    }


def _vcn(**additional):
    return {
        "vcnId": "ocid1.vcn",
        **additional
    }


def _secretkey(**additional):
    return {
        "displayName": valid.name(),
        **additional
    }


def _smtp(**additional):
    """smtp credentials don't have a name"""
    return {
        "description": fuzz.description_string(),
        **additional
    }


def _oauth2_client_cred(**additional):
    return {
        "name": valid.name(),
        "description": fuzz.description_string(),
        "scopes": [{"audience": "aud1", "scope": "abc"}],
        **additional
    }


def _account(**additional):
    user_name = valid.name()
    return {
        "accountName": valid.name()[:15].lower(),
        "adminEmail": user_name[:10] + "@oracle.com",
        "adminUsername": user_name,
        "adminPassword": _password(),
        "adminFirstName": user_name + "FirstName",
        "adminLastName": user_name + "LastName",
        **additional
    }


def _saml2_identity_provider(**additional):
    """return saml2 identity provider"""
    additional.setdefault("metadata", credentials.saml_idp_metadata_1)
    additional.setdefault("productType", "IDCS")
    additional.setdefault("metadataUrl", "http://metadata.url")
    entity = _entity(**additional)
    entity["name"] = valid.name()
    entity["description"] = fuzz.description_string()
    entity["protocol"] = "SAML2"
    return entity


def generate_totp_token(seed, token_length=6):
    mfa_totp_token = str(get_totp(seed, True, token_length=token_length), 'utf-8')
    assert len(mfa_totp_token) == token_length
    return mfa_totp_token


def _service(**additional):
    return {
        "serviceName": valid.name(),
        **additional
    }


# Fake out modules for cleaner imports and grouping
valid = Container(password=_password, key=_key, name=_name, swift=_swift, authtoken=_authtoken, secretkey=_secretkey,
                  smtp=_smtp, oauth2_client_cred=_oauth2_client_cred, mfatotptoken=_mfatotptoken)
entities = Container(user=_user,
                     tag_namespace=_entity_lowercase,
                     tag_definition=_tag_definition,
                     tag_default=_tag_default,
                     tag_default_with_value=_tag_default_with_value,
                     required_tag=_required_tag,
                     tag_validator=_tag_validator,
                     default_tag_validator=_default_tag_validator,
                     tag_rule=_entity,
                     group=_entity,
                     dynamic_group=_entity,
                     idp_group=_entity,
                     compartment=_entity,
                     policy=_entity,
                     tenancy=_tenancy,
                     system_policy_tenancy=_system_policy_tenancy,
                     system_policy_managed_compartment_tenancy=_system_policy_managed_compartment_tenancy,
                     account=_account,
                     saml2_identity_provider=_saml2_identity_provider,
                     service=_service)