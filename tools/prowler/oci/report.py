from __future__ import print_function
import oci
import os
import time
import requests 
import getpass
import json
import pandas as pd
from jsonpath_ng import jsonpath, parse
import jsonpath_rw_ext
import sys
from base64 import b64encode
import xml.dom.minidom
from idcs_client import IdcsClient
from oci_client import OciClient
from settings import Settings
from utils import myprint



_config = oci.config.from_file(os.environ['OCI_CONFIG'], os.environ['OCI_PROFILE'])

ociIdentityClient = oci.identity.IdentityClient(_config)

_settings = {
    "client_id": os.environ['IDCS_CLIENT_ID'],
    "client_secret": os.environ['IDCS_CLIENT_SECRET'],
    "base_url": os.environ['IDCS_BASE_URL'],
}
#print(_settings)
_idcsClient = IdcsClient(json.dumps(_settings))

_report = []

_users = ociIdentityClient.list_users(compartment_id=_config['tenancy'])
for _user in _users.data:
    _api_keys = ociIdentityClient.list_api_keys(user_id=_user.id)
    
    _report_row = {
        "iam_username": "",
        "TenantAdmin": 'USER',
        "user_type": "IAM",
        "iam_id": "",
        "iam_compartment_id": "",
        "iam_api_keys": len(_api_keys.data),
        "iam_can_use_api_keys": "",
        "iam_can_use_auth_tokens": "",
        "iam_can_use_console_password": "",
        "iam_can_use_customer_secret_keys": "",
        "iam_can_use_o_auth2_client_credentials": "",
        "iam_can_use_smtp_credentials": "",    
        "iam_active": "",
        "iam_islocked": True,
        "iam_mfa": False,
        "idcs_id": "",
        "idcs_username": "",
        "idcs_user_creation_time": "",
        "idcs_active": False,
        "idcs_password_last_changed": "",
        "idcs_previous_login_date": "",    
        "idcs_last_login_date": "",    
        "idcs_islocked": False,       
        "idcs_mfa": False, 
        "mfa": False,
        "active": False
    }
    #print(_user)
    
    # Local OCI User
    #print("Local User")
    _report_row["iam_username"] = _user.name
    _report_row["iam_id"] = _user.id
    _report_row["iam_compartment_id"] = _user.compartment_id
    _report_row["iam_active"] = _user.lifecycle_state
    if (_user.lifecycle_state == "ACTIVE"):
        _report_row["active"] = True
    _report_row["iam_mfa"] = _user.is_mfa_activated
    _report_row["mfa"] = _user.is_mfa_activated
    _report_row["iam_can_use_api_keys"] = _user.capabilities.can_use_api_keys
    _report_row["iam_can_use_auth_tokens"] = _user.capabilities.can_use_auth_tokens
    _report_row["iam_can_use_console_password"] = _user.capabilities.can_use_console_password
    _report_row["iam_can_use_customer_secret_keys"] = _user.capabilities.can_use_customer_secret_keys
    _report_row["iam_can_use_o_auth2_client_credentials"] = _user.capabilities.can_use_o_auth2_client_credentials
    _report_row["iam_can_use_smtp_credentials"] = _user.capabilities.can_use_smtp_credentials

    if (_user.external_identifier != None):
        #print("IDCS User")
        response = _idcsClient.get_user(_user.external_identifier)
        if (response != None):
            _report_row["user_type"] = "IDCS"
            _user_details = json.loads(response)
            #print(_user_details)
            if "nickName" in _user_details:
                if _user_details["nickName"] == "TAS_TENANT_ADMIN_USER":
                    _report_row["TenantAdmin"] = 'TAS_TENANT_ADMIN_USER'
            _report_row["idcs_username"] = _user_details["userName"]
            _report_row["idcs_id"] = _user_details["id"]
            _report_row["idcs_user_creation_time"] = _user_details["meta"]["created"]
            _report_row["idcs_active"] = _user_details["active"]
            _report_row["active"] = _user_details["active"]
            _report_row["idcs_password_last_changed"] = _user_details["urn:ietf:params:scim:schemas:oracle:idcs:extension:passwordState:User"]["lastSuccessfulSetDate"]
            _report_row["idcs_previous_login_date"] = _user_details["urn:ietf:params:scim:schemas:oracle:idcs:extension:userState:User"]["previousSuccessfulLoginDate"]
            _report_row["idcs_last_login_date"] = _user_details["urn:ietf:params:scim:schemas:oracle:idcs:extension:userState:User"]["lastSuccessfulLoginDate"]
            if "urn:ietf:params:scim:schemas:oracle:idcs:extension:mfa:User" in _user_details["schemas"]:
                if _user_details["urn:ietf:params:scim:schemas:oracle:idcs:extension:mfa:User"]["mfaStatus"] == 'ENROLLED':
                    _report_row["idcs_mfa"] = True
                    _report_row["mfa"] = True
            _report_row["idcs_islocked"] = _user_details["urn:ietf:params:scim:schemas:oracle:idcs:extension:userState:User"]["locked"]["on"]
    _report.append(_report_row)
    #print(_report_row)
         
        #print(_user_details["urn:ietf:params:scim:schemas:oracle:idcs:extension:userState:User"]["lastSuccessfulLoginDate"])

_file1 = os.environ['TEMP_REPORT_FILE']
_file2 = _file1+'.csv'
with open(_file2, 'w') as f:
    json.dump(_report, f)

df = pd.read_json (_file2)
df.to_csv (_file1, index = None)    

print(" >> OCI Credential Report ready")