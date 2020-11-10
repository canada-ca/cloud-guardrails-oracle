from __future__ import print_function
import sys
import os

import oci

import time
import requests 
import getpass
import json
import pandas as pd
from jsonpath_ng import jsonpath, parse
import jsonpath_rw_ext
from base64 import b64encode
import xml.dom.minidom
from idcs_client import IdcsClient
from oci_client import OciClient
from settings import Settings
from utils import myprint

_config = oci.config.from_file(os.environ['OCI_CONFIG'], os.environ['OCI_PROFILE'])

ociIdentityClient = oci.identity.IdentityClient(_config)

_policies = ociIdentityClient.list_policies(compartment_id=_config['tenancy'])
for _policy in _policies.data:
    print(_policy.name)