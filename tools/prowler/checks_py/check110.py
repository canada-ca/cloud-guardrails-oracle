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



_settings = {
    "client_id": os.environ['IDCS_CLIENT_ID'],
    "client_secret": os.environ['IDCS_CLIENT_SECRET'],
    "base_url": os.environ['IDCS_BASE_URL'],
}
#print(_settings)
_idcsClient = IdcsClient(json.dumps(_settings))

_response = _idcsClient.search_password_policies()  

print(_response["numPasswordsInHistory"])