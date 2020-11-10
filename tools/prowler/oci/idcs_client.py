# Ludovic Dessemon, Enterprise Cloud Strategist (Oracle Canada)
# July, 2020
# Python client for Oracle Identity Cloud Service

from modules.requests import http_retry, Status
import base64
import json
import requests

import time
import xml.etree.ElementTree as ET
from utils import myprint

class IdcsClient(object):
    """Client class to interact with IDCS server"""

    def __init__(self, settings):
        _settings = json.loads(settings)
        #print(_settings["client_id"])
        """constructor for IdcsClient"""

        self.settings = _settings
        self.headers = {
            'Content-Type': 'application/json;charset=UTF-8',
            # use entitlement app credentials to get admin privileges to create/delete managed app
            'Authorization': 'Bearer ' + self.get_access_token(_settings["client_id"], _settings["client_secret"])
        }

    # Def OK
    def get_metadata(self):
        """retrieves the federation metadata for this IDCS stripe"""

        url = self.get_metadata_url()

        with http_retry(Status.OK):
            response = requests.get(url, headers=self.headers).content.decode('utf-8')
            return response.replace("\n", "")

    # Def OK
    def get_metadata_url(self):
        """Retrieves the IDCS federation metadata URL"""

        url = '{base_url}/fed/v1/metadata'.format(base_url=self.get_base_url())

        return url

    # Def OK
    def get_base_url(self):
        """Returns the IDCS base url"""
        return self.settings["base_url"]

    # Def OK
    def get_access_token(self, client_id, client_secret):
        """Gets an JWT access token from IDCS authorization server"""
        #print(self.settings)
        url = '{base_url}/oauth2/v1/token'.format(base_url=self.settings["base_url"])

        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': 'Basic ' + base64.b64encode((client_id + ':' +
                                                          client_secret).encode()).decode('utf-8')
        }
        payload = "grant_type=client_credentials&scope=urn:opc:idm:__myscopes__"

        with http_retry(Status.OK):
            response = requests.post(url, data=payload, headers=headers)
            #print(response)
            jwt = response.json()["access_token"]

            return jwt

    # Def OK
    def search_password_policies(self):
        url = '{base_url}/admin/v1/PasswordPolicies'.format(base_url=self.settings["base_url"])

        #querystring = {"filter": 'displayName eq "Oracle Cloud Infrastructure" and active eq true'}
        querystring = {}
        
        with http_retry(Status.OK):
            response = requests.get(url, headers=self.headers, params=querystring)

        if response.json()["totalResults"] > 0:
            return response.json()["Resources"][0]

        return None

    def find_application_template(self):
        """Finds the OCI managed application template"""

        url = '{base_url}/admin/v1/AppTemplates'.format(base_url=self.settings["base_url"])

        querystring = {"filter": 'displayName eq "Oracle Cloud Infrastructure" and active eq true'}

        with http_retry(Status.OK):
            response = requests.get(url, headers=self.headers, params=querystring)

        if response.json()["totalResults"] > 0:
            return response.json()["Resources"][0]

        return None
    # Def OK
    def find_managed_app_by_tenancy(self, template_id, tenancy):
        """Find the first managed application created based on the specified template id and specified app name"""
        app_name = tenancy.replace(".","") + "_APPID"
        url = "{base_url}/admin/v1/Apps".format(base_url=self.settings["base_url"])

        querystring = {"filter": 'name eq "{app_name}" and basedOnTemplate.value eq "{template_id}"'
                       .format(app_name=app_name, template_id=template_id)}

        response = requests.get(url, headers=self.headers, params=querystring)
        if response.json()["totalResults"] > 0:
            return response.json()['Resources'][0]

        return None

    def find_managed_app(self, template_id, app_name):
        """Find the first managed application created based on the specified template id and specified app name"""

        url = "{base_url}/admin/v1/Apps".format(base_url=self.settings["base_url"])

        querystring = {"filter": 'displayName eq "{app_name}" and basedOnTemplate.value eq "{template_id}"'
                       .format(app_name=app_name, template_id=template_id)}

        response = requests.get(url, headers=self.headers, params=querystring)
        if response.json()["totalResults"] > 0:
            return response.json()['Resources'][0]

        return None

    # Def OK
    def create_managed_app(self, template_id, app_name, app_id):
        """Creates a managed application based on the specified template id"""

        url = '{base_url}/admin/v1/Apps'.format(base_url=self.settings["base_url"])

        payload = """{{
            "active":true,
            "basedOnTemplate": {{
                "value":"{template_id}"
            }},
            "displayName":"{app_name}",
            "isSamlServiceProvider":false,
            "urn:ietf:params:scim:schemas:oracle:idcs:extension:opcService:App:serviceInstanceIdentifier":"{app_id}",
            "name":"{app_id}_APPID",
            "schemas":["urn:ietf:params:scim:schemas:oracle:idcs:App"]
        }}"""

        with http_retry(Status.CREATED):
            response = requests.post(url, data=payload.format(
                template_id=template_id, app_name=app_name, app_id=app_id), headers=self.headers)

            return response.json()
        print("Error : %s" % Status)
        return Status

    # Def OK
    def patch_managed_app(self, config, app_clientid, app_secret):
        """Patches existing managed application with federation and provisioning configuration"""

        payload = """{{
    "command":"enableNextFedSyncModes",
    "FedSyncModes":{{
        "nextSynchronizationMode":"AppAsTarget",
        "nextFederationMode":"AppAsServiceProvider"
    }},
    "SyncConfig":{{
        "bundleConfigurationProperties":[
            {{
                "name":"authURL",
                "value":["{auth_url}"]
            }},{{
                "name":"scimBaseURL",
                "value":["{scim_url}"]
            }},{{
                "name":"scope",
                "value":["{scope}"]
            }},{{
                "name":"clientId",
                "value":["{client_id}"]
            }},{{
                "name":"clientSecret",
                "value":["{client_secret}"]
            }}
        ],
        "adminConsentGranted":true
    }},
    "ServiceProviderConfig":{{
        "partnerProviderId":"{assertion_consumer_url}",
        "assertionConsumerUrl":"{assertion_consumer_url}",
        "signingCertificate":"{signing_cert}"
    }}
}}"""

        # use managed app credentials to deactivate the app itself
        jwt = self.get_access_token(app_clientid, app_secret)

        headers = {
            'Content-Type': 'application/json;charset=UTF-8',
            'Authorization': 'Bearer ' + jwt
        }

        url = '{base_url}/sm/v1/AppServices/Me'.format(base_url=self.settings["base_url"])
        config["scope"] = "urn:oracle:oci:scim-service"

        response = requests.patch(url, data=payload.format(**config), headers=headers)
        return response

    # Def OK
    def deactivate_managed_app(self, app_id, app_clientid, app_secret):
        """Deactivates the managed application specified by app_id"""

        url = '{base_url}/admin/v1/AppStatusChanger/{app_id}'.format(base_url=self.settings["base_url"], app_id=app_id)

        # use managed app credentials to deactivate the app itself
        jwt = self.get_access_token(app_clientid, app_secret)

        headers = {
            'Content-Type': 'application/json;charset=UTF-8',
            'Authorization': 'Bearer ' + jwt
        }
        payload = """{
            "schemas":["urn:ietf:params:scim:schemas:oracle:idcs:AppStatusChanger"],
            "active":false
        }"""

        with http_retry(Status.OK):

            response = requests.put(url, data=payload, headers=headers)
            return response.json()

    # Def OK
    def delete_managed_app(self, app_id):
        """Deletes the specified managed application"""

        url = '{base_url}/admin/v1/Apps/{app_id}'.format(base_url=self.settings["base_url"], app_id=app_id)

        with http_retry(Status.NO_CONTENT):
            requests.delete(url, data="", headers=self.headers)

    # Not Used
    def find_grant(self, values):

        query = 'grantee[type eq "Group" and value eq "{group_id}"] and ' + \
                'app.value eq "{app_id}" and ' + \
                'grantMechanism eq "ADMINISTRATOR_TO_GROUP'

        params = {
            'filter': query.format(**values),
            'attributes': 'id'
        }

        url = self.settings["base_url"] + '/admin/v1/Grants'

        response = requests.get(url, headers=self.headers, params=params)
        return response

    # Def OK
    def create_grant(self, grp_id, group_name, app_id):
        url = '{base_url}/admin/v1/Grants'.format(base_url=self.settings["base_url"])

        payload = """{{
    "schemas":["urn:ietf:params:scim:schemas:oracle:idcs:Grant"],
    "grantee":{{
        "type":"Group",
        "value":"{grp_id}"
    }},
    "app":{{
        "value":"{app_id}"
    }},
    "grantedAttributeValuesJson":"{{\\\"attributes\\\":{{\\\"idpGroups\\\":[\\\"{grp_id}/{group_name}\\\"]}}}}",
    "grantMechanism":"ADMINISTRATOR_TO_GROUP"
}}"""

        response = requests.post(url, data=payload.format(grp_id=grp_id, group_name=group_name, app_id=app_id),
                                 headers=self.headers)
        return response

    # Not Used
    def delete_grant(self, app_id):

        url = "{base_url}/admin/v1/Grants/{app_id}".format(base_url=self.settings["base_url"], app_id=app_id)

        with http_retry(Status.NO_CONTENT):
            requests.delete(url, headers=self.headers)

    # Def OK
    def find_group(self, group_name):
        """Finds a group in IDCS by its name"""

        payload = """{{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:SearchRequest"],
  "attributes": ["displayName", "externalId"],
  "filter": "displayName sw \\\"{group_name}\\\"",
  "startIndex": 1,
  "count": 10
}}"""

        url = "{base_url}/admin/v1/Groups/.search".format(base_url=self.settings["base_url"])

        with http_retry(Status.OK):
            response = requests.post(url, data=payload.format(group_name=group_name), headers=self.headers)

            if response.json()["totalResults"] > 0:
                return response.json()["Resources"][0]

        return None

    # Def OK
    def create_group(self, group_name):
        """Creates a new group in IDCS"""
        group = self.find_group(group_name)
        if group == None:            
            url = "{base_url}/admin/v1/Groups".format(base_url=self.settings["base_url"])

            payload = """{{
    "displayName": "{group_name}",
    "externalId": "{group_name}",
    "urn:ietf:params:scim:schemas:oracle:idcs:extension:group:Group": {{
        "creationMechanism": "api",
        "description": "Employee Group"
    }},
    "members": [],
    "schemas": [
        "urn:ietf:params:scim:schemas:core:2.0:Group",
        "urn:ietf:params:scim:schemas:oracle:idcs:extension:group:Group",
        "urn:ietf:params:scim:schemas:extension:custom:2.0:Group"
    ]
    }}"""

            with http_retry(Status.CREATED):
                response = requests.post(url, data=payload.format(group_name=group_name), headers=self.headers)
            myprint("(IDCS) Group %s" % group_name,"Created")
            return response.json()
        else:
            myprint("(IDCS) Group %s" % group_name,"Already Exists")
            return group
    
    # Def OK
    def delete_group_by_name(self, group_name):
        group = self.find_group(group_name)
        if group != None:
            response = self.delete_group(group['id'])
            while self.find_group(group_name) != None:
                time.sleep(5)
            myprint("(IDCS) Group %s" % group_name,"Deleted")
            return None 
        else:
            myprint("(IDCS) Group %s" % group_name,"Not Found")

    # Def OK
    def delete_group(self, group_id):
        """Deletes the specified group from IDCS"""
        url = "{base_url}/admin/v1/Groups/{group_id}".format(base_url=self.settings["base_url"], group_id=group_id)

        with http_retry(Status.NO_CONTENT):
            response = requests.delete(url, headers=self.headers)
            return response

    # Users
    def get_user(self, id):
        if id == None:
            return None
        else:
            url = "{base_url}/admin/v1/Users/{id}?attributeSets=all".format(base_url=self.settings["base_url"], id=id)
            with http_retry(Status.OK):
                response = requests.get(url, headers=self.headers).content.decode('utf-8')
                return response
    # Def OK
    def create_user(self, user):
        _user = self.find_user(user['email'])
        if _user == None:            
            url = "{base_url}/admin/v1/Users".format(base_url=self.settings["base_url"])

            payload = """{{
    "schemas": [
        "urn:ietf:params:scim:schemas:core:2.0:User"
    ],
    "userName": "{user_name}",
    "password": "{user_password}",
    "name": {{
        "familyName": "{last_name}",
        "givenName": "{first_name}"
    }},
    "emails": [
        {{
        "value": "{email}",
        "type": "work",
        "primary": true
        }}
    ]
    }}"""
            with http_retry(Status.CREATED):
                response = requests.post(url, data=payload.format(**user), headers=self.headers)
            myprint("(IDCS) User %s" % user['email'],"Created")
            return response.json()
        else:
            myprint("(IDCS) User %s" % user['email'],"Already Exists")
            return _user

    # Def OK
    def find_user(self, user_name):
        payload = """{{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:SearchRequest"],
  "attributes": ["displayName", "userName", "groups"],
  "filter":
          "userName eq \\\"{user_name}\\\"",
  "startIndex": 1,
  "count": 10
}}"""

        url = "{base_url}/admin/v1/Users/.search".format(base_url=self.settings["base_url"])

        with http_retry(Status.OK):
            response = requests.post(url, data=payload.format(user_name=user_name), headers=self.headers)

            if response.json()["totalResults"] > 0:
                return response.json()["Resources"][0]

        return None

    # Def OK
    def delete_user_by_name(self, user_name):
        user = self.find_user(user_name)
        if user != None:
            response = self.delete_user(user['id'])
            while self.find_user(user_name) != None:
                time.sleep(5)
            myprint("User %s" % user_name,"Deleted")
            return None 
        else:
            myprint("User %s" % user_name,"Not Found")

    # Def OK
    def delete_user(self, user_id):
        """Deletes a user from IDCS"""

        url = "{base_url}/admin/v1/Users/{user_id}?forceDelete=true".format(base_url=self.settings["base_url"],
                                                                            user_id=user_id)
        with http_retry(Status.NO_CONTENT):
            requests.delete(url, data="", headers=self.headers)

    def find_group_membership(self, user_name, group_name):
        _user = self.find_user(user_name)
        if _user != None:
            for _group in _user["groups"]:
                if _group["display"] == group_name:
                    myprint("User %s belongs to group %s" % (user_name,group_name),"Found")
                    return True
            myprint("User %s belongs to group %s" % (user_name,group_name),">>> Not Found <<<")

    # Def OK
    def add_group_membership(self, group_id, user_id):

        payload = """{{
  "schemas": [
    "urn:ietf:params:scim:api:messages:2.0:PatchOp"
  ],
  "Operations": [
    {{
      "op": "add",
      "path": "members",
      "value": [
        {{
          "value": "{user_id}",
          "type": "User"
        }}
      ]
    }}
  ]
}}"""

        url = "{base_url}/admin/v1/Groups/{group_id}".format(base_url=self.settings["base_url"], group_id=group_id)

        with http_retry(Status.OK):
            response = requests.patch(url, data=payload.format(user_id=user_id), headers=self.headers)
            return response