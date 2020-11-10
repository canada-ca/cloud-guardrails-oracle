# Ludovic Dessemon, Enterprise Cloud Strategist (Oracle Canada)
# July, 2020
# OCI, Settingss

class Settings(object):
    """Class for holding configuration options for auto-federation test"""

    __slots__ = 'app_name', 'tenant_id', 'oci_idp_name', 'sscmaster_group', \
                'key_id', 'public_key_file', 'user', 'token_endpoint', 'scim_endpoint', 'base_url', \
                'client_id', 'client_secret', 'oci_metadata_endpoint', 'private_key_file', 'sp_tenant', 'idp_tenant', \
                'marketplace_group_launcher', 'marketplace_group_subscriber', \
                'master_policy', 'marketplace_policy'

    def __init__(self, run_config):
        """Constructor for the Settings class"""
        self.app_name = run_config['app_name']
        self.tenant_id = run_config['sp_tenant']['config']['tenancy']
        self.oci_idp_name = run_config['idp_name']
        self.sscmaster_group = run_config['sscmaster_group']
        self.public_key_file = run_config['public_key_file']
        self.user = run_config['user']

        self.token_endpoint = run_config['token_endpoint'].format(region=run_config['idp_tenant']['config']['region'])
        self.scim_endpoint = run_config['scim_endpoint'].format(region=run_config['idp_tenant']['config']['region'])

        self.base_url = run_config['idcs']['base_url']
        self.client_id = run_config['idcs']['client_id']
        self.client_secret = run_config['idcs']['client_secret']
        self.oci_metadata_endpoint = run_config['oci_metadata_endpoint'].format(region=run_config['sp_tenant']['config']['region'])
        self.private_key_file = run_config['private_key_file']
        self.sp_tenant = run_config['sp_tenant']
        self.idp_tenant = run_config['idp_tenant']

        self.marketplace_group_subscriber = run_config['marketplace_group_subscriber']
        self.marketplace_group_launcher = run_config['marketplace_group_launcher']

        self.marketplace_policy = run_config['marketplace_policy']
        self.master_policy = run_config['master_policy']

    @property
    def app_id(self):
        return self.tenant_id.replace('.', '')