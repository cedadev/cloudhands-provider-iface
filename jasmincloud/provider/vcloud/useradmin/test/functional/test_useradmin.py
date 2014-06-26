'''
Created on Jun 11, 2014

@author: philipkershaw
'''
import unittest
import logging
from os import path

from libcloud import security

from jasmincloud.provider.vcloud.useradmin.client import UserAdminClient

# Location of the directory containing *this* module
HERE_DIR = path.dirname(__file__)

# The configuration directory holds files for setting the vCD hostname and 
# user credentials, also, a CA directory for CA certificate bundle file
CONFIG_DIR = path.join(HERE_DIR, 'config')

# CA Certificates bundle for securing the connection to the server.  This is a
# concatenated set of PEM-format CA certificates.  Nb. server authentication is
# disabled in the test environment as the test server is using a self-signed 
# certificate
CA_CERTS_PATH = path.join(CONFIG_DIR, 'ca', 'v55-ca-bundle.crt')

CREDS_FILEPATH = path.join(CONFIG_DIR, 'creds.txt')
CLOUD_HOSTNAME_FILEPATH = path.join(CONFIG_DIR, 'hostname.txt')

log = logging.getLogger(__name__)
logging.basicConfig(format='%(asctime)s %(message)s', level=logging.DEBUG)


class UserAdminTestCase(unittest.TestCase):
    USERNAME, PASSWORD = open(CREDS_FILEPATH).read().strip().split(':')
    CLOUD_HOSTNAME = open(CLOUD_HOSTNAME_FILEPATH).read().strip()
    
    # Disable SSL verification for testing ONLY
#    security.CA_CERTS_PATH = [CA_CERTS_PATH]
    security.VERIFY_SSL_CERT = False

    def setUp(self):
        self.clnt = UserAdminClient.from_connection(self.__class__.USERNAME,
                                               self.__class__.PASSWORD,
                                               self.__class__.CLOUD_HOSTNAME)
    
    def test01_get_userinfo(self):
        vdc_name = self.__class__.USERNAME.split('@')[-1]
        
        try:
            user_info = self.clnt.get_userinfo(vdc_name=vdc_name)
        except Exception as e:
            self.fail(e)
            
        self.assertIsInstance(user_info, UserAdminClient)


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()