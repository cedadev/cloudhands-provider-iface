"""JASMIN Cloud

Cloudhands provider interface functional tests vCloud 5.5 - test networking 
config - config of Edge device
"""
__author__ = "P J Kershaw"
__date__ = "01/04/14"
__copyright__ = "(C) 2014 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__revision__ = "$Id$"
from os import path
import unittest
import logging

from libcloud import security

from cloudhands.provider.vcloud.network.client import EdgeGatewayClient


# Location of the directory containing *this* module
HERE_DIR = path.dirname(__file__)

# The configuration directory holds files for setting the vCD hostname and 
# user credentials, also, a CA directory for CA certificate bundle file
CONFIG_DIR = path.join(HERE_DIR, 'config')

# CA Certificates bundle for securing the connection to the server.  This is a
# concatenated set of PEM-format CA certificates.  Nb. server authentication is
# disabled in the test environment as the test server is using a selg-signed 
# certificate
CA_CERTS_PATH = path.join(CONFIG_DIR, 'ca', 'v55-ca-bundle.crt')

# File containing the authentication credentials.  It should be of the form
# <vCloud id>@<vCloud Org Name>:<password>
CREDS_FILEPATH = path.join(CONFIG_DIR, 'v55creds.txt')

# File containing the hostname for the vCloud Director API endpoint.  Simply
# place the FQDN on a single line and save the file.
CLOUD_HOSTNAME_FILEPATH = path.join(CONFIG_DIR, 'v55cloud-host.txt')
           
log = logging.getLogger(__name__)
logging.basicConfig(format='%(asctime)s %(message)s', level=logging.DEBUG)

 
class EdgeGatewayClientTestCase(unittest.TestCase):
    '''Test Edge Gateway client network configuration 
    '''
    USERNAME, PASSWORD = open(CREDS_FILEPATH).read().strip().split(':')
    CLOUD_HOSTNAME = open(CLOUD_HOSTNAME_FILEPATH).read().strip()
    
    # Disable SSL verification for testing ONLY
#    security.CA_CERTS_PATH = [CA_CERTS_PATH]
    security.VERIFY_SSL_CERT = False
    
    def setUp(self):
        self.edgegateway_clnt = EdgeGatewayClient.from_connection(
                                                 self.__class__.USERNAME, 
                                                 self.__class__.PASSWORD, 
                                                 self.__class__.CLOUD_HOSTNAME)
        
    def test01_retrieve_conf(self):
        edgegateway_confs = self.edgegateway_clnt.retrieve_conf()
        self.assert_(edgegateway_confs)
    
              
if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()