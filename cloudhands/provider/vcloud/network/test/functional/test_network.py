"""JASMIN Cloud

Cloudhands provider interface functional tests vCloud 5.5 - test networking 
config - config of Edge device
"""
__author__ = "P J Kershaw"
__date__ = "01/04/14"
__copyright__ = "(C) 2014 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__revision__ = "$Id$"
from os import path, getenv
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
# disabled in the test environment as the test server is using a self-signed 
# certificate
CA_CERTS_PATH = path.join(CONFIG_DIR, 'ca', 'v55-ca-bundle.crt')

           
log = logging.getLogger(__name__)
logging.basicConfig(format='%(asctime)s %(message)s', level=logging.DEBUG)

 
class EdgeGatewayClientTestCase(unittest.TestCase):
    '''Test Edge Gateway client network configuration 
    '''    
    CFG_FILEPATH = (getenv('EDGE_GATEWAY_CLNT_TEST_CFG_FILEPATH') or 
                    path.join(CONFIG_DIR, 'edgegateway_clnt.cfg'))
    
    # Disable SSL verification for testing ONLY
#    security.CA_CERTS_PATH = [CA_CERTS_PATH]
    security.VERIFY_SSL_CERT = False
    
    def __init__(self, *arg, **kwarg):
        super(EdgeGatewayClientTestCase, self).__init__(*arg, **kwarg)
        
    def setUp(self):
        settings = EdgeGatewayClient.parse_config_file(
                        self.__class__.CFG_FILEPATH,
                        section_names=[EdgeGatewayClient.CFG_FILE_MK_CON])
        
        con_settings = settings[EdgeGatewayClient.CFG_FILE_MK_CON]
        self.edgegateway_clnt = EdgeGatewayClient.from_connection(
                                                 con_settings['username'], 
                                                 con_settings['password'], 
                                                 con_settings['hostname'])
        
    
    def test01_read_config_file(self):
        settings = EdgeGatewayClient.parse_config_file(
                                                self.__class__.CFG_FILEPATH)
        for section_name in settings.keys():
            for i, param in enumerate(settings[section_name]):
                self.assert_(param, 'Missing param %r for section %r' % 
                             (i, section_name))
        
    def test02_instantiate_from_config_file_settings(self):
        edgegateway_clnt = EdgeGatewayClient.from_config_file(
                                                    self.__class__.CFG_FILEPATH) 
        self.assert_(edgegateway_clnt)
        
    def test03_retrieve_edgegateway_config(self):
        edgegateway_confs = self.edgegateway_clnt.retrieve_edgegateway_config()
        self.assert_(edgegateway_confs)
        
    def test04_(self):
        edgegateway_confs = self.edgegateway_clnt.retrieve_edgegateway_config()
        
        settings = EdgeGatewayClient.parse_config_file(
                        self.__class__.CFG_FILEPATH,
                        section_names=[EdgeGatewayClient.CFG_FILE_ROUTE_HOST])
        
        inputs = settings[EdgeGatewayClient.CFG_FILE_ROUTE_HOST]
        
        self.edgegateway_clnt.route_host(edgegateway_confs[0],
                                         inputs['iface_name'],
                                         inputs['internal_ip'],
                                         inputs['external_ip'])
        
        
    
              
if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()