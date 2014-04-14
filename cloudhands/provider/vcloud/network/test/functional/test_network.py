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
    SETTINGS_FILEPATH = (getenv('EDGE_GATEWAY_CLNT_TEST_CFG_FILEPATH') or 
                         path.join(CONFIG_DIR, 'edgegateway_clnt.cfg'))
    
    # Disable SSL verification for testing ONLY
#    security.CA_CERTS_PATH = [CA_CERTS_PATH]
    security.VERIFY_SSL_CERT = False
    
    def __init__(self, *arg, **kwarg):
        super(EdgeGatewayClientTestCase, self).__init__(*arg, **kwarg)
        
    def setUp(self):
        self.edgegateway_clnt = EdgeGatewayClient.from_settings_file(
                                            self.__class__.SETTINGS_FILEPATH)
        
        con_settings = self.edgegateway_clnt.settings[
                                        EdgeGatewayClient.SETTINGS_GLOBAL]
        self.edgegateway_clnt.connect(con_settings['username'], 
                                      con_settings['password'], 
                                      con_settings['hostname'])
        
        self.vdc_name = self.edgegateway_clnt.settings[
                    EdgeGatewayClient.SETTINGS_GLOBAL]['vdc_name']
                            
        self.edgegateway_name = self.edgegateway_clnt.settings[
                    EdgeGatewayClient.SETTINGS_GLOBAL]['edgegateway_name']
                            
    def test01_read_settings_file(self):
        edgegateway_clnt = EdgeGatewayClient()
        edgegateway_clnt.parse_settings_file(self.__class__.SETTINGS_FILEPATH)
        
        for section_name in list(edgegateway_clnt.settings.keys()):
            for i, param in enumerate(edgegateway_clnt.settings[section_name]):
                self.assertTrue(param, 'Missing param %r for section %r' % 
                             (i, section_name))
        
    def test02_instantiate_from_settings_file(self):
        vdc_uri = self.edgegateway_clnt.get_vdc_uri(self.vdc_name)
        self.assertTrue(vdc_uri)  
        uri = self.edgegateway_clnt.get_vdc_edgegateways_uri(vdc_uri)
    
        self.assertTrue(uri)
        log.info('VDC Edge Gateways URI: %r', uri)
        
    def test03_get_config_for_specified_vdc_and_edgegateway(self):
        # Retrieve named Edge Gateway from given VDC
        edgegateway_configs = self.edgegateway_clnt.get_config(
                                                vdc_name=self.vdc_name,
                                                names=[self.edgegateway_name])
        self.assertTrue(edgegateway_configs)
        self.assertTrue(len(edgegateway_configs) == 1)
        
    def test04_set_host_routing(self):
        edgegateway_configs = self.edgegateway_clnt.get_config(
                                                vdc_name=self.vdc_name,
                                                names=[self.edgegateway_name])
        
        edgegateway_config = edgegateway_configs[0]
        
        inputs = self.edgegateway_clnt.settings[
                                        EdgeGatewayClient.SETTINGS_ROUTE_HOST]
        
        self.edgegateway_clnt.set_host_routing(edgegateway_config,
                                               inputs['iface_name'],
                                               inputs['internal_ip'],
                                               inputs['external_ip'])
        
        res = self.edgegateway_clnt.post_config(edgegateway_config)
        
        self.assertTrue(res)

    def test05_remove_nat_rules(self):
        edgegateway_configs = self.edgegateway_clnt.get_config(
                                                vdc_name=self.vdc_name,
                                                names=[self.edgegateway_name])
        edgegateway_config = edgegateway_configs[0]
        
        nat_rule_ids = self.edgegateway_clnt.settings[
                        EdgeGatewayClient.SETTINGS_RM_NAT_RULES]['nat_rule_ids']

        EdgeGatewayClient.remove_nat_rules(edgegateway_config, nat_rule_ids)
        
        res = self.edgegateway_clnt.post_config(edgegateway_config)
        
        self.assertTrue(res)
    
              
if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()