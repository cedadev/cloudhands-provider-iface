"""JASMIN Cloud

JASMIN Cloud provider interface functional tests vCloud 5.5 - test networking 
config - Firewall Rule aspects of config for Edge device
"""
__author__ = "P J Kershaw"
__date__ = "21/05/14"
__copyright__ = "(C) 2014 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__revision__ = "$Id$"
from os import path
import unittest
import logging

from jasmincloud.provider.vcloud.network.client import FirewallRule


# Location of the directory containing *this* module
HERE_DIR = path.dirname(__file__)

# The configuration directory holds files for setting the vCD hostname and 
# user credentials, also, a CA directory for CA certificate bundle file
CONFIG_DIR = path.join(HERE_DIR, 'config')
           
log = logging.getLogger(__name__)
logging.basicConfig(format='%(asctime)s %(message)s', level=logging.DEBUG)

 
class EdgeGatewayClientFirewallRuleTestCase(unittest.TestCase):
    '''Test Edge Gateway client Firewall Rule configuration 
    '''        
    def test01(self):
        firewall_rule = FirewallRule()
        self.assertIsInstance(firewall_rule, FirewallRule)

        self.assertEqual(firewall_rule.rule_id, -1)
        
        self.assertEqual(firewall_rule.rule_is_enabled, False)
        
        self.assertEqual(firewall_rule.match_on_translate, False)
        self.assertEqual(firewall_rule.description, '')
        self.assertEqual(firewall_rule.policy, FirewallRule.POLICY_DROP)
        
        self.assertEqual(firewall_rule.protocols, {})
            
        self.assertEqual(firewall_rule.port, FirewallRule.ANY_PORT)
        self.assertEqual(firewall_rule.dest_port_range, FirewallRule.ANY_PORT)
        self.assertEqual(firewall_rule.src_port, FirewallRule.ANY_PORT)
        self.assertEqual(firewall_rule.src_port_range, FirewallRule.ANY_IP)
        self.assertEqual(firewall_rule.src_ip, FirewallRule.ANY_IP)
        self.assertEqual(firewall_rule.direction, FirewallRule.DIRECTION_OUT)
        self.assertEqual(firewall_rule.enable_logging, False)
              
    def test02(self):
        firewall_rule = FirewallRule()
        self.assertIsInstance(firewall_rule, FirewallRule)
              
if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()