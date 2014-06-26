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
import xml.etree.ElementTree as ET

from jasmincloud.provider.vcloud.network.edge_gateway import (FirewallRule, 
                                                              ETreeFirewallRule)


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
    def test01_instantiate(self):
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
        self.assertEqual(firewall_rule.dest_ip, FirewallRule.ANY_IP)
        self.assertEqual(firewall_rule.src_port, FirewallRule.ANY_PORT)
        self.assertEqual(firewall_rule.src_port_range, FirewallRule.ANY_PORT)
        self.assertEqual(firewall_rule.src_ip, FirewallRule.ANY_IP)
        self.assertEqual(firewall_rule.direction, FirewallRule.DIRECTION_OUT)
        self.assertEqual(firewall_rule.enable_logging, False)

    def test02_attribute_set(self):
        firewall_rule = FirewallRule()
        self.assertIsInstance(firewall_rule, FirewallRule)
        self._set_properties(firewall_rule)
        
    def _set_properties(self, firewall_rule):
        firewall_rule.rule_id = 12345
        self.assertEqual(firewall_rule.rule_id, 12345)
        
        firewall_rule.rule_is_enabled = True
        self.assertEqual(firewall_rule.rule_is_enabled, True)
        
        firewall_rule.match_on_translate = True
        self.assertEqual(firewall_rule.match_on_translate, True)
        
        firewall_rule.description = 'ssh access'
        self.assertEqual(firewall_rule.description, 'ssh access')
        
        try:
            firewall_rule.policy = 'Deny'
        except ValueError:
            pass
        else:
            self.fail("'Deny' is not a valid value for policy attribute")
            
        firewall_rule.policy = FirewallRule.POLICY_ALLOW
        self.assertEqual(firewall_rule.policy, FirewallRule.POLICY_ALLOW)
        
        try:
            firewall_rule.protocols[0] = True
            
        except TypeError as e:
            log.debug('Exception correctly raised: %r', e)
            pass
        else:
            self.fail("0 is not a valid key for protocols dict")
        
        try:
            firewall_rule.protocols['tcp'] = 1
            
        except TypeError as e:
            log.debug('Exception correctly raised: %r', e)
            pass
        else:
            self.fail("1 is not a valid value for protocols dict")
            
        firewall_rule.protocols['tcp'] = True
        self.assertEqual(firewall_rule.protocols['tcp'], True)
            
        firewall_rule.port = 22   
        self.assertEqual(firewall_rule.port, 22)
        
        firewall_rule.dest_port_range = 21
        self.assertEqual(firewall_rule.dest_port_range, 21)
        
        firewall_rule.dest_ip = '192.168.0.72'
        self.assertEqual(firewall_rule.dest_ip, '192.168.0.72')
        
        firewall_rule.src_port = 443
        self.assertEqual(firewall_rule.src_port, 443)
        
        firewall_rule.src_port_range = 7532
        self.assertEqual(firewall_rule.src_port_range, 7532)
        
        firewall_rule.src_ip = '192.168.0.5'
        self.assertEqual(firewall_rule.src_ip, '192.168.0.5')
        
        firewall_rule.direction = FirewallRule.DIRECTION_IN
        self.assertEqual(firewall_rule.direction, FirewallRule.DIRECTION_IN)
        
        firewall_rule.enable_logging = True
        self.assertEqual(firewall_rule.enable_logging, True)
                      
    def test03_serialise_from_defaults(self):
        firewall_rule = FirewallRule()
        self.assertIsInstance(firewall_rule, FirewallRule)
        
        et_firewall_rule = ETreeFirewallRule()
        firewall_rule_elem = et_firewall_rule.create_elem(firewall_rule)
        
        self.assertIsInstance(firewall_rule_elem, ET.Element)
        
        log.debug(ET.tostring(firewall_rule_elem))
    
    def test04_serialise_from_custom(self):
        firewall_rule = FirewallRule()
        self.assertIsInstance(firewall_rule, FirewallRule)
        
        self._set_properties(firewall_rule)
        
        et_firewall_rule = ETreeFirewallRule()
        firewall_rule_elem = et_firewall_rule.create_elem(firewall_rule)
        
        self.assertIsInstance(firewall_rule_elem, ET.Element)
        
        log.debug(ET.tostring(firewall_rule_elem))
        
if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()