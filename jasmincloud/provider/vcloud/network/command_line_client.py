"""JASMIN Cloud

JASMIN Cloud Provider Interface package - command line client for Edge Gateway
interface
"""
__author__ = "P J Kershaw"
__date__ = "24/03/14"
__copyright__ = "(C) 2014 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__revision__ = "$Id$"
import os
import logging
import argparse
import getpass
import xml.etree.ElementTree as ET

from jasmincloud.provider.vcloud.network.client import EdgeGatewayClient


log = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(
                        description='vCloud Director Edge Gateway interface')
    
    parser.add_argument('--config-file', '-f', dest='config_filepath',
                        help='Path to Configuration file which sets connection '
                             'parameters and which command to execute.')
    
    parser.add_argument('--log-level', '-l', dest='log_level', 
                        help='Set log level for output to stdout.  Choose one '
                        'of %r, default is silent mode.' % 
                            [logging.getLevelName(i) 
                             for i in range(logging.DEBUG, 
                                            logging.CRITICAL+1, 
                                            10)])
    
    args = parser.parse_args()
    
    if args.log_level is not None:
        logging.basicConfig(format='%(asctime)s %(message)s', 
                            level=logging.getLevelName(args.log_level))
    
    if args.config_filepath is None:
        raise SystemExit('Error: no configuration file set.%s%s' % 
                         (os.linesep, parser.format_help()))
     
    edgegateway_clnt = EdgeGatewayClient.from_settings_file(
                                                        args.config_filepath)
    
    global_settings = edgegateway_clnt.settings[
                                            EdgeGatewayClient.SETTINGS_GLOBAL]
    
    if global_settings['password'] is None:
        # Prompt for password from command line if not set in settings file
        global_settings['password'] = getpass.getpass(
                                            'Enter password for user %r: ' % 
                                            global_settings['username'])
                                                   
    # Connect to vCloud Director service
    edgegateway_clnt.connect_from_settings()
    
    # Check actions to execute from settings file section - allow one connection
    # section followed by an action section - first filter out connect section
    action_name = None
    for section_name in list(edgegateway_clnt.settings.keys()):
        if section_name != EdgeGatewayClient.SETTINGS_GLOBAL:
            action_name = section_name
            break
    
    # Retrieving the current configuration settings applies to all actions
    edgegateway_configs = edgegateway_clnt.get_config(
                                    vdc_name=global_settings['vdc_name'],
                                    names=global_settings['edgegateway_name'])
    
    if action_name is None:
        # Default to display the current configuration
        print((ET.tostring(edgegateway_configs[0]._elem)))
        
    elif action_name == EdgeGatewayClient.SETTINGS_ROUTE_HOST:
        settings = edgegateway_clnt.settings[action_name]
        
        # NAT host IP from VDC to outside
        edgegateway_clnt.set_host_routing(edgegateway_configs[0],
                                          settings['iface_name'], 
                                          settings['internal_ip'], 
                                          settings['external_ip'])
        
        result = edgegateway_clnt.post_config(edgegateway_configs[0])
        
    elif action_name == EdgeGatewayClient.SETTINGS_RM_NAT_RULES:
        settings = edgegateway_clnt.settings[action_name]
        
        # Remove NAT rules by identifier
        edgegateway_clnt.remove_nat_rules(edgegateway_configs[0],
                                          settings['nat_rule_ids'])
        
        result = edgegateway_clnt.post_config(edgegateway_configs[0])
        log.debug(ET.tostring(result._elem))
        
    elif action_name == EdgeGatewayClient.SETTINGS_CANCEL_TASKS:
        settings = edgegateway_clnt.settings[action_name]
        
        # Purge tasks waiting to be executed
        result = edgegateway_clnt.cancel_tasks(edgegateway_configs[0],
                                               task_uris=settings['task_uris'])

       
        
if __name__ == '__main__':
    main()
    