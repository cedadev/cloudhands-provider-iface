"""JASMIN Cloud

JASMIN Cloud Provider Interface package - module for handling networking 
functionality
"""
__author__ = "P J Kershaw"
__date__ = "24/03/14"
__copyright__ = "(C) 2014 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__revision__ = "$Id$"
from os import path
import logging
import xml.etree.ElementTree as ET

import iptools
from libcloud.compute.providers import Provider, DRIVERS, get_driver
from libcloud.compute.drivers.vcloud import (get_url_path, fixxpath, 
                                             DEFAULT_TASK_COMPLETION_TIMEOUT)

from jasmincloud.provider.vcloud.network.edge_gateway import (NatRule, 
                                                              ETreeNatRule)
from jasmincloud.provider import utils
import jasmincloud.provider.utils.etree as et_utils


log = logging.getLogger(__name__)


def _log_etree_elem(elem, level=logging.DEBUG):
    '''Helper function - Log serialisation of an ElementTree Element'''
    if log.getEffectiveLevel() <= level:
        log.debug(ET.tostring(elem))
                        
    
class EdgeGatewayClientError(Exception):
    '''Generic exception class for EdgeGatewayClient'''
    
    
class EdgeGatewayClientConfigError(EdgeGatewayClientError):
    '''Error with configuration of client request'''
    

class EdgeGatewayResponseParseError(EdgeGatewayClientError):
    '''Error parsing response from vCD web server'''
    

class EdgeGatewayRequestedResourcesInUseError(EdgeGatewayClientError):
    '''A resource such as an IP address has been requested which is unavailable
    because it is already in use'''
    

class EdgeGatewayClientResourceNotFound(EdgeGatewayClientError):
    '''Requested resource not found in Edge Gateway configuration retrieved'''
    
    
class EdgeGatewayClient(object):
    '''Retrieve, parse and update vCloud Edge Device configuration
    
    Edge Gateways provide organisational VDCs with routed connections to the 
    outside
    :cvar SETTINGS_SECTION_NAME: section in config file to read parameters from
    - applies to from_settings_file classmethod only
    ''' 
    VCD_XML_NS = et_utils.VCD_XML_NS
    
    SETTINGS_GLOBAL = 'EdgeGatewayClient'
    SETTINGS_ADD_FIREWALL_RULES = 'EdgeGatewayClient.add_firewall_rules'
    SETTINGS_RM_FIREWALL_RULES = 'EdgeGatewayClient.remove_firewall_rules'
    SETTINGS_ROUTE_HOST = 'EdgeGatewayClient.set_host_routing'
    SETTINGS_RM_NAT_RULES = 'EdgeGatewayClient.remove_nat_rules'
    SETTINGS_CANCEL_TASKS = 'EdgeGatewayClient.cancel_tasks'
    
    SETTINGS_SECTION_NAMES = (
        SETTINGS_GLOBAL,
        SETTINGS_ADD_FIREWALL_RULES,
        SETTINGS_RM_FIREWALL_RULES,
        SETTINGS_ROUTE_HOST,
        SETTINGS_RM_NAT_RULES
    ) 

    VCD_API_VERS = '5.5'
    DEFAULT_PORT = 443
           
    # VDC Edge Gateway discovery related terms        
    LINK_TAG = 'Link'
    LINK_ATTR_TAG = 'href'
    REL_ATTR_TAG = 'rel'
    EDGE_GATEWAYS_LINK_REL = 'edgeGateways' 
    EDGE_GATEWAY_REC_TAG = 'EdgeGatewayRecord'   
    CONFIG_EDGE_GATEWAY_REL = 'edgeGateway:configureServices'    
    GATEWAY_IFACE_TAG = 'GatewayInterface'
    
    def __init__(self):
        self.driver = None
        self.settings = {}

    @classmethod
    def from_connection(cls, *arg, **kwarg):
        '''Instantiate and make a connection to the vCD API'''
        obj_ = cls()
        obj_.connect(*arg, **kwarg)
        
        return obj_     
           
    @classmethod
    def from_settings_file(cls, settings_filepath):
        '''Instantiate from settings in a configuration file
        '''
        obj_ = cls()
        obj_.parse_settings_file(settings_filepath)
                
        return obj_
       
    def connect(self, username, password, hostname, port=DEFAULT_PORT, 
                api_version=VCD_API_VERS):
        '''Create vCloud driver and authenticated connection'''
        
        # Need this explicit check to workaround bug in libcloud vCD driver
        # If no password is set, it's omitted from the argument list such
        # the argument order is shuffled up.  The hostname gets set to the port
        # number!
        if password is None:
            raise TypeError('Password not set')
        
        driver_cls = get_driver(Provider.VCLOUD)
        self.driver = driver_cls(username, password, host=hostname,
                                 api_version=api_version, port=port)
     
    def connect_from_settings(self):
        '''Connect using settings read from config file'''
        settings = self.settings[self.__class__.SETTINGS_GLOBAL]
        
        self.connect(settings['username'], settings['password'], 
                     settings['hostname'], port=settings['port'], 
                     api_version=settings['api_version'])
           
    def parse_settings_file(self, settings_filepath):
        '''Get settings needed for initialising the vCD driver from a config
        file
        '''
        cls = self.__class__
        cfg = utils.CaseSensitiveConfigParser()
        
        if not path.exists(settings_filepath):
            raise IOError('Configuration file not found %r' % settings_filepath)
        
        cfg.read(settings_filepath)
        
        for section_name in cfg.sections():
            if section_name == cls.SETTINGS_GLOBAL:
                if cfg.has_option(section_name, 'driver_path'):
                    driver_path = cfg.get(section_name, 'driver_path')
                else:
                    driver_path = None

                if cfg.has_option(section_name, 'password'):
                    password = cfg.get(section_name, 'password')
                else:
                    password = None
                    
                self.settings[section_name] = {
                    'driver_path': driver_path,
                    'username':  cfg.get(section_name, 'username'),
                    'password':  password,
                    'hostname':  cfg.get(section_name, 'hostname'),
                    'port':  cfg.getint(section_name, 'port'),
                    'api_version':  cfg.get(section_name, 'api_version'),
                    'cacert_filepath': cfg.get(section_name, 'cacert_filepath'),
                    'verify_ssl_certs': cfg.getboolean(section_name, 
                                                       'verify_ssl_certs'),
                    'vdc_name': cfg.get(section_name, 'vdc_name'),
                    'edgegateway_name': cfg.get(section_name, 
                                                'edgegateway_name')
                }
                if self.settings[section_name]['driver_path']:
                    driver_path = self.settings[section_name]['driver_path']
                    DRIVERS[Provider.VCLOUD] = tuple(driver_path.rsplit('.', 1))

                if self.settings[section_name]['verify_ssl_certs'] == False:
                    # This will switch off verification of the server's identity
                    # potentially allowing credentials to be passed to an
                    # unauthenticated 3rd party.  Make sure you know what you 
                    # doing!
                    from libcloud import security
                    security.VERIFY_SSL_CERT = False
                
            elif section_name == cls.SETTINGS_ADD_FIREWALL_RULES:
                firewall_settings = {}
                
                if cfg.has_option(section_name, 'rule_id'): 
                    firewall_settings['rule_id'] = cfg.getint(section_name, 
                                                              'rule_id')
                    
                if cfg.has_option(section_name, 'rule_is_enabled'): 
                    firewall_settings['rule_is_enabled'] = cfg.getboolean(
                                                            section_name, 
                                                            'rule_is_enabled')
                    
                if cfg.has_option(section_name, 'match_on_translate'): 
                    firewall_settings['match_on_translate'] = cfg.getboolean(
                                                        section_name, 
                                                        'match_on_translate')
                    
                if cfg.has_option(section_name, 'description'): 
                    firewall_settings['description'] = cfg.get(section_name, 
                                                              'description')
                    
                if cfg.has_option(section_name, 'policy'): 
                    firewall_settings['policy'] = cfg.get(section_name,
                                                          'policy')
                    
                if cfg.has_option(section_name, 'protocols'): 
                    protocols = cfg.get(section_name, 'protocols').split()
                    
                    for protocol in protocols:
                        k, v = protocol.split(':')
                        firewall_settings['protocols'][k.strip()
                                                       ] = v.strip().strip(',')
                    
                if cfg.has_option(section_name, 'port'): 
                    firewall_settings['port'] = cfg.getint(section_name, 
                                                           'port')
                    
                if cfg.has_option(section_name, 'dest_port_range'): 
                    firewall_settings['dest_port_range'] = cfg.getint(
                                                              section_name, 
                                                              'dest_port_range')
                    
                if cfg.has_option(section_name, 'dest_ip'): 
                    firewall_settings['dest_ip'] = cfg.get(section_name, 
                                                           'dest_ip')
                    
                if cfg.has_option(section_name, 'src_port'): 
                    firewall_settings['src_port'] = cfg.getint(section_name, 
                                                              'src_port')
                    
                if cfg.has_option(section_name, 'src_port_range'): 
                    firewall_settings['src_port_range'] = cfg.getint(
                                                            section_name, 
                                                            'src_port_range')
                    
                if cfg.has_option(section_name, 'src_ip'): 
                    firewall_settings['src_ip'] = cfg.get(section_name, 
                                                          'src_ip')
                    
                if cfg.has_option(section_name, 'direction'): 
                    firewall_settings['direction'] = cfg.get(section_name, 
                                                             'direction')
                    
                if cfg.has_option(section_name, 'enable_logging'): 
                    firewall_settings['enable_logging'] = cfg.getboolean(
                                                            section_name, 
                                                            'enable_logging')
                
                self.settings[section_name] = firewall_settings
                
            elif section_name == cls.SETTINGS_RM_FIREWALL_RULES:
                self.settings[section_name] = {
                    'firewall_rule_ids': [
                        int(i.strip())
                        for i in cfg.get(section_name, 
                                         'firewall_rule_ids').split(',')
                        ]
                }                
            elif section_name == cls.SETTINGS_ROUTE_HOST:
                self.settings[section_name] = {
                    'iface_name': cfg.get(section_name, 'iface_name'),
                    'internal_ip': cfg.get(section_name, 'internal_ip'),
                    'external_ip': cfg.get(section_name, 'external_ip'),
                }
                
            elif section_name == cls.SETTINGS_RM_NAT_RULES:
                self.settings[section_name] = {
                    'nat_rule_ids': [
                        int(i.strip())
                        for i in cfg.get(section_name, 
                                         'nat_rule_ids').split(',')
                        ]
                }
            elif section_name == cls.SETTINGS_CANCEL_TASKS:
                if cfg.has_option(section_name, 'task_uris'):
                    task_uris_ = cfg.get(section_name, 'task_uris').split(',')
                    self.settings[section_name] = {
                        'task_uris': [i.strip() for i in task_uris_]
                    }
                else:
                    self.settings[section_name] = {'task_uris': None}
        
    def get_config(self, vdc_name=None, names=None):
        '''Retrieve configurations for each Edge Gateway in a given 
        Organisational VDC
        
        :param vdc_name: name of VDC to retrieve Edge Gateway configurations for
        :param names: names of the Edge Gateway configurations to retrieve. If
        none given, retrieve all the ones found
        '''
        if vdc_name is not None:
            vdc_id = self.get_vdc_uri(vdc_name)
            if vdc_id is None:
                raise EdgeGatewayClientConfigError('No VDC found with requested'
                                                   ' name %r' % vdc_name)
        else:
            # Default to the first ID found in the returned list
            vdc_id = self.driver.vdcs[0].id
            
        # Find out the Edge Gateway URIs for this VDC
        edgegateway_uri = self.get_vdc_edgegateways_uri(vdc_id)
        
        # Resolve to retrieve the Edge Gateway Records
        edgegateway_recs = self.get_edgegateway_recs(edgegateway_uri)
        
        edgegateway_configs = []
        if names is None:
            edgegateway_configs = [self._get_edgegateway_from_uri(
                                                    edgegateway_rec.href)
                                   for edgegateway_rec in edgegateway_recs]
        else:
            edgegateway_configs = [self._get_edgegateway_from_uri(
                                                    edgegateway_rec.href)
                                   for edgegateway_rec in edgegateway_recs 
                                   if edgegateway_rec.name in names]
                
        return edgegateway_configs

    def post_config(self, gateway, timeout=DEFAULT_TASK_COMPLETION_TIMEOUT,
                    cancel_after_timeout=False):
        '''Despatch updated Edge Gateway configuration
        
        :param gateway: new configuration to posted to the Edge Gateway
        '''
        update_uri = self._get_edgegateway_update_uri(gateway)
        
        gateway_service_config_xml = ET.tostring(
                gateway.configuration.edge_gateway_service_configuration._elem)
        
        res = self.driver.connection.request(get_url_path(update_uri),
                                             method='POST',
                                             data=gateway_service_config_xml)
        if res.status < 200 or res.status >= 300:
            log.error('Error sending Edge Gateway configuration to %r: %r:',
                      update_uri, ET.tostring(res.object))
            
        response = et_utils.obj_from_elem_walker(res.object)
        
        self.driver._wait_for_task_completion(response.href,
                                              timeout=timeout)
        if cancel_after_timeout:
            log.info('Task cancelled following timeout')
            
        return response

    def cancel_tasks(self, gateway, task_uris=None):
        '''Cancel queued tasks
        
        '''
        if not hasattr(gateway, 'tasks'):
            return []
        
        if task_uris is None:
            task_uris = [task.href for task in gateway.tasks.task]
        
        try:    
            for task_uri in task_uris:
                self.driver.connection.request(task_uri + '/action/cancel',
                                               method='POST')
        except Exception as e:
            log.error('Error cancelling task %r:', task_uri)
            for line in ET.tostringlist(e.args[0]):
                log.error(line)
            raise
        
        return task_uris
                            
    def _get_elems(self, uri, xpath):
        '''Helper method - Get XML elements from a given URI and XPath search 
        over returned XML content
        
        :var uri: URI to retrieve XML response from
        :var xpath: XPath to search returned XML content with.  It can contain
        the {} delimited namespace or else the default vCloud one is assumed
        :return: ElementTree Element contain search results
        '''
        res = self.driver.connection.request(get_url_path(uri))
        _log_etree_elem(res.object)
        if xpath.startswith(et_utils.NS_START_DELIM):
            return res.object.findall(xpath)
        else:
            return res.object.findall(fixxpath(res.object, xpath))
    
    def get_vdc_uri(self, vdc_name):
        '''Match VDC URI to input name
        
        :return: VDC URI or None if not found
        '''
        for vdc in self.driver.vdcs:
            if vdc.name == vdc_name:
                return vdc.id
            
    def get_vdc_edgegateways_uri(self, vdc_uri):
        '''Get VDC Edge Gateways query URI for the Given VDC URI'''
        for link in self._get_elems(vdc_uri, self.__class__.LINK_TAG):
            rel_tag = link.get(self.__class__.REL_ATTR_TAG)
            
            if rel_tag == self.__class__.EDGE_GATEWAYS_LINK_REL:
                return link.get(self.__class__.LINK_ATTR_TAG)
           
    def get_edgegateway_recs(self, edgegateway_uri):
        '''Retrieve Edge Gateway Records from the Edge Gateway query URI
        '''
        res = self.driver.connection.request(get_url_path(edgegateway_uri))
        _log_etree_elem(res.object)

        edgegateway_rec_elems = res.object.findall(
            fixxpath(res.object, self.__class__.EDGE_GATEWAY_REC_TAG))
        
        edgegateway_recs = [et_utils.obj_from_elem_walker(edgegateway_rec_elem)
                            for edgegateway_rec_elem in edgegateway_rec_elems]
                   
        return edgegateway_recs
    
    def _get_edgegateway_from_uri(self, edgegateway_rec_uri):
        res = self.driver.connection.request(get_url_path(edgegateway_rec_uri))
        _log_etree_elem(res.object)
        
        gateway = et_utils.obj_from_elem_walker(res.object)
        
        # Augment gateway object with explicit reference to ElementTree elem
        #gateway._elem = res.object
        
        return gateway

    @staticmethod
    def get_ip_range_list(gateway, iface_name):
        '''Get the range of IPs for a given Gateway Interface
        
        :param gateway: gateway configuration
        :param iface_name: gateway interface name
        :return: iptools.IpRangeList
        '''
        gateway_ifaces = \
                    gateway.configuration.gateway_interfaces.gateway_interface
                    
        for gateway_iface in gateway_ifaces:
            if gateway_iface.name.value_ == iface_name:
                
                # Check that an IP range has been set
                if not hasattr(gateway_iface.subnet_participation, 'ip_ranges'):
                    raise EdgeGatewayClientResourceNotFound(
                            'No IP Range set for Edge Gateway interface %r' %
                            iface_name)
                
                # Parser may have allocated a scalar or list for IP range
                # setting
                if isinstance(
                        gateway_iface.subnet_participation.ip_ranges.ip_range,
                        list):
                    ip_ranges = \
                        gateway_iface.subnet_participation.ip_ranges.ip_range
                else:
                    ip_ranges = [
                        gateway_iface.subnet_participation.ip_ranges.ip_range]
                
                return iptools.IpRangeList(
                        *tuple([(i.start_address.value_, i.end_address.value_)
                                for i in ip_ranges]))

    @classmethod
    def _get_edgegateway_update_uri(cls, gateway):
        '''Find update endpoint from returned gateway content
        '''
        for link in gateway.link:
            if link.rel == cls.CONFIG_EDGE_GATEWAY_REL:
                return link.href

    @staticmethod
    def _get_edgegateway_iface_uri(gateway, iface_name):
        ''''Get Edge Gateway interface URI
        
        :param iface_name: name of network interface that you want to retrieve
        URI for
        :return: interface URI
        '''
        for iface in gateway.configuration.gateway_interfaces.gateway_interface:
            if iface.name.value_ == iface_name:
                return iface.network.href
    
    @classmethod
    def set_host_routing(cls, gateway, iface_name, internal_ip, external_ip):
        '''Update Edge Gateway with new routing of internal to external IP
        '''
        # Get the Edge Gateway update endpoint
        update_uri = cls._get_edgegateway_update_uri(gateway)
        if update_uri is None:
            raise EdgeGatewayResponseParseError('No Gateway update URI found '
                                                'in Gateway response')
            
        # Check allocation of external IPs - query allowed range
        ip_range_list = cls.get_ip_range_list(gateway, iface_name)
        if external_ip not in ip_range_list:
            raise EdgeGatewayClientConfigError('Target external IP %r is not '
                                               'in the allowed range for the '
                                               'Gateway interface %r: %r' %
                                               (external_ip, iface_name,
                                                ip_range_list))

        iface_uri = cls._get_edgegateway_iface_uri(gateway, iface_name)
        if iface_uri is None:
            raise EdgeGatewayResponseParseError('Interface found with name %r' % 
                                                iface_name)

        # Check rule IDs already allocated and allocate a new one based on an 
        # increment of the highest value currently in use
        highest_nat_rule_id = 0
        nat_service = \
            gateway.configuration.edge_gateway_service_configuration.nat_service
        for nat_rule in nat_service.nat_rule:
            if nat_rule.id.value_ > highest_nat_rule_id:
                highest_nat_rule_id = nat_rule.id.value_
                
        next_nat_rule_id = highest_nat_rule_id + 1 # may be able to omit

        # Check external IP is not already used in an existing rule
        # TODO: should this necessarily be a fatal error?
        used_nat_rules = [
            nat_rule 
            for nat_rule in nat_service.nat_rule 
            if (external_ip in (nat_rule.gateway_nat_rule.original_ip.value_, 
                                nat_rule.gateway_nat_rule.translated_ip.value_))
        ]
        if len(used_nat_rules) > 0:
            raise EdgeGatewayRequestedResourcesInUseError(
                        'Required external IP address %r has already been '
                        'used in an existing NAT rule ids %r' %
                        (external_ip, [i.id.value_ for i in used_nat_rules]))
        
        # Source NAT rule
        snat_rule = NatRule(rule_type=ETreeNatRule.SRC_RULE_TYPE,
                            rule_id=str(next_nat_rule_id),
                            rule_is_enabled=True,
                            iface_uri=iface_uri,
                            iface_name=iface_name,
                            orig_ip=internal_ip,
                            transl_ip=external_ip)
        
        # Destination NAT rule
        next_nat_rule_id += 1
        dnat_rule = NatRule(rule_type=ETreeNatRule.DEST_RULE_TYPE,
                            rule_id=str(next_nat_rule_id),
                            rule_is_enabled=True,
                            iface_uri=iface_uri,
                            iface_name=iface_name,
                            orig_ip=external_ip,
                            transl_ip=internal_ip)
        
        cls.add_nat_rules(gateway, snat_rule, dnat_rule)
        
        _log_etree_elem(gateway._elem)
    
    @classmethod
    def add_nat_rules(cls, gateway, *arg):
        '''Add new NAT rules to Edge Gateway Configuration ElementTree
        
        :param gateway: gateway object contains _elem attribute which is the
        root of the Gateway Configuration ElementTree
        '''
        # NAT rules can be added as an argument list or a single argument which
        # is a list
        if len(arg) == 0:
            raise TypeError('add_nat_rules expects at least 2 arguments, got 1')

        elif len(arg) == 1 and utils.is_iterable(arg):
            nat_rules = arg[0]
            
        else:
            nat_rules = arg
            
        nat_service = gateway.configuration.\
            edge_gateway_service_configuration.nat_service
            
        # Input Gateway may have not had any NAT rules allocated to it 
        # previously
        if not hasattr(nat_service, 'nat_rule'):
            nat_service.nat_rule = []
            
        ns = et_utils.get_namespace(gateway._elem)
        
        for nat_rule in nat_rules:
            nat_service._elem.append(ETreeNatRule(ns=ns).create_elem(nat_rule))
            nat_service.nat_rule.append(nat_rule)
    
    @classmethod
    def remove_nat_rules(cls, gateway, nat_rule_ids):
        '''Remove NAT one or more rules from Edge Gateway Configuration 
        ElementTree instance *and* from gateway object
        
        :param gateway: gateway object contains _elem attribute which is the
        root of the Gateway Configuration ElementTree
        :param firewall_rule_ids: list of identifiers for rules to be removed
        '''
        nat_service = gateway.configuration.\
            edge_gateway_service_configuration.nat_service
            
        nat_rules_del = [
            nat_rule for nat_rule in nat_service.nat_rule
            if nat_rule.id.value_ in nat_rule_ids
        ]
            
        if len(nat_rules_del) == 0:
            raise EdgeGatewayClientResourceNotFound('No NAT rules ids found '
                                                    'matching selected list %r ' 
                                                    % nat_rule_ids)
        
        # Remove ElementTree Element
        for nat_rule in nat_rules_del:
            nat_service._elem.remove(nat_rule._elem)
        
        # Remove NATRule_ object from NatService_.NatRule_ list
        gateway.configuration.\
                edge_gateway_service_configuration.nat_service.nat_rule = [                                                  
            nat_rule for nat_rule in nat_service.nat_rule 
            if nat_rule not in nat_rules_del
        ]
        _log_etree_elem(gateway._elem)
    
    @classmethod
    def add_firewall_rules(cls, gateway, *arg):
        '''Add one or more Firewall rules to Edge Gateway Configuration 
        ElementTree
        
        :param gateway: gateway object contains _elem attribute which is the
        root of the Gateway Configuration ElementTree
        '''
        # NAT rules can be added as an argument list or a single argument which
        # is a list
        if len(arg) == 0:
            raise TypeError('add_firewall_rules expects at least 2 arguments, '
                            'got 1')

        elif len(arg) == 1 and utils.is_iterable(arg):
            firewall_rules = arg[0]
            
        else:
            firewall_rules = arg
            
        firewall_service = gateway.configuration.\
            edge_gateway_service_configuration.firewall_service
            
        # Input Gateway may have not had any firewall rules allocated to it 
        # previously
        if not hasattr(firewall_service, 'firewall_rule'):
            firewall_service.firewall_rule = []
            
        ns = et_utils.get_namespace(gateway._elem)
        
        for firewall_rule in firewall_rules:
            firewall_service._elem.append(ETreeNatRule(ns=ns).create_elem(
                                                                firewall_rule))
            firewall_service.firewall_rule.append(firewall_rule)

    @classmethod
    def remove_firewall_rules(cls, gateway, firewall_rule_ids):
        '''Remove firewall rules from Edge Gateway Configuration ElementTree
        instance *and* from gateway object
        
        :param gateway: gateway object contains _elem attribute which is the
        root of the Gateway Configuration ElementTree
        :param firewall_rule_ids: list of identifiers for rules to be removed
        '''
        firewall_service = gateway.configuration.\
            edge_gateway_service_configuration.firewall_service
            
        firewall_rules_del = [
            firewall_rule for firewall_rule in firewall_service.firewall_rule
            if firewall_rule.id.value_ in firewall_rule_ids
        ]
            
        if len(firewall_rules_del) == 0:
            raise EdgeGatewayClientResourceNotFound('No firewall rules ids '
                                                    'found matching selected '
                                                    'list %r ' 
                                                    % firewall_rule_ids)
        
        # Remove ElementTree Element
        for firewall_rule in firewall_rules_del:
            firewall_service._elem.remove(firewall_rule._elem)
        
        # Remove FirewallRule_ object from FirewallService_.FirewallRule_ list
        gateway.configuration.edge_gateway_service_configuration.\
                                            firewall_service.firewall_rule = [ 
            firewall_rule for firewall_rule in firewall_service.firewall_rule 
            if firewall_rule not in firewall_rules_del
        ]
        _log_etree_elem(gateway._elem)
        