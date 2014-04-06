"""JASMIN Cloud

Cloudhands Provider Interface package - module for handling networking 
functionality
"""
__author__ = "P J Kershaw"
__date__ = "24/03/14"
__copyright__ = "(C) 2014 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__revision__ = "$Id$"
import logging
import xml.etree.ElementTree as ET

import iptools
from libcloud.compute.providers import Provider, DRIVERS, get_driver
from libcloud.compute.drivers.vcloud import get_url_path, fixxpath

from cloudhands.provider import utils
import cloudhands.provider.utils.elementtree as et_utils


# TODO: Fix location
DRIVERS[Provider.VCLOUD] = (
    "cloudhands.ops.test.functional.cloudclient.vcloud.patch.vcloud",
    "VCloud_5_5_NodeDriver"
)

log = logging.getLogger(__name__)


def _log_etree_elem(elem, level=logging.DEBUG):
    '''Helper function - Log serialisation of an ElementTree Element'''
    if log.getEffectiveLevel() <= level:
        log.debug(ET.tostring(elem))
        

class GatewayNatRule(object):
    '''Representation of Edge Gateway configuration Gateway NAT rule'''
    IFACE_URI_TYPE = "application/vnd.vmware.admin.network+xml"
    DEFAULT_PORT = "any"
    DEFAULT_PROTOCOL = "any"
    
    def __init__(self,
                 iface_uri=None,
                 iface_name=None,
                 iface_uri_type=IFACE_URI_TYPE,
                 orig_ip=None,
                 orig_port=DEFAULT_PORT,
                 transl_ip=None,
                 transl_port=DEFAULT_PORT,
                 protocol=DEFAULT_PROTOCOL):
    
        self.iface_uri = iface_uri
        self.iface_name = iface_name
        self.iface_uri_type = iface_uri_type
        self.orig_ip = orig_ip
        self.orig_port = orig_port
        self.transl_ip = transl_ip
        self.transl_port = transl_port
        self.protocol = protocol
        
        
class NatRule(object):
    '''Representation of Edge Gateway configuration NAT Rule'''
    RULE_TYPES = ('DNAT', 'SNAT')
    
    def __init__(self, rule_type='DNAT', rule_id=None, rule_is_enabled=False,
                 **gateway_nat_rule_kw):
        self.rule_type = rule_type
        self.rule_id = rule_id
        self.rule_is_enabled = rule_is_enabled
        
        self.gateway_nat_rule = GatewayNatRule(**gateway_nat_rule_kw)
    
    @property
    def rule_type(self):
        return self._rule_type
    
    @rule_type.setter
    def rule_type(self, val):
        if val not in self.__class__.RULE_TYPES:
            raise ValueError('Accepted values for "rule_type" are: %r' %
                             self.__class__.RULE_TYPES) 

        self._rule_type = val


class EdgeGatewayClientError(Exception):
    '''Generic exception class for EdgeGatewayClient'''
    
    
class EdgeGatewayClientConfigError(EdgeGatewayClientError):
    '''Error with configuration of client request'''
    

class EdgeGatewayResponseParseError(EdgeGatewayClientError):
    '''Error parsing response from vCD web server'''
    

class EdgeGatewayRequestedResourcesInUseError(EdgeGatewayClientError):
    '''A resource such as an IP address has been requested which is unavailable
    because it is already in use'''
    
    
class EdgeGatewayClient(object):
    '''Retrieve, parse and update vCloud Edge Device configuration
    
    Edge Gateways provide organisational VDCs with routed connections to the 
    outside
    :cvar SETTINGS_FILE_SECTION_NAME: section in config file to read parameters from
    - applies to from_settings_file classmethod only
    ''' 
    SETTINGS_FILE_MK_CON = 'EdgeGatewayClient'
    SETTINGS_FILE_ROUTE_HOST = 'EdgeGatewayClient.route_host'
    SETTINGS_FILE_SECTION_NAMES = (
        SETTINGS_FILE_MK_CON,
        SETTINGS_FILE_ROUTE_HOST
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
    NAT_SERVICE_XPATH = ('Configuration/EdgeGatewayServiceConfiguration/'
                         'NatService')
    EDGE_GATEWAY_SERVICE_CONF_XPATH = \
                        'Configuration/EdgeGatewayServiceConfiguration'
    
    GATEWAY_IFACE_TAG = 'GatewayInterface'
        
    GATEWAY_NAT_RULE_TAG = 'GatewayNatRule'
                 
    # NAT rule configuration
    NAT_RULE_TAG = 'NatRule'
    NAT_RULE_TYPE_TAG = 'RuleType'
    SRC_NAT_RULE_TYPE = 'SNAT'
    DEST_NAT_RULE_TYPE = 'DNAT'
    NAT_RULE_IS_ENABLED_TAG = 'IsEnabled'
    NAT_RULE_ID_TAG = 'Id'
    
    ORIGINAL_IP_TAG = 'OriginalIp'
    ORIGINAL_PORT_TAG = 'OriginalPort'
    TRANSLATED_IP_TAG = 'TranslatedIp'
    TRANSLATED_PORT_TAG = 'TranslatedPort'
    PROTOCOL_TAG = 'Protocol'
    
    def __init__(self):
        self.driver = None
        self._ns = None
        
    @classmethod
    def from_connection(cls, username, password, hostname, port=DEFAULT_PORT, 
                        api_version=VCD_API_VERS, **kwarg):
        '''Instantiate from a connection made to the vCD API'''
        obj_ = cls(**kwarg)
        
        driver_cls = get_driver(Provider.VCLOUD)
        obj_.driver = driver_cls(username, password, host=hostname,
                                 api_version=api_version, port=port)
        
        return obj_     
           
    @classmethod
    def from_settings_file(cls, settings_filepath):
        '''Instantiate from settings in a configuration file
        '''
        settings = cls.parse_settings_file(
                                    settings_filepath, 
                                    section_names=[cls.SETTINGS_FILE_MK_CON])
        
        con_settings = settings[cls.SETTINGS_FILE_MK_CON]
        
        obj_ = cls.from_connection(con_settings.pop('username'), 
                                   con_settings.pop('password'), 
                                   con_settings.pop('hostname'), 
                                   **con_settings)
        
        return obj_
        
    @classmethod
    def parse_settings_file(cls, settings_filepath, section_names=None):
        '''Get settings needed for initialising the vCD driver from a config
        file
        '''
        cfg = utils.CaseSensitiveConfigParser()
        cfg.read(settings_filepath)
        
        if section_names is None:
            section_names = cfg.sections()
            
        settings = {}
        for section_name in section_names:
            if section_name == cls.SETTINGS_FILE_MK_CON:
                settings[section_name] = {
                    'username':  cfg.get(section_name, 'username'),
                    'password':  cfg.get(section_name, 'password'),
                    'hostname':  cfg.get(section_name, 'hostname'),
                    'port':  cfg.getint(section_name, 'port'),
                    'api_version':  cfg.get(section_name, 'api_version'),
                }
            elif section_name == cls.SETTINGS_FILE_ROUTE_HOST:
                settings[section_name] = {
                    'iface_name': cfg.get(section_name, 'iface_name'),
                    'internal_ip': cfg.get(section_name, 'internal_ip'),
                    'external_ip': cfg.get(section_name, 'external_ip'),
                }
        
        return settings
        
    def get_config(self, vdc_id=None, names=None):
        '''Retrieve configurations for each Edge Gateway in a given 
        Organisational VDC
        
        :param names: names of the Edge Gateway configurations to retrieve. If
        none given, retrieve all the ones found
        '''
        if vdc_id is not None:
            vdc_id_found = False
            for vdc in self.driver.vdcs:
                if vdc.id == vdc_id:
                    vdc_id_found = True
                    break
                
            if not vdc_id_found:
                raise EdgeGatewayClientConfigError('No VDC found with requested'
                                                   ' id %r' % vdc_id)
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

        self._ns = et_utils.get_namespace(edgegateway_configs[0]._elem)
        
        return edgegateway_configs

    def post_config(self, gateway_config):
        '''Despatch updated configuration
        
        :param gateway_config: new configuration to posted to the Edge Gateway
        '''
        update_uri = self._get_edgegateway_update_uri(gateway_config)
        
        # Get the update elements - the update interface expects a 
        # <EdgeGatewayServiceConfiguration/> top-level element
        gateway_service_conf_elem = gateway_config._elem.find(
                    fixxpath(gateway_config._elem,
                             self.__class__.EDGE_GATEWAY_SERVICE_CONF_XPATH))
        if gateway_service_conf_elem is None:
            raise EdgeGatewayClientConfigError(
                    'No <EdgeGatewayServiceConfiguration/> element found '
                    '<EdgeGateway/> settings returned from service')
            
        gateway_service_conf_xml = ET.tostring(gateway_service_conf_elem)
        res = self.driver.connection.request(get_url_path(update_uri),
                                             method='POST',
                                             data=gateway_service_conf_xml)

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
        gateway._elem = res.object
        
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
                
                # Parser may have allocated a scalar or list for IP range
                # setting
                n_ip_rge = gateway_iface.subnet_participation.ip_ranges.ip_range
                if len(n_ip_rge) == 1:
                    ip_ranges = [
                        gateway_iface.subnet_participation.ip_ranges.ip_range]
                else:
                    ip_ranges = \
                        gateway_iface.subnet_participation.ip_ranges.ip_range
                
                return iptools.IpRangeList(
                                        [iptools.IpRange(i.start_address.value_,
                                                         i.end_address.value_)
                                         for i in ip_ranges])
            
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
    def _get_gateway_service_conf_elem(cls, gateway):
        '''Get Edge Gateway service configuration element section from parsed
        Edge Gateway configuration
        '''
        
        # Get the update elements - the update interface expects a 
        # <EdgeGatewayServiceConfiguration/> top-level element
        return gateway._elem.find(
                fixxpath(gateway._elem, cls.EDGE_GATEWAY_SERVICE_CONF_XPATH))
    
    @classmethod
    def route_host(cls, gateway, iface_name, internal_ip, external_ip):
        '''Update Edge Gateway with new routing of internal to external IP
        '''
        # Get the Edge Gateway update endpoint
        update_uri = cls._get_edgegateway_update_uri(gateway)
        if update_uri is None:
            raise EdgeGatewayResponseParseError('No Gateway update URI found '
                                                'in Gateway response')
         
        # Edge Gateway service configuration is the element which needs to be 
        # modified and POST'ed in order to make an update
        gateway_service_conf_elem = cls._get_gateway_service_conf_elem(gateway)   
        if gateway_service_conf_elem is None:
            raise EdgeGatewayResponseParseError(
                    'No <EdgeGatewayServiceConfiguration/> element found '
                    '<EdgeGateway/> settings returned from service')

            
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
        for nat_rule in nat_service.nat_rule:
            gw_rule = nat_rule.gateway_nat_rule
            if (external_ip in (gw_rule.original_ip.value_, 
                                gw_rule.translated_ip.value_)):
                raise EdgeGatewayRequestedResourcesInUseError(
                        'Required external IP address %r has already been '
                        'used in an existing NAT rule (id %r)' %
                        (external_ip, nat_rule.id.value_))
        
        # Source NAT rule
        snat_rule = NatRule(rule_type=cls.SRC_NAT_RULE_TYPE,
                            rule_id=str(next_nat_rule_id),
                            rule_is_enabled=True,
                            iface_uri=iface_uri,
                            iface_name=iface_name,
                            orig_ip=internal_ip,
                            transl_ip=external_ip)

       
        nat_service_elem = gateway._elem.find(
                    fixxpath(gateway._elem, cls.NAT_SERVICE_XPATH))
        if nat_service_elem is None:
            raise EdgeGatewayResponseParseError('No <NatService/> element '
                                                'found in returned Edge '
                                                'Gateway configuration')
            
        nat_service_elem.append(cls._create_nat_rule_elem(snat_rule))
        
        # Destination NAT rule
        next_nat_rule_id += 1
        dnat_rule = NatRule(rule_type=cls.DEST_NAT_RULE_TYPE,
                            rule_id=str(next_nat_rule_id),
                            rule_is_enabled=True,
                            iface_uri=iface_uri,
                            iface_name=iface_name,
                            orig_ip=external_ip,
                            transl_ip=internal_ip)
                
        nat_service_elem.append(cls._create_nat_rule_elem(dnat_rule))
        
        _log_etree_elem(gateway._elem)
    
    @classmethod
    def _add_nat_rule_elem(cls, gateway, nat_rule):
        '''Add new NAT rule to Edge Gateway Configuration ElementTree
        
        :param gateway: gateway object contains _elem attribute which is the
        root of the Gateway Configuration ElementTree
        '''
        nat_service_elem = gateway._elem.find(
                                fixxpath(gateway._elem, cls.NAT_SERVICE_XPATH))
        if nat_service_elem is None:
            raise EdgeGatewayResponseParseError('No <NatService/> element '
                                                'found in returned Edge '
                                                'Gateway configuration')
            
        nat_service_elem.append(cls._create_nat_rule_elem(nat_rule))
    
    @classmethod
    def _remove_nat_rule_elem(cls, gateway, nat_rule_id):
        '''Add new NAT rule to Edge Gateway Configuration ElementTree
        
        :param gateway: gateway object contains _elem attribute which is the
        root of the Gateway Configuration ElementTree
        :param nat_rule_id: identifier for rule to be removed
        '''
        nat_service_elem = gateway._elem.find(
                                fixxpath(gateway._elem, cls.NAT_SERVICE_XPATH))
        if nat_service_elem is None:
            raise EdgeGatewayResponseParseError('No <NatService/> element '
                                                'found in returned Edge '
                                                'Gateway configuration')
            
        # Need string representation for matching
        str_nat_rule_id = str(nat_rule_id)

        for elem in list(nat_service_elem):
            if elem.value == str_nat_rule_id:
                break
            
        nat_service_elem.remove(elem)
        
    def _update_edgegateway_service_conf(self, gateway_service_conf_elem,
                                         update_uri):
        '''Despatch updated Edge Gateway service configuration'''
        
        gateway_service_conf_xml = ET.tostring(gateway_service_conf_elem)
        res = self.driver.connection.request(get_url_path(update_uri),
                                             method='POST',
                                             data=gateway_service_conf_xml)
        _log_etree_elem(res.object)

    def _create_nat_rule_elem(self, nat_rule):   
        '''Create XML for a new NAT rule appending it to the NAT Service element
        '''            
        cls = self.__class__
                                                                   
        nat_rule_elem = ET.Element(
                    et_utils.mk_tag(self._ns, cls.NAT_RULE_TAG))
        
        rule_type_elem = ET.SubElement(
                    nat_rule_elem, 
                    et_utils.mk_tag(self._ns, cls.NAT_RULE_TYPE_TAG))
        
        rule_type_elem.text = nat_rule.rule_type
        
        is_enabled_elem = ET.SubElement(
                nat_rule_elem, 
                et_utils.mk_tag(self._ns, cls.NAT_RULE_IS_ENABLED))
        
        is_enabled_elem.text = utils.bool2str(nat_rule.rule_is_enabled)
        
        id_elem = ET.SubElement(
                nat_rule_elem, 
                et_utils.mk_tag(self._ns, cls.NAT_RULE_ID_TAG))
                
        id_elem.text = str(nat_rule.rule_id)
        
        gateway_nat_rule_elem = self._create_gateway_nat_rule_elem(
                                                    nat_rule.gateway_nat_rule)
        
        nat_rule_elem.append(gateway_nat_rule_elem)
        
        return nat_rule_elem
    
    def _create_gateway_nat_rule_elem(self, gateway_nat_rule):
        '''Make a NAT Rule gateway interface XML element
        '''
        gateway_nat_rule_elem = ET.Element(
                        et_utils.mk_tag(self._ns, 
                                        self.__class__.GATEWAY_NAT_RULE_TAG))
        
        ET.SubElement(gateway_nat_rule_elem,
                      et_utils.mk_tag(self._ns, 'Interface'),
                      attrib={
                         'href': gateway_nat_rule.iface_uri,
                         'name': gateway_nat_rule.iface_name,
                         'type': gateway_nat_rule.iface_uri_type
                      })
        orig_ip_elem = ET.SubElement(
                 gateway_nat_rule_elem, 
                 et_utils.mk_tag(self._ns, self.__class__.ORIGINAL_IP_TAG))
        
        orig_ip_elem.text = gateway_nat_rule.orig_ip
        
        orig_port_elem = ET.SubElement(
                gateway_nat_rule_elem, 
                et_utils.mk_tag(self._ns, self.__class__.ORIGINAL_PORT_TAG))
        
        orig_port_elem.text = gateway_nat_rule.orig_port
        
        transl_ip_elem = ET.SubElement(
                gateway_nat_rule_elem, 
                et_utils.mk_tag(self._ns, self.__class__.TRANSLATED_IP_TAG))
        
        transl_ip_elem.text = gateway_nat_rule.transl_ip
        
        transl_port_elem = ET.SubElement(
                gateway_nat_rule_elem, 
                et_utils.mk_tag(self._ns, self.__class__.TRANSLATED_IP_TAG))
        
        transl_port_elem.text = gateway_nat_rule.transl_port
        
        protocol_elem = ET.SubElement(
                gateway_nat_rule_elem, 
                et_utils.mk_tag(self._ns, self.__class__.PROTOCOL_TAG))
        
        protocol_elem.text = gateway_nat_rule.protocol
        
        return gateway_nat_rule_elem

