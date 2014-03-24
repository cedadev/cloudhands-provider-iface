"""JASMIN Cloud

Cloudhands Provider Interface package - ElementTree utilities
"""
__author__ = "P J Kershaw"
__date__ = "24/03/14"
__copyright__ = "(C) 2014 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__revision__ = "$Id$"
import logging
import xml.etree.ElementTree as ET
from libcloud.compute.providers import Provider, DRIVERS

import cloudhands.providers.utils.elementtree as et_utils

# TODO: Fix location
DRIVERS[Provider.VCLOUD] = (
    "cloudhands.ops.test.functional.cloudclient.vcloud.patch.vcloud",
    "VCloud_5_5_NodeDriver"
)

log = logging.getLogger(__name__)


class GatewayNatRule(object):
    '''Gateway NAT rule'''
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


class EdgeGatewayClient(object): 
    VCD_API_VERS = '5.5'
    DEFAULT_PORT = 443
    
    def __init__(self, api_version=VCD_API_VERS):
        self.driver = None
        self._ns = None
        
    @classmethod
    def connect(cls, username, password, hostname, port=DEFAULT_PORT, **kwarg):
        obj_ = cls(**kwarg)
        
        driver = get_driver(Provider.VCLOUD)
        self.driver = driver(username, password, host=hostname,
                             api_version=api_version, port=port)
        
        return obj_     
              
    def retrieve(self, vdc_id=None):
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
            vdc_id = self.driver.vdcs[0].id
            
        # Find out the Edge Gateway URIs for this VDC
        edgegateway_uris = self._get_vdc_edgegateway_uris(vdc_id)
        
        # Resolve the first to retrieve the Edge Gateway Record
        edgegateway_recs = self._get_edgegateway_rec(edgegateway_uris[0])
        
        # Resolve the Edge Gateway record link to get the Edge Gateway 
        # information
        return self._get_edgegateway_from_uri(edgegateway_recs[0].href)
      
    def _add_nat_rule(self, vdc, internal_ip, external_ip):
        '''Add a new NAT to map from an internal organisation address to an
        external host
        '''
        gateway = self.retrieve()
        self._ns = et_utils.get_namespace(gateway._elem)
        
        log.debug('Current EdgeGateway configuration . . . ')
        _log_etree_elem(gateway._elem)
        
        # Alter the gateway settings adding a new NAT entry
        
#        self._update_edgegateway(gateway)
        
    def _update_edgegateway(self, gateway, iface_name, internal_ip, 
                            external_ip):
        '''Update Edge Gateway with settings provided'''
        
        # Find update endpoint
        update_uri = None
        for link in gateway.link:
            if link.rel == self.__class__.CONFIG_EDGE_GATEWAY_URI:
                update_uri = link.href
                break
            
        if update_uri is None:
            self.fail('No Gateway update URI found in Gateway response')
        
        
        
        # Get the update elements - the update interface expects a 
        # <EdgeGatewayServiceConfiguration/> top-level element
        gateway_service_conf_elem = gateway._elem.find(
                    fixxpath(gateway._elem,
                             self.__class__.EDGE_GATEWAY_SERVICE_CONF_XPATH))
        if gateway_service_conf_elem is None:
            self.fail('No <EdgeGatewayServiceConfiguration/> element found '
                      '<EdgeGateway/> settings returned from service')
            
        # Check allocation of external IPs
        
        # Get interface URI
        iface_uri = None
        for interface in \
                gateway.configuration.gateway_interfaces.gateway_interface:
            if interface.name.value_ == iface_name:
                iface_uri = interface.network.href
                break
            
        if iface_uri is None:
            self.msg('Interface found with name %r' % iface_name)

        # Check rule IDs already allocated
        highest_nat_rule_id = 0
        nat_service = \
            gateway.configuration.edge_gateway_service_configuration.nat_service
        for nat_rule in nat_service.nat_rule:
            if nat_rule.id.value_ > highest_nat_rule_id:
                highest_nat_rule_id = nat_rule.id.value_
                
        next_nat_rule_id = highest_nat_rule_id + 1

        # Check external IP is not already used in an existing rule
        # TODO: should this necessarily be a fatal error?
        for nat_rule in nat_service.nat_rule:
            gw_rule = nat_rule.gateway_nat_rule
            if (external_ip in (gw_rule.original_ip.value_, 
                                gw_rule.translated_ip.value_)):
                self.fail('Required external IP address %r has already been '
                          'used in an existing NAT rule (id %r)' %
                          (external_ip, nat_rule.id.value_))
        
        # Source NAT rule
        snat_rule = NatRule(rule_type=self.__class__.SRC_NAT_RULE_TYPE,
                            rule_id=str(next_nat_rule_id),
                            rule_is_enabled=True,
                            iface_uri=iface_uri,
                            iface_name=iface_name,
                            orig_ip=internal_ip,
                            transl_ip=external_ip)

       
        nat_service_elem = gateway._elem.find(
                    fixxpath(gateway._elem, self.__class__.NAT_SERVICE_XPATH))
        if nat_service_elem is None:
            self.fail('No <NatService/> element found in returned Edge Gateway '
                      'configuration')
            
        nat_service_elem.append(self._create_nat_rule(snat_rule))
        
        # Destination NAT rule
        next_nat_rule_id += 1
        dnat_rule = NatRule(rule_type=self.__class__.DEST_NAT_RULE_TYPE,
                            rule_id=str(next_nat_rule_id),
                            rule_is_enabled=True,
                            iface_uri=iface_uri,
                            iface_name=iface_name,
                            orig_ip=external_ip,
                            transl_ip=internal_ip)
                
        nat_service_elem.append(self._create_nat_rule(dnat_rule))
        
        _log_etree_elem(gateway._elem)
        
        # Despatch updated configuration
        gateway_service_conf_xml = ET.tostring(gateway_service_conf_elem)
        res = self.driver.connection.request(get_url_path(update_uri),
                                             method='POST',
                                             data=gateway_service_conf_xml)
        self.assert_(res)
        _log_etree_elem(res.object)

    def _create_nat_rule(self, nat_rule):   
        '''Create XML for a new NAT rule appending it to the NAT Service element
        '''                                                                       
        nat_rule_elem = ET.Element(et_utils.mk_tag(self._ns, 'NatRule'))
        rule_type_elem = ET.SubElement(nat_rule_elem, et_utils.mk_tag(self._ns, 
                                                                'RuleType'))
        rule_type_elem.text = nat_rule.rule_type
        
        is_enabled_elem = ET.SubElement(nat_rule_elem, 
                                        et_utils.mk_tag(self._ns, 'IsEnabled'))
        is_enabled_elem.text = bool2str(nat_rule.rule_is_enabled)
        
        id_elem = ET.SubElement(nat_rule_elem, et_utils.mk_tag(self._ns, 'Id'))
        id_elem.text = str(nat_rule.rule_id)
        
        gateway_nat_rule_elem = self._create_gateway_nat_rule_elem(
                                                    nat_rule.gateway_nat_rule)
        
        nat_rule_elem.append(gateway_nat_rule_elem)
        
        return nat_rule_elem
    
    def _create_gateway_nat_rule_elem(self, gateway_nat_rule):
        '''Make a NAT Rule gateway interface XML element
        '''
        gateway_nat_rule_elem = ET.Element(et_utils.mk_tag(self._ns, 
                                                     'GatewayNatRule'))
        
        ET.SubElement(gateway_nat_rule_elem,
                      et_utils.mk_tag(self._ns, 'Interface'),
                      attrib={
                         'href': gateway_nat_rule.iface_uri,
                         'name': gateway_nat_rule.iface_name,
                         'type': gateway_nat_rule.iface_uri_type
                      })
        
        orig_ip_elem = ET.SubElement(gateway_nat_rule_elem, 
                                     et_utils.mk_tag(self._ns, 'OriginalIp'))
        orig_ip_elem.text = gateway_nat_rule.orig_ip
        
        orig_port_elem = ET.SubElement(gateway_nat_rule_elem, 
                                       et_utils.mk_tag(self._ns, 'OriginalPort'))
        orig_port_elem.text = gateway_nat_rule.orig_port
        
        transl_ip_elem = ET.SubElement(gateway_nat_rule_elem, 
                                       et_utils.mk_tag(self._ns, 'TranslatedIp'))
        transl_ip_elem.text = gateway_nat_rule.transl_ip
        
        transl_port_elem = ET.SubElement(gateway_nat_rule_elem, 
                                         et_utils.mk_tag(self._ns, 'TranslatedPort'))
        transl_port_elem.text = gateway_nat_rule.transl_port
        
        protocol_elem = ET.SubElement(gateway_nat_rule_elem, 
                                      et_utils.mk_tag(self._ns, 'Protocol'))
        protocol_elem.text = gateway_nat_rule.protocol
        
        return gateway_nat_rule_elem
                   
    def _get_vdc_edgegateway_uris(self, vdc_uri):
        '''Get vDC Edge Gateway URIs'''
        edgegateway_uris = []
        for link in self._get_elems(vdc_uri, "Link"):
            if link.get('rel') == 'edgeGateways':
                edgegateway_uris.append(link.get('href'))
                
        return edgegateway_uris

    def _get_elems(self, uri, xpath):
        '''Get XML elements from a given URI and XPath search over returned XML 
        content
        '''
        res = self.driver.connection.request(get_url_path(uri))
        if xpath.startswith('{'):
            return res.object.findall(xpath)
        else:
            return res.object.findall(fixxpath(res.object, xpath))
           
    def _get_edgegateway_rec(self, edgegateway_uri):
        res = self.driver.connection.request(get_url_path(edgegateway_uri))
        _log_etree_elem(res.object)

        edgegateway_rec_elems = res.object.findall(fixxpath(res.object, 
                                                   "EdgeGatewayRecord"))
        edgegateway_recs = []
        for edgegateway_rec_elem in edgegateway_rec_elems:
            edgegateway_recs.append(et_utils.obj_from_elem_walker(
                                                        edgegateway_rec_elem))
                   
        return edgegateway_recs
    
    def _get_edgegateway_from_uri(self, edgegateway_rec_uri):
        res = self.driver.connection.request(get_url_path(edgegateway_rec_uri))
        _log_etree_elem(res.object)
        
        gateway_iface_elems = res.object.findall(fixxpath(res.object, 
                                                          "GatewayInterface"))
        
        gateway = et_utils.obj_from_elem_walker(res.object)
        
        # Augment gateway object with explicit reference to ElementTree elem
        gateway._elem = res.object
        
        return gateway
