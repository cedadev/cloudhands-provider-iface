"""JASMIN Cloud

JASMIN Cloud Provider Interface package - module for vCloud Director Edge 
Gateway classes
"""
__author__ = "P J Kershaw"
__date__ = "22/05/14"
__copyright__ = "(C) 2014 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__revision__ = "$Id$"
import xml.etree.ElementTree as ET

from jasmincloud.provider.utils import string as string_utils
from jasmincloud.provider.utils import etree as etree_utils
from jasmincloud.provider.utils import VettedDict


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
            raise ValueError('Accepted values for "rule_type" are: ' +
                             repr(self.__class__.RULE_TYPES))

        self._rule_type = val

         
class ETreeNatRule(object):  
    '''Class for creating XML serialisation of NAT Rule using ElementTree'''      

    VCD_XML_NS = etree_utils.VCD_XML_NS

    TAG = 'NatRule'
    TYPE_TAG = 'RuleType'
    SRC_RULE_TYPE = 'SNAT'
    DEST_RULE_TYPE = 'DNAT'
    IS_ENABLED_TAG = 'IsEnabled'
    ID_TAG = 'Id'

    def __init__(self, ns=VCD_XML_NS):
        self._ns = ns
        
    def create_elem(self, nat_rule, ns=VCD_XML_NS):   
        '''Create XML for a new NAT rule appending it to the NAT Service element
        '''            
        cls = self.__class__
                                                                   
        nat_rule_elem = ET.Element(etree_utils.mk_tag(ns, cls.TAG))
        
        rule_type_elem = ET.SubElement(nat_rule_elem, 
                                       etree_utils.mk_tag(ns, cls.TYPE_TAG))
        
        rule_type_elem.text = nat_rule.rule_type
        
        is_enabled_elem = ET.SubElement(nat_rule_elem, 
                                    etree_utils.mk_tag(ns, cls.IS_ENABLED_TAG))
        
        is_enabled_elem.text = string_utils.bool2str(nat_rule.rule_is_enabled)
        
        id_elem = ET.SubElement(nat_rule_elem, 
                                etree_utils.mk_tag(ns, cls.ID_TAG))
                
        id_elem.text = str(nat_rule.rule_id)
        
        
        gateway_nat_rule_elem = ETreeGatewayNatRule(ns=ns).create_elem(
                                                    nat_rule.gateway_nat_rule)
        
        nat_rule_elem.append(gateway_nat_rule_elem)
        
        return nat_rule_elem
    

class ETreeGatewayNatRule(object):
    '''Class for creating XML serialisation of Gateway NAT Rule using
    ElementTree
    '''
    VCD_XML_NS = etree_utils.VCD_XML_NS
            
    TAG = 'GatewayNatRule'
    
    ORIGINAL_IP_TAG = 'OriginalIp'
    ORIGINAL_PORT_TAG = 'OriginalPort'
    TRANSLATED_IP_TAG = 'TranslatedIp'
    TRANSLATED_PORT_TAG = 'TranslatedPort'
    PROTOCOL_TAG = 'Protocol'

    def __init__(self, ns=VCD_XML_NS):
        self._ns = ns
        
    def create_elem(self, gateway_nat_rule):
        '''Make a NAT Rule gateway interface XML element
        '''
        gateway_nat_rule_elem = ET.Element(
                        etree_utils.mk_tag(self._ns, self.__class__.TAG))
        
        ET.SubElement(gateway_nat_rule_elem,
                      etree_utils.mk_tag(self._ns, 'Interface'),
                      attrib={
                         'href': gateway_nat_rule.iface_uri,
                         'name': gateway_nat_rule.iface_name,
                         'type': gateway_nat_rule.iface_uri_type
                      })
        orig_ip_elem = ET.SubElement(
                 gateway_nat_rule_elem, 
                 etree_utils.mk_tag(self._ns, self.__class__.ORIGINAL_IP_TAG))
        
        orig_ip_elem.text = gateway_nat_rule.orig_ip
        
        orig_port_elem = ET.SubElement(
                gateway_nat_rule_elem, 
                etree_utils.mk_tag(self._ns, self.__class__.ORIGINAL_PORT_TAG))
        
        orig_port_elem.text = gateway_nat_rule.orig_port
        
        transl_ip_elem = ET.SubElement(
                gateway_nat_rule_elem, 
                etree_utils.mk_tag(self._ns, self.__class__.TRANSLATED_IP_TAG))
        
        transl_ip_elem.text = gateway_nat_rule.transl_ip
        
        transl_port_elem = ET.SubElement(
            gateway_nat_rule_elem, 
            etree_utils.mk_tag(self._ns, self.__class__.TRANSLATED_PORT_TAG))
        
        transl_port_elem.text = gateway_nat_rule.transl_port
        
        protocol_elem = ET.SubElement(
                gateway_nat_rule_elem, 
                etree_utils.mk_tag(self._ns, self.__class__.PROTOCOL_TAG))
        
        protocol_elem.text = gateway_nat_rule.protocol
        
        return gateway_nat_rule_elem


class FirewallRule(object):
    '''Representation of Edge Gateway configuration Firewall Rule
    
    '''
    POLICY_ALLOW = 'allow'
    POLICY_DROP = 'drop'
    POLICY_VALUES = (POLICY_ALLOW, POLICY_DROP)
    
    DIRECTION_IN = 'in'
    DIRECTION_OUT = 'out'
    DIRECTION_VALUES = (DIRECTION_IN, DIRECTION_OUT)

    ANY_PORT = -1
    ANY_IP = 'Any'
    
    def __init__(self, rule_id=-1, rule_is_enabled=False,
                 match_on_translate=False, description='', policy=POLICY_DROP, 
                 protocols=None, port=ANY_PORT, dest_port_range=ANY_PORT, 
                 dest_ip=ANY_IP, src_port=ANY_PORT, src_port_range=ANY_PORT, 
                 src_ip=ANY_IP, direction=DIRECTION_OUT, enable_logging=False):

        # Initialise protected variables - these have associated properties for
        # getters and setters
        self._rule_is_enabled = None
        self._policy = None
        
        def _type_check(val, type_):
            if not isinstance(val, type_):
                raise TypeError('Expecting %r type got %r' % (type_, val))
            
            return True
        
        self._protocols = VettedDict(lambda k: _type_check(k, basestring), 
                                     lambda v: _type_check(v, bool))
        self._match_on_translate = None
        self._direction = None
        self._enable_logging = None

        self.rule_id = rule_id
        
        self.rule_is_enabled = rule_is_enabled
        
        self.match_on_translate = match_on_translate
        self.description = description
        self.policy = policy
        
        if protocols is not None:
            self.protocols = protocols
            
        self.port = port
        self.dest_port_range = dest_port_range
        self.dest_ip = dest_ip
        self.src_port = src_port
        self.src_port_range = src_port_range
        self.src_ip = src_ip
        self.direction = direction
        self.enable_logging = enable_logging
        
    @property
    def rule_is_enabled(self):
        return self._rule_is_enabled
    
    @rule_is_enabled.setter
    def rule_is_enabled(self, val):
        if not isinstance(val, bool):
            raise TypeError("Expecting bool type for 'rule_is_enabled' got: %r"%
                            type(val)) 
        self._rule_is_enabled = val
    
    @property
    def policy(self):
        return self._policy
    
    @policy.setter
    def policy(self, val):
        if val not in self.__class__.POLICY_VALUES:
            raise ValueError('Accepted values for "policy" are: ' + 
                             repr(self.__class__.POLICY_VALUES))

        self._policy = val
    
    @property
    def protocols(self):
        return self._protocols
    
    @protocols.setter
    def protocols(self, val):
        for k, v in dict(val):
            if not isinstance(v, basestring):
                raise TypeError("Expecting string type for protocol name "
                                "setting; got: %r" % type(val))

            if not isinstance(v, bool):
                raise TypeError("Expecting bool type for protocol enabled "
                                "setting; got: %r" % type(val))
            self._protocols[k] = v
                        
    @property
    def match_on_translate(self):
        return self._match_on_translate
    
    @match_on_translate.setter
    def match_on_translate(self, val):
        if not isinstance(val, bool):
            raise TypeError("Expecting bool type for 'match_on_translate' got: "
                            "%r" % type(val)) 
        self._match_on_translate = val
    
    @property
    def direction(self):
        return self._direction
    
    @direction.setter
    def direction(self, val):
        if val not in self.__class__.DIRECTION_VALUES:
            raise ValueError('Accepted values for "direction" are: ' +
                             repr(self.__class__.DIRECTION_VALUES)) 

        self._direction = val
                
    @property
    def enable_logging(self):
        return self._enable_logging
    
    @enable_logging.setter
    def enable_logging(self, val):
        if not isinstance(val, bool):
            raise TypeError("Expecting bool type for 'enable_logging' got: %r"%
                            type(val)) 
        self._enable_logging = val
        
        
class ETreeFirewallRule(object):
    '''Class for creating XML serialisation of Gateway Firewall Rule using
    ElementTree
    '''
    VCD_XML_NS = etree_utils.VCD_XML_NS
            
    TAG = 'FirewallRule'
    
    IS_ENABLED_TAG = 'IsEnabled'
    MATCH_ON_TRANSLATE_TAG = 'MatchOnTranslate'
    DESCRIPTION_TAG = 'Description'
    POLICY_TAG = 'Policy'
    SRC_PORT_TAG = 'SourcePort'
    SRC_PORT_RANGE_TAG = 'SourcePortRange'
    SRC_IP_TAG = 'SourceIp'
    DEST_PORT_TAG = 'Port'
    DEST_PORT_RANGE_TAG = 'PortRange'
    DEST_IP_TAG = 'DestinationIp'
    PROTOCOLS_TAG = 'Protocols'
    ENABLE_LOGGING_TAG = 'EnableLogging'

    def __init__(self, ns=VCD_XML_NS):
        self._ns = ns
        
    def create_elem(self, firewall_rule):
        '''Make a Firewall Rule gateway interface XML element
        '''
        firewall_rule_elem = ET.Element(
                        etree_utils.mk_tag(self._ns, self.__class__.TAG))
        
        is_enabled_elem = ET.SubElement(
                 firewall_rule_elem, 
                 etree_utils.mk_tag(self._ns, self.__class__.IS_ENABLED_TAG))
        
        is_enabled_elem.text = string_utils.bool2str(
                                                firewall_rule.rule_is_enabled)
        
        descr_elem = ET.SubElement(
                firewall_rule_elem, 
                etree_utils.mk_tag(self._ns, self.__class__.DESCRIPTION_TAG))
        
        descr_elem.text = firewall_rule.description
        
        match_on_translate_elem = ET.SubElement(
            firewall_rule_elem, 
            etree_utils.mk_tag(self._ns, self.__class__.MATCH_ON_TRANSLATE_TAG))
        
        match_on_translate_elem.text = string_utils.bool2str(
                                            firewall_rule.match_on_translate)
        
        policy_elem = ET.SubElement(
                firewall_rule_elem, 
                etree_utils.mk_tag(self._ns, self.__class__.POLICY_TAG))
        
        policy_elem.text = firewall_rule.policy
        
        src_port_elem = ET.SubElement(
                firewall_rule_elem, 
                etree_utils.mk_tag(self._ns, self.__class__.SRC_PORT_TAG))
        
        src_port_elem.text = str(firewall_rule.src_port)
        
        src_port_range_elem = ET.SubElement(
                firewall_rule_elem, 
                etree_utils.mk_tag(self._ns, self.__class__.SRC_PORT_RANGE_TAG))
        
        src_port_range_elem.text = str(firewall_rule.src_port_range)
        
        src_ip_elem = ET.SubElement(
                firewall_rule_elem, 
                etree_utils.mk_tag(self._ns, self.__class__.SRC_IP_TAG))
        
        src_ip_elem.text = firewall_rule.src_ip
                
        dest_port_elem = ET.SubElement(
                firewall_rule_elem, 
                etree_utils.mk_tag(self._ns, self.__class__.DEST_PORT_TAG))
        
        dest_port_elem.text = str(firewall_rule.port)
        
        dest_port_range_elem = ET.SubElement(
            firewall_rule_elem, 
            etree_utils.mk_tag(self._ns, self.__class__.DEST_PORT_RANGE_TAG))
        
        dest_port_range_elem.text = str(firewall_rule.dest_port_range)
        
        dest_ip_elem = ET.SubElement(
                firewall_rule_elem, 
                etree_utils.mk_tag(self._ns, self.__class__.DEST_IP_TAG))
                       
        dest_ip_elem.text = firewall_rule.dest_ip
                
        policy_elem = ET.SubElement(
                firewall_rule_elem, 
                etree_utils.mk_tag(self._ns, self.__class__.POLICY_TAG))
        
        policy_elem.text = firewall_rule.policy
                
        protocols_elem = ET.SubElement(
                firewall_rule_elem, 
                etree_utils.mk_tag(self._ns, self.__class__.PROTOCOLS_TAG))
        
        for protocol, enabled in firewall_rule.protocols.items():
            tag_name = protocol.capitalize()
            protocol_elem = ET.SubElement(protocols_elem, 
                                        etree_utils.mk_tag(self._ns, tag_name))
            
            protocol_elem.text = string_utils.bool2str(enabled)
            
        enable_logging_elem = ET.SubElement(
                firewall_rule_elem, 
                etree_utils.mk_tag(self._ns, self.__class__.ENABLE_LOGGING_TAG))
        
        enable_logging_elem.text = string_utils.bool2str(
                                                firewall_rule.enable_logging)
                
        return firewall_rule_elem
