"""JASMIN Cloud

JASMIN Cloud Provider Interface package - module for handling networking 
functionality
"""
__author__ = "P J Kershaw"
__date__ = "11/06/14"
__copyright__ = "(C) 2014 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__revision__ = "$Id$"
import logging
import xml.etree.ElementTree as ET

from libcloud.compute.providers import Provider, get_driver


import jasmincloud.provider.utils.etree as et_utils


log = logging.getLogger(__name__)


def _log_etree_elem(elem, level=logging.DEBUG):
    '''Helper function - Log serialisation of an ElementTree Element'''
    if log.getEffectiveLevel() <= level:
        log.debug(ET.tostring(elem))
        

class UserAdminClientError(Exception):
    '''Base class for vCloud User Administration client exceptions'''
    

class UserAdminRoleAlreadyGranted(UserAdminClientError):
    '''vCloud User Administration client - user already has the role specified
    '''
    
    
class UserAdminClient(object):
    '''
    Client to vCloud Director user administration functions
    '''

    VCD_API_VERS = '5.5'
    DEFAULT_PORT = 443

    def __init__(self):
        self.driver = None
        self.hostname = None
        self.settings = {}

    @classmethod
    def from_connection(cls, *arg, **kwarg):
        '''Instantiate and make a connection to the vCD API'''
        obj_ = cls()
        obj_.connect(*arg, **kwarg)
        
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
        self.hostname = hostname
        
        
     
    def connect_from_settings(self):
        '''Connect using settings read from config file'''
        settings = self.settings[self.__class__.SETTINGS_GLOBAL]
        
        self.connect(settings['username'], settings['password'], 
                     settings['hostname'], port=settings['port'], 
                     api_version=settings['api_version'])
    
    def get_userinfo(self, vdc_name=None):
        '''Get account information for a given registered user'''
        if vdc_name is not None:
            user_uri = "https://%s/api/admin/org/%s/users" % (self.hostname,
                                                              vdc_name)
        else:
            # Assume admin uri
            user_uri = "https://%s/api/admin/users" % self.hostname
            
        res = self.driver.connection.request(user_uri)
        _log_etree_elem(res.object)
        
        return et_utils.obj_from_elem_walker(res.object)
        
    def grant_userrole(self, user_id, role_name, vdc_name=None):
        '''Grant specified user the given role'''
        if vdc_name is not None:
            user_uri = "https://%s/api/admin/org/%s/users" % (self.hostname,
                                                              vdc_name)
        else:
            # Assume admin uri
            user_uri = "https://%s/api/admin/users" % self.hostname

        user_info = self.get_user_info(vdc_name=vdc_name)
        
        # Check user doesn't already have the specified role
        roles = getattr(user_info.user, 'role', [])
        for role in roles:
            if role == role_name:
                raise UserAdminRoleAlreadyGranted('User %r already has the '
                                                  'role %r' % (user_id, 
                                                               role_name))
                
        # Add the specified role name
        res = self.driver.connection.request(user_uri, method='POST')
        _log_etree_elem(res.object)
        