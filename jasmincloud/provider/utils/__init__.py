"""JASMIN Cloud

JASMIN Cloud Provider Interface package - utilities package 
"""
__author__ = "P J Kershaw"
__date__ = "24/03/14"
__copyright__ = "(C) 2014 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__revision__ = "$Id$"
try:
    from configparser import SafeConfigParser
    
except ImportError:
    from ConfigParser import SafeConfigParser

import UserDict


class CaseSensitiveConfigParser(SafeConfigParser):
    '''
    Subclass the SafeConfigParser - to preserve the original string case of the
    cfg section names - NB, the RawConfigParser default is to lowercase these 
    by default
    '''
    def optionxform(self, optionstr):
        return optionstr


is_iterable = lambda obj: getattr(obj, '__iter__', False)


class VettedDict(UserDict.DictMixin):
    """Enforce custom checking on keys and items before addition to a 
    dictionary
    """
    
    def __init__(self, *args):
        """Initialise setting the allowed type or types for keys and items
        
        :param args: two arguments: the first is a callable which filters for 
        permissable keys in this dict, the second sets the type or list of
        types permissable for items in this dict
        :type args: tuple
        """
        if len(args) != 2:
            raise TypeError('__init__() takes 2 arguments, key_filter and '
                            'value_filter (%d given)' % len(args))
        
        # Validation of inputs
        for arg, arg_name in zip(args, ('key_filter', 'value_filter')):
            if not callable(arg):
                raise TypeError('Expecting callable for %r input; got %r' % 
                                (arg_name, type(arg)))

        self.__key_filter, self.__value_filter = args
        
        self.__map = {}
        
    def _verify_kvpair(self, key, val):
        """Check given key value pair and return False if they should be 
        filtered out.  Filter functions may also raise an exception if they
        wish to abort completely
        
        :param key: dict key to check
        :type key: basestring
        :param val: value to check
        :type val: any
        """
        if not self.__key_filter(key):
            return False
        
        elif not self.__value_filter(val):
            return False
        
        else:
            return True
                  
    def __setitem__(self, key, val):
        """Enforce type checking when setting new items
        
        :param key: key for item to set
        :type key: any
        :param val: value to set for this key
        :type val: any
        """       
        if self._verify_kvpair(key, val):
            self.__map[key] = val

    def __getitem__(self, key):
        """Provide implementation for getting items
        :param key: key for item to retrieve
        :type key: any
        :return: value for input key
        :rtype: any
        """
        if key not in self.__map:
            raise KeyError('%r key not found in dict' % key)
        
        return self.__map[key]
    
    def keys(self):
        '''Implementation of keys is required to fulfill dict-like interface
        required
        '''
        return self.__map.keys()