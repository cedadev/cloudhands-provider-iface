"""JASMIN Cloud

JASMIN Cloud Provider Interface package - utility functions for converting
variables
"""
__author__ = "P J Kershaw"
__date__ = "24/03/14"
__copyright__ = "(C) 2014 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__revision__ = "$Id$"
import keyword
import re

try:
    from configparser import SafeConfigParser
    
except ImportError:
    from ConfigParser import SafeConfigParser


is_iterable = lambda obj: getattr(obj, '__iter__', False)
is_bool = lambda val: val.lower() in ('true', 'false')
bool2str = lambda val: str(val).lower()


def infer_type_from_str(val):
    '''Attempt to convert a string to its correct equivalent type by checking
    its content.
    
    :ivar val: string to be converted
    :type val: basestring
    :return: infered value
    :rtype: basestring / long / bool or float  
    '''
    if is_bool(val):
        return bool(val)
    
    # Try for an integer
    try:
        return int(val)
 
    except ValueError:
        # Check for floating point number
        try:
            return float(val)
        
        except ValueError:
            # Default to string
            return val


def mk_valid_varname(name):
    '''Make a valid Python variable name from XML element attributes
    
    :ivar name: XML variable name to be converted
    :type name: basestring
    :return: equivalent name in lower case with underscores
    :rtype: basestring
    '''
    if not isinstance(name, str):
        return None
    
    varname = camelcase2underscores(re.sub('[^0-9a-zA-Z_]', '_', name))

    # Avoid reserved names
    if keyword.iskeyword(varname):
        varname += '_'
        
    return varname


def camelcase2underscores(varname):
    '''Convert camel case variable names to underscore equivalent
    
    :ivar varname: camel case variable name to be converted
    :type varname: basestring
    :return: equivalent name in lower case with underscores
    :rtype: basestring
    '''
    to_underscores_name = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', varname)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', to_underscores_name).lower()


class CaseSensitiveConfigParser(SafeConfigParser):
    '''
    Subclass the SafeConfigParser - to preserve the original string case of the
    cfg section names - NB, the RawConfigParser default is to lowercase these 
    by default
    '''
    def optionxform(self, optionstr):
        return optionstr
