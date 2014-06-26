"""JASMIN Cloud

JASMIN Cloud Provider Interface package - utilities package 
"""
import collections
__author__ = "P J Kershaw"
__date__ = "24/03/14"
__copyright__ = "(C) 2014 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__revision__ = "$Id$"
try:
    from configparser import SafeConfigParser
    
except ImportError:
    from ConfigParser import SafeConfigParser
    
    
class CaseSensitiveConfigParser(SafeConfigParser):
    '''
    Subclass the SafeConfigParser - to preserve the original string case of the
    cfg section names - NB, the RawConfigParser default is to lowercase these 
    by default
    '''
    def optionxform(self, optionstr):
        return optionstr


is_iterable = lambda obj: getattr(obj, '__iter__', False)
