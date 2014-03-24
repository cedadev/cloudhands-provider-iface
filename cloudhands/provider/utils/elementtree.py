"""JASMIN Cloud

Cloudhands Provider Interface package - ElementTree utilities
"""
__author__ = "P J Kershaw"
__date__ = "24/03/14"
__copyright__ = "(C) 2014 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__revision__ = "$Id$"
from cloudhands.provider import utils


# Take away ElementTree added namespace from a tag and return the tag name alone
strip_ns_from_tag = lambda tagname: tagname.rsplit('}')[-1]

# Given an ElementTree element instance, return the tag name minus its namespace
# prefix 
get_tagname = lambda elem: strip_ns_from_tag(elem.tag)

# Return the namespace for a given ElementTree Element
get_namespace = lambda elem: elem.tag[1:].split("}", 1)[0]

# Given a namespace and tag name make an ElementTree style tag
mk_tag = lambda namespace, tagname: "{%s}%s" % (namespace, tagname)


CLASS_NAME_SUFFIX = '_'
XML_ELEM_VARNAME = 'value_'

def obj_from_elem_walker(elem):
    '''Dynamically creates classes corresponding to ElementTree elements and 
    instantiates objects with attributes based on the element's attributes.
    This function navigates a whole tree recursively calling itself.  Classes
    are named corresponding to the XML element names but with a trailing
    underscore to indicate that their special status.  This can be overridden
    by changing ``CLASS_NAME_SUFFIX``.  XML elements are made into objects
    of dynamic classes.  If the element is assigned a value, this is given the 
    object attribute name ``value_`` (See ``XML_ELEM_VARNAME``).
    
    :var elem: ``xml.etree.ElementTree.Element``
    :return: object of dynamically created class corresponding to ElementTree
    Elements
    '''
    
    # Make a class with the same name as the XML element and instantiate.
    # Trailing underscore flags that this class was created dynamically
    _cls = type(get_tagname(elem) + CLASS_NAME_SUFFIX, (object,), {})
    _obj = _cls()
    
    # Add the XML element's attributes as attributes of the new Python
    # object
    for attrname, attrval in elem.attrib.items():
        # Make a valid variable name from XML attribute name -
        # et_get_tagname() call strips out ElementTree namespace specifier
        # where needed
        varname = mk_valid_varname(strip_ns_from_tag(attrname))
        if varname is not None:
            setattr(_obj, varname, utils.infer_type_from_str(attrval))
    
    # Check for a text setting for the XML element, if present add its
    # content as a new variable 'value_'
    if elem.text is not None:
        elem_text = elem.text.strip()
        if elem_text:
            setattr(_obj, XML_ELEM_VARNAME, utils.infer_type_from_str(elem_text))
        
    # Go to the next levels in XML hierarchy recursively adding further
    # child objects to _obj
    for child_elem in elem:
        
        # Check for duplicate element names - if so make an array of items
        if len(elem.findall(child_elem.tag)) > 1:
            # More than one XML child element of the same name is present
            
            # Create a Python variable name for it
            varname = camelcase2underscores(get_tagname(child_elem))
            
            # Check to see if the current object already has an attribute
            # with this name
            var = getattr(_obj, varname, None)
            if var is not None:
                # List variable already exists - append to it
                var.append(obj_from_elem_walker(child_elem))
            else:
                # List variable doesn't exist - create it and populate with
                # first element
                setattr(_obj, 
                        varname, 
                        [obj_from_elem_walker(child_elem)])
        else:
            # Only one XML child element exists with this name
            setattr(_obj, 
                    camelcase2underscores(get_tagname(child_elem)), 
                    obj_from_elem_walker(child_elem))
        
    return _obj 
