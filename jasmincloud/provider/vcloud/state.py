'''
Created on Apr 15, 2014

@author: philipkershaw
'''

"""Settings for object states within vCloud Director - applies to VApp
templates, VApps and VMs

:param MAP: map of states, dict items are: code, message, and booleans for 
the last three items.  The first is set to true if it applies to VApp
templates, the second set to true for VApps, the last for VMs.

See VMware documentation: 

http://pubs.vmware.com/vcloud-api-1-5/wwhelp/wwhimpl/js/html/wwhelp.htm#context=vCloudAPI&file=GUID-843BE3AD-5EF6-4442-B864-BCAE44A51867.html
"""
VCD_STATE_MAP = {
    'COULD_NOT_BE_CREATED':
        (-1, 'The object could not be created.', True, True, True), 
    'UNRESOLVED':
        (0, 'The object is unresolved.', True, True, True), 
    'RESOLVED':
        (1, 'The object is resolved.', True, True, True), 
    'DEPLOYED':
        (2, 'The object is deployed.', False, False, False),
    'SUSPENDED': 
        (3, 'The object is suspended.', False, True, True),
    'POWERED_ON':
        (4, 'The object is powered on.', False, True, True),
    'WAITING_USER_INPUT': 
        (5, 'The object is waiting for user input.', False, True, True),
    'UNKNOWN': 
        (6, 'The object is in an unknown state.', True, True, True),
    'UNRECOGNISED':
        (7, 'The object is in an unrecognized state.', True, True, True),
    'POWERED_OFF': 
        (8, 'The object is powered off.', True, True, True), 
    'INCONSISTENT':
        (9, 'The object is in an inconsistent state.', False, True, True),
    'CHILDREN_HAVE_DIFFERENT_STATUSES': 
        (10, 'Children do not all have the same status.', True, True, 
         False), 
    'UPLOAD_INITD_OVF_DESCR_PENDING':
        (11, 'Upload initiated, OVF descriptor pending.', True, False, 
         False), 
    'UPLOAD_INITD_CP_CONTENTS':
        (12, 'Upload initiated, copying contents.', True, False, False),
    'UPLOAD_INITD_DISK_CONTENTS_PENDING': 
        (13, 'Upload initiated, disk contents pending.', True, False, 
         False), 
    'UPLOAD_QUARANTINED':
        (14, 'Upload has been quarantined.', True, False, False), 
    'UPLOAD_QUARANTINE_PERIOD_EXPIRED':
        (15, 'Upload quarantine period has expired.', True, False, False)
}


VCloudState = type('VCloudState', (object,),
                   dict([(k, v[:2]) for k, v in list(VCD_STATE_MAP.items())]))

VAppTemplateState = type('VAppTemplateState', (object,),
                         dict([(k, v[:2]) 
                               for k, v in list(VCD_STATE_MAP.items()) 
                               if v[2]]))

VAppState = type('VAppState', (object,),
                 dict([(k, v[:2]) for k, v in list(VCD_STATE_MAP.items()) 
                       if v[3]]))

VmState = type('VmState', (object,),
               dict([(k, v[:2]) for k, v in list(VCD_STATE_MAP.items()) 
               if v[4]]))
    
displ_cls_vars = lambda cls: ["%s = %s" % (k, v) 
                              for k, v in list(cls.__dict__.items()) 
                              if not k.startswith('_')] 
 
def print_cls_vars(cls):
    print(('%r' % cls))
    for i in list(displ_cls_vars(cls)):
        print(i)
          

from libcloud.compute.drivers.vcloud import VCloud_1_5_NodeDriver
from libcloud.compute.types import NodeState

node_state_ = dict([(v, k) for k, v in list(NodeState.__dict__.items()) 
                              if not k.startswith('_')])

def display_vcd2libcloud_mapping(cls):
    node_state = VCloud_1_5_NodeDriver.NODE_STATE_MAP

    print('VCD State    libcloud State')
    print(('='*30))
    for k, v in list(cls.__dict__.items()): 
        if not k.startswith('_'):
            libcloud_state = node_state_.get(node_state.get(str(v[0])))
            print(('%s = %s' % (k, libcloud_state)))
        
if __name__ == '__main__':
    print(('%r' % VCD_STATE_MAP))
    print_cls_vars(VAppTemplateState)
    print_cls_vars(VAppState)
    print_cls_vars(VmState)
    
    display_vcd2libcloud_mapping(VAppState)