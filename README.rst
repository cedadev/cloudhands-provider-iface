JASMIN Cloud - Cloud Provider Interfaces
========================================
Cloud provider interface package for the JASMIN project (http://jasmin.ac.uk).
It provides client interfaces JASMIN's underlying private cloud which uses
VMware vCloud Director.  It will also provide interfaces to public clouds to 
enabling burst of resources to these external providers.

This package builds on Apache Libcloud extending the baseline of support 
included for vCloud.

Network Interface
=================
The first extension to Apache Libcloud's VCD support is for networking 
configuration.  ``jasmincloud.provider.vcloud.network`` provides support for 
VCD Edge Gateway configuration.  The ``EdgeGatewayClient`` enables:

* listing of current configuration and parsing into dynamically created objects
  and classes derived from the XML structure
* the additional and subtraction of NAT rules including a wrapper to enable
  simple addition of a NAT'ing for a host to an external IP.
   
Command Line Interface
----------------------
A simple command line tool is provided::

    jasmincloud_netclnt -h
    usage: command_line_client.py [-h] [--config-file CONFIG_FILEPATH]
                                  [--log-level LOG_LEVEL]
    
    vCloud Director Edge Gateway interface
    
    optional arguments:
      -h, --help            show this help message and exit
      --config-file CONFIG_FILEPATH, -f CONFIG_FILEPATH
                            Path to Configuration file which sets connection
                            parameters and which command to execute.
      --log-level LOG_LEVEL, -l LOG_LEVEL
                            Set log level for output to stdout. Choose one of
                            ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                            default is silent mode.

The configuration file sets what operations will be executed.  This follows the
standard ini file format used by the Python ``configparser`` package.  The file
must include an ``EdgeGatewayClient`` section::

    [EdgeGatewayClient]
    # Path libcloud vCloud Driver - uses default location if omitted
    #driver_path = 
    username = somebody@vdc_name
    password = pass 
    hostname = fqdn
    port = 443
    api_version = 5.5
    cacert_filepath = <CA Certificate bundle file location>
    verify_ssl_certs = true
    
    # VDC and Edge Gateway name must be identified
    
    # Name of VDC to query
    vdc_name = VDC1
    
    # Names of Edge Gateway configurations to retrieve
    edgegateway_name = EDGEGATEWAY1
    
Note that the password can be omitted in which case, it will be prompted for on
the command line.  With the above configuration, the client tool will print
a copy of the Edge Gateway configuration to ``stdout``.

To set a host routing, add an additional section::

    [EdgeGatewayClient.set_host_routing]
    iface_name = Network1
    internal_ip = 192.168.0.72
    external_ip = 192.168.1.32

This will route the host with an IP of ``192.168.0.72`` with the VDC to an
external IP of ``192.168.1.32`` via the network interface ``Network1``.

To remove NAT rules, add a section as follows (making sure that ONLY it and an
``EdgeGatewayClient`` section are present)::

    [EdgeGatewayClient.remove_nat_rules]
    nat_rule_ids = 12345, 67890
    
The above will remove the NAT rules with ids ``12345`` and``67890`` 
respectively.  The rule ids can be checked by inspecting the content of the 
current Edge Gateway configuration.

