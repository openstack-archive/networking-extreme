===============================
networking-extreme
===============================

Extreme Networks Service Plugins and ML2 mechanism drivers for Neutron

ML2 mechanism driver is available for the Extreme Networks Control Center 
software to enable VxLAN offload through Hierarchical port binding on 
XOS switches with VxLAN support, like X670-G2 and X770.

* Free software: Apache license
* Source: http://git.openstack.org/cgit/openstack/networking-extreme
* Bugs: http://bugs.launchpad.net/networking-extreme

ML2 Mechanism driver install and configuration
==============================================

1. Setting up openvswitch on all Openstack nodes
---------------------------------------------
    Create a bridge between on the physical interface for data.
       $ovs-vsctl add-br <bridge-name>
       $ovs-vsctl add-port <data-interface>
       $ifconfig <data-interface> 0.0.0.0
       $ifconfig <bridge-name> <data-interface>
      
       Note: "local_ip" in openvswitch-agent.ini or ml2_conf.ini should be 
       same as data-interface IP as applicable to the setup configuration

2. Setup Configuration
-----------------------
     i.Configure vlan type driver on the OpenStack Controller node
       as below, along with the vxlan type driver
       type_drivers =vlan,vxlan
 
    ii.Configure VLAN ranges on the OpenStack Controller node
        In /etc/neutron/plugins/ml2/ml2_conf.ini, add the vlan ranges 
        in ml2_conf_type_vlan section as below

        [ml2_type_vlan]
        network_vlan_ranges = <physnet-name>:<start-vlanid> :<end-vlanid> 

    iii.Configure bridge mappings on all OpenStack nodes as below
        In /etc/neutron/plugins/ml2/openvswitch_agent.ini, modify 
        “bridge_mappings” section as below 
  
        bridge_mappings = <physnet-name>:<bridge-name>

    Note: bridge created in Step 3.a and bridge given in bridge_mappings
          as in 3.b.iii should be the same.
          physical network given in 3.b.ii and 3.b.iii should be same on 
          the controller node
    

3. Driver Installation
----------------------
    On the controller node, copy the Extreme  ML2 Mech driver folder 
    'extremenet' from networking_extreme/plugins/ml2/drivers to 
    /usr/lib/python2.7/site-packages/neutron/plugins/ml2/drivers/

    Note: Replace 'site-packages' with 'dist-packages' for Debian/Ubuntu hosts   

    Add class path and driver name in entry_point.txt                                                                         
       file path: 
       /usr/lib/python2.7/site-packages/neutron-7.X.X-py2.7.egg-info/entry_points.txt
       For Liberty, it is neutron-7.0.1-py2.7.egg-info

    Add below at the tail under [neutron.ml2.mechanism_drivers] section
        extremenet_mech = 
           neutron.plugins.ml2.drivers.extremenet.driver:ExtremeNetMechanismDriver

    Configure extremenet_mech and openvswitch mech drivers in ml2_conf.ini's 
     mechanism_drivers config section as
          mechanism_drivers = extremenet_mech,openvswitch

4. Driver Configuration
------------------------
   On Controller node, configure NetSight server details and Network node 
   switch details in /etc/neutron/plugins/ml2/ml2_conf.ini’s 
   ml2_extreme section as below
  
   [ml2_extreme]
   #NetSight Server IP Address
   #netsight_ip=<server-IP>
   #NetSight Server port - Default : 8443
   #netsight_port=<server-port>

   # HTTP Scheme - Default : https
   #scheme=<http/https>
   #NetSight Server username - Default : root
   #netsight_username=<netsight username>
   #NetSight Server password
   #netsight_passwd=<netsight password>
   #Enable/disable ssl certificate verification
   #ssl_cert_verify=<True/False>

   # NAC Configuration - Default “NAC Configuration”
   #nac_config=<NAC configuration name>
   #Example
   #nac_config="NAC Configuration"
   # Policy Domain - Default “Default Policy Domain”
   #policy_domain=<Policy domain name>
   #Example
   #policy_domain="Default Policy Domain"

   # Switch IP where Network node is connected
   #network_node_switch_ip=<switch IP>
   # Switch port num where Network node is connected
   #network_node_switch_port=<switch phy port>
   # Switch username  - Default : admin
   #switch_username=<username>
   #Switch password
   #switch_password=<password>

   # Delay between NetSight REST API calls
   #api_processing_delay=<delay in secs>
  
   Restart neutron-server on the controller node and ovs-agent on 
     all the openstack nodes

   On Controller node,
   #service neutron-server restart
   #service neutron-openvswitch-agent restart

   On compute nodes,
   #service neutron-openvswitch-agent restart


