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
-------------------
     i.Configure vlan type driver on the OpenStack Controller node
       as below, along with the vxlan type driver

       In /etc/neutron/plugins/ml2/ml2_conf.ini,
  
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

    Note: bridge created in Step 1 and bridge given in bridge_mappings
          as in 2.iii should be the same.
          physical network given in 2.ii and 2.iii should be same on 
          the controller node
    

3. Driver Installation
----------------------
    a. On the controller node, copy the Extreme  ML2 Mech driver folder 
    'extremenet' from networking_extreme/plugins/ml2/drivers to 
    /usr/lib/python2.7/site-packages/neutron/plugins/ml2/drivers/

    Note: Replace 'site-packages' with 'dist-packages' for Debian/Ubuntu hosts   

    b. Add class path and driver name in entry_point.txt                                                                         
       file path: 
       /usr/lib/python2.7/site-packages/neutron-X.X.X-py2.7.egg-info/entry_points.txt

    c. Add below at the tail under [neutron.ml2.mechanism_drivers] section
        extremenet_mech = 
           neutron.plugins.ml2.drivers.extremenet.driver:ExtremeNetMechanismDriver

    d. Configure extremenet_mech and openvswitch mech drivers in ml2_conf.ini's 
        mechanism_drivers config section as
          mechanism_drivers = extremenet_mech,openvswitch

    e. Setup the ML2 DB table as below
       1. cd /usr/lib/python2.7/site-packages/neutron/db/migration
       2. alembic revision -m "add extreme_l2_mappings"
             step 2 will generate one file at path 
             /usr/lib/python2.7/site-packages/neutron/db/migration/alembic_migrations/versions

       3. append following contents to this generated file 
          (DO NOT REMOVE ANY OTHER THINGS FROM THAT FILE EXCEPT upgrade and downgrade functions):

              from sqlalchemy import CheckConstraint
              from sqlalchemy import ForeignKey

              def upgrade():
                  op.create_table(
                     'extreme_l2_mappings',
                  sa.Column('vlan_id', sa.Integer, sa.CheckConstraint('vlan_id' < 4096), primary_key=True, unique=True, autoincrement=False),
                  sa.Column('network_id', sa.String(255), sa.ForeignKey('networks.id'), nullable=False, unique=True),
                  sa.Column('original_netname', sa.String(255), nullable=False))


              def downgrade():
                  op.drop_table('extreme_l2_mappings')


       4. Run upgrade with following command on the Controller node
             neutron-db-manage --config-file /etc/neutron/neutron.conf upgrade current


4. Driver Configuration
------------------------
   On Controller node, configure Extreme Management Center server access details
   and configuration in /etc/neutron/plugins/ml2/ml2_conf.ini’s 
   ml2_extreme section as below
  
   [ml2_extreme]
   #Extreme Management Center IP Address
   #emc_ip=<Extreme Management Center-IP>
   #Extreme Management Center port - Default : 8443
   #emc_port=<server-port>

   # HTTP Scheme - Default : https
   #scheme=<http/https>
   #Extreme Management Center username - Default : root
   #emc_username=<emc username>
   #Extreme Management Center password
   #emc_passwd=<emc password>
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
   # Role for Network node switch port
   # 'None',if no Neutron gateway is deployed
   #role=<Name of the Role configured on Network nodes Switch ports>
   #Example
   #role=None
   #OR
   #role="Openstack Controller"

   # Delay between Extreme Management Center REST API calls
   #api_processing_delay=<delay in secs>
  
   Restart neutron-server on the controller node and ovs-agent on 
     all the openstack nodes

   On Controller node,
   #service neutron-server restart
   #service neutron-openvswitch-agent restart

   On compute nodes,
   #service neutron-openvswitch-agent restart
