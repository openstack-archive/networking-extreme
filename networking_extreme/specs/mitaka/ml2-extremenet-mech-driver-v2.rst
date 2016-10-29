=================================================================
Extreme ML2 Mechanism Driver Enhancements V2
=================================================================

Launchpad blueprint:

https://blueprints.launchpad.net/networking-extreme/+spec/ml2-extreme-mechanism-driver-v2

Purpose of the blueprint is to add following enhancements to the current Extreme ML2 mechanism driver

 1. Updates for EMC v 7.0.5
 2. Assistance to VLAN type networks 
 3. Include the Neutron allocated segmentation-id in the EndSystemGroup name
 4. ML2 DB table to track created/deleted EndSystemGroups


Problem description
===================

Current Extreme ML2 Mechanism driver works with Extreme Management Center 
version 6.4.0. 

Goal of this blueprint is to enhance ML2 Mechanism driver
to work with EMC v 7.0.5.


Proposed change
===============

Extreme ML2 Mechanism driver will be enhanced to support updated version of 
Extreme Manager Center(EMC) version 7.0.5.

Extreme Networks Extreme Management Center® provides a rich set of integrated
management capabilities for centralized visibility and highly efficient 
anytime, anywhere control of enterprise wired and wireless network resources.

Management Center is distinguished by its web-based, unified control 
interface. Graphical and exceptionally easy-to-use, Management Center 
simplifies troubleshooting, help desk support tasks, problem-solving and 
reporting. Its Control interface provides specialized visibility and control
for managed and unmanaged devices connecting to the network.

Management Center's granularity reaches beyond ports, VLANs, and SSIDs down to 
individual users, applications, and protocols. Management Center increases 
efficiency, enabling IT staff to avoid time-consuming manual device-by-device 
configuration tasks. Management Center fills the functionality gap between 
traditional element managers that offer limited vendor-specific device control
and expensive, complex enterprise management applications.

REST Client will be enhanced to integrate with the EMC v 7.0.5.

A DB table will be added to the Neutron database to track the EndSystemGroups
that are created/deleted in correspondence to the Neutron networks created/deleted.

Assistance to VLAN type networks will be added.

Alternatives
------------

None.

Data Model impact
-----------------

Adds a new DB table into the Neutron Database
with following model :

|
| **extreme_l2_mappings**


+------------------+--------------+------+-----+---------+-------+
| Field            | Type         | Null | Key | Default | Extra |
+==================+==============+======+=====+=========+=======+
| vlan_id          | int(11)      | NO   | PRI | NULL    |       |
+------------------+--------------+------+-----+---------+-------+
| network_id       | varchar(255) | NO   | UNI | NULL    |       |
+------------------+--------------+------+-----+---------+-------+
| original_netname | varchar(255) | NO   |     | NULL    |       |
+------------------+--------------+------+-----+---------+-------+

vlan_id is the segmentation_id for VLAN type networks and dynamic 
VLANID allocated for a VxLAN type network.

network_id is the Neutron network UUID and is the foreign key from 
Neutron "Networks" table.

original_netname is the Neutron network name given during creation.


REST API impact
---------------

None.

Security impact
---------------

None.

Notifications impact
--------------------

None.

Other end user impact
---------------------

None.

Performance Impact
------------------

The performance of ML2 when configured with the ExtremeNet 
mechanism driver will be dependent on the performance of the link 
between Neutron and the Extreme Networks Management Center and on the 
responsiveness of the Extreme Networks Management Center itself.

Other deployer impact
---------------------

The deployer should configure the installation to use the 
Extreme Networks Management Center with the following configuration variables:

* IP address, port number and scheme of the Extreme Networks Management Center.
* Username and password to login to the Extreme Networks Management Center.
* NAC configuration and Policy domain.
* Role defined for the Network node traffic reception.

Also, the deployer must configure the ML2 plugin to include the 
openvswitch mechanism driver after the ExtremeNet mechanism driver:


::

  [ml2]
  mechanism_drivers = extremenet_mech,openvswitch

Developer impact
----------------

None.


Implementation
==============

Assignee(s)
-----------


Work Items
----------

1. Neutron DB table to track EndSystemsGroups created/deleted for corresponding 
     Neutron Networks.
2. REST Client enhancements to the Extreme Networks Management Center v 7.0.5.
3. Integration.


Dependencies
============

There are no new library requirements. Third party libraries will 
be used as needed.


Testing
=======

* Network and port creation/deletion/update events will be validated.  
* Scenarios where Extreme Networks Management Center is not reachable will be 
  validated.


Documentation Impact
====================

Configuration steps will be documented.


References
==========

1. https://specs.openstack.org/openstack/neutron-specs/specs/kilo/ml2-hierarchical-port-binding.html
2. http://specs.openstack.org/openstack/neutron-specs/specs/juno/ml2-type-driver-refactor.html
3. https://extranet.extremenetworks.com/downloads/Pages/dms.ashx?download=d746e26d-0006-4842-abfb-761cb790d5e6
4. https://blueprints.launchpad.net/networking-extreme/+spec/ml2-extreme-mechanism-driver
