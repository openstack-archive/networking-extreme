=================================================================
ML2 Mechanism Driver for Extreme Networks XOS Switches
=================================================================

Launchpad blueprint:

https://blueprints.launchpad.net/networking-extreme/+spec/ml2-extreme-mechanism-driver

Purpose of the blueprint is to provide ML2 mechanism driver for the
Extreme Networks Control Center software to enable VxLAN offload 
through Hierarchical port binding on XOS switches with VxLAN support,
like X670-G2 and X770.


Problem description
===================

Usecase:

Neutron ML2 Hierarchical port binding feature coupled with 
Extreme Networks switches support for VxLAN 
encapsulation/decapsulation, compute-nodes/soft switches can 
offload tunneling overhead. This reduces the packet latency 
and enables compute-nodes to achieve line rate throughputs.

Extreme Networks XOS switches can function as
 1. Top-of-rack switch for servers in enterprise and cloud 
    data centers
 2. High-performance 10GbE core switch for a small network
 3. High-performance 10GbE aggregation switch in a traditional 
    three-tiered network
 4. Interconnect switch providing low-latency connections for 
    High-Performance Cluster Computing (HPCC)

This blueprint outlines the approach for the ML2 mechanism driver 
for Extreme Networks Switches within the scope of 
ML2 hierarchical port binding.



Proposed change
===============

ExtremeNet ML2 Mechanism driver is designed to work in conjunction 
with existing mechanism drivers like OVS,Linux bridge etc as per 
the Hierarchical port binding feature. ExtremeNet mech driver binds 
at the top level and facilitates the underlying mech driver to 
complete the port binding with the VLAN type segment allocated by 
Extreme Networks Mech driver. Neutron ML2 “allocate_dynamic_segment” 
API is invoked to allocate the VLAN segment.

Hence VLANs will be used between compute-node and ToRs and VxLANs 
across the switches.
ExtremeNet mechanism driver implements the network and port related 
event notification methods and communicates the relevant events to 
Extreme Networks Control Center software over REST API to enforce 
the configuration within the switch fabric.

ExtremeNet mechanism driver implements following Neutron events
 * Network create/delete
 * Port binding
 * Port create/delete

Extreme Networks Control Center is a single pane management system 
that provides wired/wireless visibility and control from the 
data center to the mobile edge. The intelligence, automation, 
and integration of management software enables the IT organization 
to optimize the efficiency of network operations and reduce total
cost of ownership.

The diagram belows captures how ExtremeNet mechanism driver works 
with Neutron server and communicates with Extreme Networks Control Center  
over REST API within OpenStack Setup.

Flows::

          +–––––––––––––––––––––––––+
          |                         |
          | Neutron Server          |
          | with ML2 Plugin         |
          |                         |
          |          +–––––––––––+  |
  +–––––––+          | ExtremeNet|  |
  |       |          | Mechanism |  |                  +–––––––––––––––––+
  |       |          |  Driver   |  |    REST API      |                 |
  |  +––––+          |           +––+––––––––––––––––––+ Extreme Networks|
  |  |    |          +-----------+  |                  |    Control      |
  |  |    |          |   OVS     |  |                  |     Center      +–––––––+  
  |  |    |          | Mechanism |  |                  |                 |       |
  |  |    |          |   Driver  |  |                  +–––+–––––––––––––+       |
  |  |    +––––––––––+–––––––––––+––+                      |                     |
  |  |                                                     |                     |
  |  |                                                     |                     |
  |  |                                                     |                     |
  |  |                                            +––––––––+––––––––––+          |  
  |  |                                            |                   |          | 
  |  |                                            |  ExtremeNetworks  |          |
  |  |    +–––––––––––+––––––––––––––+   VLAN     |       XOS         |          |
  |  +––––+ L2 Agent  | Open vSwitch +––––––––––––+    Switch #1      |          |
  |       +–––––––––––+––––––––––––––+            |          +––––––––+          |
  |       |                          |            |          | VTEP   +------+   |
  |       |        HOST 1            |            |          +––––––––+      |   |      
  |       |                          |            +–––––––––––––––––––+      |   |
  |       +––––––––––––––––––––––––––+                                       |   |
  |                                                  +–––––––––––––––––––+   |   |
  |                                                  |                   |  V|   |
  |       +––––––––––+–––––––––––––––+               |  ExtremeNetworks  |  X|   |
  +–––––––+ L2 Agent | Open vSwitch  +               |       XOS         |  L|   |
          +––––––––––+–––––––––––––––+               |    Switch #2      |  A|   |
          |                          |               |                   |  N|   |
          |        HOST 2            |    VLAN       |          +––––––––+   |   |
          |                          +–––––––––––––––+          |  VTEP  +---+   |
          +––––––––––––––––––––––––––+               |          +––––––––+       |
                                                     |                   +–––––––+
                                                     +–––––––––––––––––––+








Alternatives
------------

None

Data model impact
-----------------

None

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
between Neutron and the Extreme Networks Control Center and on the 
responsiveness of the Extreme Networks Control Center itself.

Other deployer impact
---------------------

The deployer should configure the installation to use the 
Extreme Networks Control Center with the following configuration variables:
* IP address, port number and scheme of the Extreme Networks Control Center.
* Username and password to login to the Extreme Networks Control Center.
* NAC configuration and Policy domain
* Switch IP,username/password where Network node is connected

Also, the deployer must configure the ML2 plugin to include the 
openvswitch mechanism driver after the ExtremeNet mechanism driver:


::

  [ml2]
  mechanism_drivers = extremenet_mech,cisco_apic

Developer impact
----------------

None.


Implementation
==============

Assignee(s)
-----------


Work Items
----------

1. MechanismDriver network and port event methods implementation
2. REST Client to the Extreme Networks Control Center
3. Integration


Dependencies
============

There are no new library requirements. Third party libraries will 
be used as needed.


Testing
=======

* Network and port creation/deletion events will be validated.  
* Tempest based network and port related tests coverage will 
  be provided.
* Scenarios where Extreme Networks Control Center is not reachable will be 
  validated.


Documentation Impact
====================

Configuration steps will be documented.


References
==========

1. https://specs.openstack.org/openstack/neutron-specs/specs/kilo/ml2-hierarchical-port-binding.html
2. http://specs.openstack.org/openstack/neutron-specs/specs/juno/ml2-type-driver-refactor.html
3. https://extranet.extremenetworks.com/downloads/Pages/dms.ashx?download=d746e26d-0006-4842-abfb-761cb790d5e6
