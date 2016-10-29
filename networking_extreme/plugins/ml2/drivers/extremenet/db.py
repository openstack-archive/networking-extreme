"""extreme_l2_mappings DB Model."""
# Copyright 2016 Extreme Networks.
#
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
# ML2 Mech Driver Version : 1.0


from neutron.db import api as db_api

from neutron.db import model_base
from oslo_log import log
import sqlalchemy as sa


LOG = log.getLogger(__name__)


class Extreme_l2_mappings(model_base.BASEV2):
    """Defines extreme_l2_mappings table model."""

    __tablename__ = 'extreme_l2_mappings'
    vlan_id = sa.Column(
        'vlan_id', sa.Integer, sa.CheckConstraint('vlan_id' < 4096),
        primary_key=True, autoincrement=False)
    network_id = sa.Column(
        'network_id', sa.String(255), sa.ForeignKey('networks.id'),
        nullable=False, unique=True)
    original_netname = sa.Column(
        'original_netname', sa.String(255), nullable=False)


def add_row_to_extreme_l2_mappings(vlan_id, network_id, netname):
    """Add a row into the extreme_l2_mappings."""
    LOG.debug("add_row_to_extreme_l2_mappings called "
              "for network %(network)s with "
              "%(vlan_id)d  and network id %(net_id)s", {'network': netname,
                                                         'vlan_id': vlan_id,
                                                         'net_id': network_id})

    session = db_api.get_session()
    with session.begin(subtransactions=True):
        new_mapping = Extreme_l2_mappings(vlan_id=vlan_id,
                                          network_id=network_id,
                                          original_netname=netname)
        session.add(new_mapping)
        LOG.debug("Added new entry added for "
                  "network %(network)s with %(vlan_id)d"
                  " and network id %(net_id)s", {'network': netname,
                                                 'vlan_id': vlan_id,
                                                 'net_id': network_id})


def get_row_from_extreme_l2_mappings(network_id):
    """Retrieve row by network_id from extreme_l2_mappings."""
    session = db_api.get_session()
    rows = (session.query(Extreme_l2_mappings).filter_by(
        network_id=network_id))
    if rows.count() != 0:
        return rows
    return None


def get_extreme_l2_mapping_by_vlan_id(vlan_id):
    """Get extreme_l2_mapping row by VLANID."""
    session = db_api.get_session()
    rows = (session.query(Extreme_l2_mappings).filter_by(vlan_id=vlan_id))
    return rows.count()


def delete_row_from_extreme_l2_mappings(vlan_id):
    """Delete row from extreme_l2_mappings."""
    LOG.debug("Delete called for %(vlan_id)d", {'vlan_id': vlan_id})
    session = db_api.get_session()
    rows = (session.query(Extreme_l2_mappings).filter_by(vlan_id=vlan_id))
    if rows.count() != 0:
        session.query(Extreme_l2_mappings).filter_by(vlan_id=vlan_id).delete()
        LOG.debug("Deleted entry for %(vlan_id)d", {'vlan_id': vlan_id})
    else:
        LOG.debug("Delete from db called but NO entry "
                  "found for %(vlan_id)d", {'vlan_id': vlan_id})
