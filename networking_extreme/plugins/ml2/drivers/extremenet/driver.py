"""ExtremeNet ML2 Mech Driver."""
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
import db
import re as regex
import time
import xml.etree.ElementTree as ET

from collections import OrderedDict
from neutron_lib.api.definitions import portbindings
from oslo_config import cfg
from oslo_log import log
from oslo_serialization import jsonutils

import requests
import six

from enum import Enum

from neutron._i18n import _LE
from neutron._i18n import _LI
from neutron.common import constants
from neutron.common import utils
from neutron.db import api as db_api
from neutron.db import models_v2

from neutron.plugins.ml2 import driver_api as api

from neutron.plugins.ml2.drivers.extremenet import config

EMCNAMESPACE = '{http://ws.web.server.tam.netsight.enterasys.com}return'
HTTP_SUCCESS_RESPONSE_CODES = [requests.codes.ok, requests.codes.created,
                               requests.codes.no_content]

LOG = log.getLogger(__name__)
# Timeout in seconds
REST_API_TIMEOUT = 30

NAC_ES_WS_URL = '{scheme}://{server_ip}:{port}/axis/services/'\
    'NACEndSystemWebService/{service}?'

NAC_CONF_PUSH_URL = '{scheme}://{server_ip}:{port}/fusion_jboss/dwr/jsonp/'\
    'TaskSchedulerService/{service}'

NAC_CONF_WS_URL = '{scheme}://{server_ip}:{port}/axis/services/'\
    'NACConfigurationWebService/{service}?'

POLICY_SERVICE_URL = '{scheme}://{server_ip}:{port}/axis/services/'\
    'PolicyService/{service}?'

NAC_GET_ESG_DESC_URL = '{scheme}://{server_ip}:{port}/fusion_jboss/dwr/'\
    'jsonp/FusionToolkit/{service}/vlan='


OPENVSWITCH_MECH_DRIVER = 'openvswitch'
LINUXBRIDGE_MECH_DRIVER = 'linuxbridge'
EXTREMENET_MECH_DRIVER = 'extremenet_mech'
ESG_PREFIX = 'VNI'
DELIMITER = '-'
EXTREME_ML2_MECH_DRIVER_VERSION = 2.0


class EMCErrorCode(Enum):
    """EMCErrorcode provides error codes and error messages.

    of the NetSight REST API calls

    """

    # This error code indicates success.
    SUCCESS = 0
    # This error indicates that the requested object does not exist.
    NOT_FOUND = 1
    # This error indicates that the action cannot be performed because
    # the object already exists.
    EXISTS = 2
    # This error indicates that a parameter value is invalid
    INVALID_VALUE = 3
    # This error code indicates an error parsing an input string.
    SYNTAX = 4
    # This error code indicates that the result would be an invalid
    # configuration.
    CONFIGURATION = 5
    # This error code is used to report an error using a remote connection.
    REMOTE = 6
    # This error code is a catch-all for an unexpected error condition.
    UNEXPECTED = 7
    # This error code is used to report the group parameter does not exist
    NO_SUCH_GROUP = 8
    # A generic CSV operation error
    CSV_ERROR = 9
    # Connection timed out error code
    CONN_TIMED_OUT = 0XA
    # Http Connection error code
    HTTP_CONN_ERROR = 0xB
    # Unexpected http response or unexpected response from manager
    UNKNOWN_ERROR = 0XC
    # This is the property name for an error string.
    PROPERTY_ERROR_STRING = "errorString"
    # ESG already exists
    PROPERTY_EXISTS_STRING = "already exists"
    # createVirtualAndPhysical API response success criteria
    ESG_SUCCESS_CRITERIA = "End-System Group.*created"
    # Switch API success response
    SUCCESS_STR = "SUCCESS"
    # API unable to aquire lock on domain
    DOMAIN_LOCK_UNAVAILABLE = "Could not acquire domain "
    # removeMACFromEndSystemGroup failed
    DELETE_FROM_DEVICE_FAILED = "Error deleting VLAN(s) from device(s)"


EMCErrorMessages = {
    # This error code indicates success.
    0: "Requested API returned SUCCESS",
    # This error indicates that the requested object does not exist.
    1: "Requested operation did not find object",
    # This error indicates that the action cannot be performed because
    # the object already exists.
    2: "Requested action cannot be performed because"
       " the object already exists ",
    # This error indicates that a parameter value is invalid
    3: "Parameter value provided for requestes API are Invalid",
    # This error code indicates an error parsing an input string.
    4: "Error while parsing input string",
    # This error code indicates that the result would be an invalid
    # configuration.
    5: "Requested API with given input may lead to "
       "invalid configuration",
    # This error code is used to report an error using a remote connection.
    6: "Error while using remote connection",
    # This error code is a catch-all for an unexpected error condition.
    7: "Unexpected error occured",
    # This error code is used to report the group parameter does not exist
    8: "Error : Group parameter does not exists",
    # A generic CSV operation error
    9: "Generic CSV operation error",
    # Connection timed out error code
    0XA: "Error : Connection timed out",
    # Http Connection error code
    0xB: "Error : HTTP connection error",
    # Unexpected http response or unexpected response from manager
    0XC: "Error : Unexpected HTTP response or "
         "unexpected response from manager"
}


class SupportedRestApi(Enum):
    """SupportedRestApi provides constants for the NetSight REST API."""

    # This property name for Creating EndSystemGroup(ESG)
    CREATE_ESG = "createVirtualAndPhysicalNetworkV2"
    # This property name for Removing EndSystemGroup(ESG)
    DELETE_ESG = "removeVirtualAndPhysicalNetwork"
    # This property name for Adding MAC addr to ESG
    ADD_MAC_ESG = "addMACToEndSystemGroup"
    # This property name for deleting MAC addr from ESG
    DELETE_MAC_ESG = "removeMACFromEndSystemGroup"
    # This property name for Enforcing on all NAC Appliances
    NC_ENFORCE_CONFIG = "enforceAllNacAppliances"
    # This property name for SNMP Enfore on the given domain
    NC_ENFORCE_SNMP = "snmpEnforceDomain"
    # This property for adding ESG to Role by name
    NS_ADD_VLAN_TO_ROLE_BY_NAME =\
        "netsightPolicyManagerAddVLANEgressToRoleByName"
    # This property for adding ESG to Role by VLAN Id
    NS_ADD_VLAN_TO_ROLE_BY_VID =\
        "netsightPolicyManagerAddVLANEgressToRoleByVid"
    # This property for getting all esg present in the system
    NS_GET_ALL_NAMED_LISTS = "getAllNamedLists"
    # This property for changing the description of ESG
    NC_WB_UPDATE_DESC = "updateNamedListDescription"
    # This property for getting description as per VLAN id
    NS_GET_DESC_BY_VLAN = "netsightNACGetNamedListByDescription"


class RestClient(object):
    """RestClient provides the NetSight REST API invocation methods.

    All the NetSight REST calls needed for ExtremeNetMechanismDriver are
    implemented within this class.
    """

    @staticmethod
    def _dict_to_query_params(params):
        return '&'.join(
            [str(k) + '=' + str(v) for k, v in six.iteritems(params)])

    @staticmethod
    def _dict_to_path_params(params):
        return '/' + ('/'.join(str(v) for k, v in six.iteritems(params)))

    @staticmethod
    def _process_emc_url(requested_url, api_name, config_params):
        LOG.debug("%(api)s request URL is %(url)s",
                  {'api': api_name,
                   'url': requested_url})
        try:
            response = requests.get(requested_url, timeout=REST_API_TIMEOUT,
                                    auth=(config_params['emc_user_name'],
                                          config_params['emc_passwd']),
                                    verify=config_params['ssl_cert_verify'])

            return response
        except requests.exceptions.Timeout as ex:
            LOG.exception(_LE("REST API %(api)s requested URL %(url)s "
                              "timed out %(reason)s"),
                          {'api': api_name,
                           'url': requested_url,
                           'reason': ex})
            return EMCErrorCode.CONN_TIMED_OUT.value
        except requests.ConnectionError as ex:
            LOG.exception(_LE("REST API %(api)s requested URL %(url)s "
                              "ConnectionError %(reason)s"),
                          {'api': api_name,
                           'url': requested_url,
                           'reason': ex})
            return EMCErrorCode.HTTP_CONN_ERROR.value
        except Exception as ex:
            LOG.exception(_LE("REST API %(api)s requested URL %(url)s "
                              "failed. Reason: %(reason)s"),
                          {'api': api_name,
                           'url': requested_url,
                           'reason': ex})
            return EMCErrorCode.UNKNOWN_ERROR.value

    def get_esg_description_by_vlanid(self, vlan_id, config_params):
        """Get ESG description by vlan id from the EMC."""
        LOG.debug("get_esg_description_by_vlanid called with vlan id"
                  " %(vlan)s ", {'vlan': vlan_id})
        description = None
        get_esg_desc_url = NAC_GET_ESG_DESC_URL.format(
            scheme=config_params['scheme'],
            server_ip=config_params['emc_server_ip'],
            port=config_params['emc_server_port'],
            service=SupportedRestApi.NS_GET_DESC_BY_VLAN.value,
        )
        get_esg_desc_url += str(vlan_id)
        response = self._process_emc_url(
            get_esg_desc_url,
            SupportedRestApi.NS_GET_DESC_BY_VLAN.value,
            config_params
        )
        if response.status_code in HTTP_SUCCESS_RESPONSE_CODES:
            desc = response.content
            desc1 = desc.replace("{ \"reply\":[", "").replace(
                "]}\r\n", "").replace("\"", "")
            desc_list = desc1.split(",")
            if len(desc_list) >= 2:
                description = desc_list[2]
                return description
        else:
            LOG.error(_LE("Unable to get description by VLAN id, response"
                          " code is %(resp)d"), {'resp': response.status_code})
        return description

    def update_description_for_esg(self, esg_name, desc, config_params):
        """Update description for the given ESG."""
        LOG.debug("update_description_for_esg called with ESG : %(esg), "
                  "Description: %(desc)", {'esg': esg_name, 'desc': desc})
        update_desc_url = NAC_ES_WS_URL.format(
            scheme=config_params['scheme'],
            server_ip=config_params['emc_server_ip'],
            port=config_params['emc_server_port'],
            service=SupportedRestApi.NC_WB_UPDATE_DESC.value,
        )
        query_params = OrderedDict([('listName', esg_name),
                                    ('descr', desc)])
        update_desc_url += self._dict_to_query_params(query_params)
        response = self._process_emc_url(
            update_desc_url,
            SupportedRestApi.NC_WB_UPDATE_DESC.value,
            config_params
        )
        return response

    def create_esg(self, vlan, esg_name, config_params):
        """Create EndSystemGroup."""
        es_create_url = NAC_CONF_WS_URL.format(
            scheme=config_params['scheme'],
            server_ip=config_params['emc_server_ip'],
            port=config_params['emc_server_port'],
            service=SupportedRestApi.CREATE_ESG.value)
        query_params = OrderedDict([('name', esg_name),
                                    ('nacConfig', config_params['nac_config']),
                                    ('domain', config_params['policy_domain']),
                                    ('isPrivateVlan', "false"),
                                    ('primaryVlanId', vlan),
                                    ('secondaryVlanId', 0),
                                    ('mode', "promiscuous"),
                                    ('forwardAsTagged', "true"),
                                    ('vlanName', esg_name)])
        es_create_url += self._dict_to_query_params(query_params)
        response = self._process_emc_url(
            es_create_url, SupportedRestApi.CREATE_ESG.value, config_params)
        return response

    def delete_esg(self, esg_name, vlan_id, config_params):
        """Delete the ESG and associated resources.

        within the switch fabric domain

        """
        del_net_url = NAC_CONF_WS_URL.format(
            scheme=config_params['scheme'],
            server_ip=config_params['emc_server_ip'],
            port=config_params['emc_server_port'],
            service=SupportedRestApi.DELETE_ESG.value)
        query_params = OrderedDict([('name', esg_name),
                                    ('primaryVlanId', vlan_id),
                                    ('nacConfig',
                                     config_params['nac_config']),
                                    ('domain',
                                     config_params['policy_domain']),
                                    ('removeEndSystemGroup', "true"), ])
        del_net_url += self._dict_to_query_params(query_params)
        response = self._process_emc_url(
            del_net_url, SupportedRestApi.DELETE_ESG.value, config_params)
        return response

    def ns_enforce_nac_config(self, config_params):
        """EMC API for NAC appliances' enforce."""
        enforce_nac_app_url = NAC_CONF_WS_URL.format(
            scheme=config_params['scheme'],
            server_ip=config_params['emc_server_ip'],
            port=config_params['emc_server_port'],
            service=SupportedRestApi.NC_ENFORCE_CONFIG.value)
        path_params = OrderedDict([('forceMask', 0),
                                   ('ignoreWarnings', "true"), ])
        enforce_nac_app_url += self._dict_to_query_params(path_params)
        response = self._process_emc_url(
            enforce_nac_app_url, SupportedRestApi.NC_ENFORCE_CONFIG.value,
            config_params)
        return response

    def ns_pm_enforce_snmp(self, config_params):
        """EMC API for SNMP Domain enforcement."""
        enforce_domain_url = POLICY_SERVICE_URL.format(
            scheme=config_params['scheme'],
            server_ip=config_params['emc_server_ip'],
            port=config_params['emc_server_port'],
            service=SupportedRestApi.NC_ENFORCE_SNMP.value)
        path_params = OrderedDict([('domainName',
                                    config_params['policy_domain']),
                                   ('wait', "true")])
        enforce_domain_url += self._dict_to_query_params(path_params)
        response = self._process_emc_url(
            enforce_domain_url, SupportedRestApi.NC_ENFORCE_SNMP.value,
            config_params)
        return response

    def add_mac_to_esg(self, mac_addr, host_id, esg_name, config_params):
        """Adds the port MAC to Given EndSystemGroup."""
        add_mac_url = NAC_ES_WS_URL.format(
            scheme=config_params['scheme'],
            server_ip=config_params['emc_server_ip'],
            port=config_params['emc_server_port'],
            service=SupportedRestApi.ADD_MAC_ESG.value)
        query_params = OrderedDict([('endSystemGroup', esg_name),
                                    ('mac', mac_addr),
                                    ('description',
                                     mac_addr + DELIMITER + host_id),
                                    ('reauthorize', "true"),
                                    ('removeFromOtherGroups', "true")])
        LOG.debug("addMACToEndSystemGroup details: MAC address %(mac)s "
                  "added to endSystemGroup %(esg)s, on host %(host)s",
                  {'mac': mac_addr,
                   'esg': esg_name,
                   'host': host_id})

        add_mac_url += self._dict_to_query_params(query_params)
        response = self._process_emc_url(
            add_mac_url, SupportedRestApi.ADD_MAC_ESG.value,
            config_params)
        return response

    def remove_mac_from_esg(self, mac_address, esg_name, config_params):
        """Removes MAC from given EndSystemGroup."""
        delete_port_url = NAC_ES_WS_URL.format(
            scheme=config_params['scheme'],
            server_ip=config_params['emc_server_ip'],
            port=config_params['emc_server_port'],
            service=SupportedRestApi.DELETE_MAC_ESG.value)
        query_params = OrderedDict([('endSystemGroup', esg_name),
                                    ('mac', mac_address),
                                    ('reauthorize', "true")])
        delete_port_url += self._dict_to_query_params(query_params)
        response = self._process_emc_url(
            delete_port_url, SupportedRestApi.DELETE_MAC_ESG.value,
            config_params)

        LOG.debug("remove_mac_from_esg details: Removing MAC %(mac)s "
                  "from ESG %(esg)s",
                  {'esg': esg_name,
                   'mac': mac_address})
        return response

    def add_vlan_egress_to_role(self, esg_name, config_params):
        """Add ESG's VLAN to the given Role."""
        add_esg_to_role_url = NAC_CONF_PUSH_URL.format(
            scheme=config_params['scheme'],
            server_ip=config_params['emc_server_ip'],
            port=config_params['emc_server_port'],
            service=SupportedRestApi.NS_ADD_VLAN_TO_ROLE_BY_NAME.value,
        )
        path_params = OrderedDict([('roleName', config_params['role']),
                                   ('domainName',
                                    config_params['policy_domain']),
                                   ('vlanName', esg_name),
                                   ('forwardAsTagged', "true")])
        add_esg_to_role_url += self._dict_to_path_params(path_params)
        resp = requests.get(add_esg_to_role_url, timeout=REST_API_TIMEOUT,
                            auth=(config_params['emc_user_name'],
                                  config_params['emc_passwd']),
                            verify=config_params['ssl_cert_verify'])

        LOG.debug("addESGToRoleByName details: Adding ESG %(esg)s "
                  "to Role %(role)s",
                  {'esg': esg_name,
                   'role': config_params['role']})
        return resp


class Util(object):
    """Util provides the utility API for the ExtremeNetMechanismDriver.

    to access different Neutron DB tables

    """

    @staticmethod
    def get_network_name(network_id):
        """Retrieve the network name for given network id."""
        session = db_api.get_session()
        rows = (session.query(models_v2.Network).filter_by
                (id=network_id).first())
        return rows['name']


class ExtremeNetMechanismDriver(api.MechanismDriver):
    """ExtremeNetMechanismDriver implements the ML2 MechanismDriver methods.

    for network and port related events to utilize ExtremeNetworks Switches
    VxLAN encapsulation support, coupled with Hierarchical port
    binding feature.

    Communicates with the ExtremeNetworks Extreme Management Center over REST
    API to enforce the network and port configuration within the Switch
    fabric.

    """

    def validate_config_params(self):
        """Validate configured emc_server ip and.

        user name.

        """
        if not self.config_params['emc_server_ip']:
            LOG.error(_LE("Extreme Management Center Switch Manager"
                          " IP not configured"))
        if not self.config_params['emc_user_name']:
            LOG.error(_LE("Extreme Management Center Switch Manager "
                          "user name not configured"))

    def initialize(self):
        """ExtremeNetMechanismDriver init method."""
        LOG.info(_LI("ExtremeNet ML2 Mechanism Driver Version:"
                     " %.1f") % EXTREME_ML2_MECH_DRIVER_VERSION)
        self.mechanism_drivers = cfg.CONF.ml2.mechanism_drivers
        self.config_params = {}

        if len(self.mechanism_drivers) >= 2:
            if self.mechanism_drivers[0] == EXTREMENET_MECH_DRIVER and \
                    self.mechanism_drivers[1] in [LINUXBRIDGE_MECH_DRIVER,
                                                  OPENVSWITCH_MECH_DRIVER]:
                self.config_params = config.get_emc_config()
                LOG.info(_LI("Extreme Management Center configuration"
                             " parameters %s"), self.config_params)
                LOG.info(_LI('Configured Mechanism drivers are %s'),
                         self.mechanism_drivers)
                self.validate_config_params()
            else:
                LOG.error(
                    _LE("Mechanism drivers are misconfigured "
                        "%(mechanismdriver)s Expected config "
                        "extreme_mech, openvswitch/linuxbridge"),
                    {'mechanismdriver': self.mechanism_drivers})
        else:
            LOG.error(
                _LE("Mechanism drivers are misconfigured "
                    "%(mechanismdriver)s Expected config "
                    "extreme_mech, openvswitch/linuxbridge"),
                {'mechanismdriver': self.mechanism_drivers})

    @staticmethod
    def _to_esg_name_format(vni, network_name):
        esg_name = ESG_PREFIX + DELIMITER + str(vni) + \
            DELIMITER + network_name
        return esg_name

    @staticmethod
    def _is_valid_current_context(context, api_str):
        """current may be port context or network context."""
        try:
            if context.current is None:
                LOG.error(_LE("%(api)s: Current context is not available"),
                          {'api': api_str})
                return False

            LOG.debug("%(api)s: Current context is %(port)s",
                      {'api': api_str,
                       'port': context.current})
            return True
        except AttributeError:
            LOG.error(_LE("context.current attribute error for API %(api)s"),
                      {'api': api_str})
            return False

    @staticmethod
    def _is_valid_top_bound_seg(context, api_str):
        try:
            if context.top_bound_segment is None:
                LOG.error(
                    _LE("%(api)s: top_bound_segment is not available"),
                    {'api': api_str})
                return False
            LOG.debug("%(api)s: Top bound segment is %(top)s",
                      {'api': api_str,
                       'top': context.top_bound_segment})
            return True
        except AttributeError:
            LOG.error(_LE("%(api)s: top_bound_segment attribute error"),
                      {'api': api_str})
            return False

    @staticmethod
    def _is_valid_bottom_bound_seg(context, api_str):
        try:
            if context.bottom_bound_segment is None:
                LOG.error(_LE("%(api)s: bottom_bound_segment is "
                              "not available"), {'api': api_str})
                return False
            LOG.debug("%(api)s Bottom bound segment is %(bottom)s",
                      {'api': api_str,
                       'bottom': context.bottom_bound_segment})
            return True
        except AttributeError:
            LOG.error(_LE("%(api)s: bottom_bound_segment attribute error"),
                      {'api': api_str})
            return False

    @staticmethod
    def _process_json_resp(resp, esg_name, rest_api):
        if isinstance(resp, int):
            # HTTP connection timed out and connection error
            LOG.error(_LE("%(api)s: REST API failed with error code "
                          "%(error_code)d"), {'error_code': resp})
            return resp
        if resp is not None and resp.content:
            if resp.status_code in HTTP_SUCCESS_RESPONSE_CODES:
                resp_content = jsonutils.loads(resp.content)
                if resp_content['result'][1]['status'] == \
                        EMCErrorCode.SUCCESS_STR.value and \
                        resp_content['result'][1]['vlanMap']['vlanName'] == \
                        esg_name:
                    LOG.debug("%(api)s: REST API request success response "
                              "is %(result)s",
                              {'api': rest_api,
                               'result': resp_content['result']})
                    return EMCErrorCode.SUCCESS.value
                else:
                    LOG.error(_LE("%(api)s: REST API request failed "
                                  "response is %(result)s"),
                              {'api': rest_api,
                               'result': resp_content['result']})
                    return -1
            else:
                LOG.error(_LE("%(api)s: REST API failed with error code: "
                              "%(code)d, reason %(error)s"),
                          {'api': rest_api,
                           'code': resp.status_code,
                           'error': resp.content})
                return resp.status_code
        else:
            LOG.error(_LE("%(api)s: REST API failed with reason: %(reason)s"),
                      {'api': rest_api,
                       'reason': resp})
            return EMCErrorCode.UNKNOWN_ERROR.value

    @staticmethod
    def _process_response_str(resp, api_name):
        match_found = False
        ret_value = -1
        xml_tree = ET.fromstring(resp.text)
        for child_element in xml_tree.findall(EMCNAMESPACE):
            if regex.search(EMCErrorCode.PROPERTY_EXISTS_STRING.value,
                            child_element.text):
                LOG.error(_LE("%(api)s:REST API request failed. "
                              "ERROR CODE %(error_code)d : %(error)s"),
                          {'api': api_name,
                           'error_code':
                           EMCErrorCode.EXISTS.value,
                           'error':
                           EMCErrorMessages[
                               EMCErrorCode.EXISTS.value]
                           })
                match_found = True
                ret_value = EMCErrorCode.EXISTS.value
                break
            if regex.search(EMCErrorCode.ESG_SUCCESS_CRITERIA.value,
                            child_element.text):
                LOG.debug("%(api)s: REST API request success ",
                          {'api': api_name})
                match_found = True
                ret_value = EMCErrorCode.SUCCESS.value
                break
            if regex.search(EMCErrorCode.PROPERTY_ERROR_STRING.value,
                            child_element.text):
                split_strings = (child_element.text).split('=')
                error_code = int(split_strings[2])
                LOG.error(_LE("%(api)s: REST API request failed. "
                              "ERROR CODE %(error_code)d : %(error)s"),
                          {'api': api_name, 'error_code': error_code,
                           'error':
                           EMCErrorMessages[error_code]})
                match_found = True
                ret_value = error_code
                break

        if match_found is True:
            return ret_value
        return EMCErrorCode.UNKNOWN_ERROR.value

    def _check_restapi_resp(self, resp, api_name):
        if isinstance(resp, int):
            # HTTP connection timed out and connection error
            LOG.error(_LE("%(api)s: REST API failed "
                          "%(error_code)d"), {'error_code': resp})
            return resp

        if resp is not None and resp.content:
            if resp.status_code in HTTP_SUCCESS_RESPONSE_CODES:
                if api_name in [
                    SupportedRestApi.NC_ENFORCE_CONFIG.value,
                    SupportedRestApi.NC_ENFORCE_SNMP.value,
                    SupportedRestApi.NC_WB_UPDATE_DESC.value,
                    SupportedRestApi.DELETE_ESG.value,
                    SupportedRestApi.NS_ADD_VLAN_TO_ROLE_BY_NAME.value]:
                    if api_name == SupportedRestApi.NC_ENFORCE_SNMP.value:
                        if EMCErrorCode.DOMAIN_LOCK_UNAVAILABLE.value in [
                            resp.content]:
                            LOG.error(_LE("%(api)s FAILED. As API Could not"
                                          " acquire domain "
                                          "lock."), {'api': api_name})
                            LOG.error(_LE("Responsemessage: %(response)s"),
                                      {'response': resp.content})
                            return EMCErrorCode.UNEXPECTED.value
                    if api_name == SupportedRestApi.DELETE_ESG.value:
                        if EMCErrorCode.DELETE_FROM_DEVICE_FAILED.value in [
                            resp.content]:
                            LOG.error(_LE("%(api)s FAILED. As API Could not"
                                          " remove vlans from switches."),
                                      {'api': api_name})
                            LOG.error(_LE("Responsemessage: %(response)s"),
                                      {'response': resp.content})
                    LOG.debug("%(api)s: REST API request success "
                              "response content is %(resp)s",
                              {'api': api_name,
                               'resp': resp.content})
                    return EMCErrorCode.SUCCESS.value

                if api_name == SupportedRestApi.CREATE_ESG.value:
                    return self._process_response_str(resp, api_name)

                if api_name in [SupportedRestApi.ADD_MAC_ESG.value,
                                SupportedRestApi.DELETE_MAC_ESG.value]:
                    xml_tree = ET.fromstring(resp.text)
                    ret_value = int(xml_tree.findall(
                        EMCNAMESPACE)[0].text)
                    if ret_value == EMCErrorCode.SUCCESS.value:
                        LOG.debug(_LI("%(api)s: REST API request success "),
                                  {'api': api_name})
                        return EMCErrorCode.SUCCESS.value
                    else:
                        LOG.error(_LE("%(api)s: REST API failed with "
                                      "error code: %(code)d : "
                                      "Response contents : %(resp)s"),
                                  {'api': api_name, 'code': ret_value,
                                   'resp': resp.content})
                        return ret_value
            else:
                LOG.error(_LE("%(api)s: REST API failed with error code: "
                              "%(code)d, reason "
                              ". Response contents :"
                              "%(resp)s"),
                          {'api': api_name, 'code': resp.status_code,
                           # 'error' : EMCErrorMessages[resp.status_code],
                           'resp': resp.content})
                return resp.status_code
        else:
            LOG.error(_LE("%(api)s:REST API failed with reason: %(error)s."
                          "Response contents : %(reason)s"),
                      {'api': api_name, 'error': EMCErrorMessages[0XC],
                       'reason': resp})
            return EMCErrorCode.UNKNOWN_ERROR.value

    @utils.synchronized('extremenet-mech')
    def _create_logical_network(
        self, network_id, vni, vlan_id, esg_name, network_name):
        db_row_count = db.get_extreme_l2_mapping_by_vlan_id(vlan_id)
        LOG.debug("_create_logical_network: number of entries in the "
                  "database for network  %(network)s are %(num_rows)s",
                  {'network': network_name,
                   'num_rows': db_row_count})

        while db_row_count == 0:
            ret = {}
            resp = {}
            # Create logical resource in the switch fabric equivalent
            # to the tenant network, if already not created
            LOG.info(_LI("First port of the network, creating "
                         "EndSystemGroup with name %(esg)s"),
                     {'esg': esg_name})
            response = RestClient().create_esg(
                vlan_id, esg_name, self.config_params)
            ret = self._check_restapi_resp(response,
                                           SupportedRestApi.CREATE_ESG.value)
            if ret != 0:
                LOG.error(_LE("EndSystemGroup %(esg)s creation failed with "
                              "ERROR CODE %(error_code)d : %(error)s "
                              "for network %(network_id)s with vni %(vni)d "
                              "and VLAN %(vlan_id)d"),
                          {'esg': esg_name,
                           'error_code': ret,
                           'error': EMCErrorMessages[ret],
                           'network_id': network_id, 'vni': vni,
                           'vlan_id': vlan_id})
                break
            else:
                db.add_row_to_extreme_l2_mappings(vlan_id, network_id,
                                                  network_name)

            if self.config_params['role'] != 'None':
                time.sleep(self.config_params['api_processing_delay'])
                response = RestClient().ns_pm_enforce_snmp(self.config_params)
                ret = self._check_restapi_resp(
                    response, SupportedRestApi.NC_ENFORCE_SNMP.value)
                if ret != 0:
                    LOG.error(_LE("NetSight PolicyManager Snmp Enforcement "
                                  "failed with ERROR CODE %(error_code)d : "
                                  "%(error)s after EndSystemGroup creation "
                                  "having network-id %(network_id)s with vni "
                                  "%(vni)d and VLAN %(vlan_id)d"),
                              {'error_code': ret,
                               'error': EMCErrorMessages[ret],
                               'network_id': network_id,
                               'vni': vni,
                               'vlan_id': vlan_id})
                    break

            time.sleep(self.config_params['api_processing_delay'])

            resp = RestClient().get_esg_description_by_vlanid(
                vlan_id,
                self.config_params)
            if resp is not None:
                desc = resp.replace("description=", "", 1)
                desc += "name="
                desc += network_name
                response = RestClient().update_description_for_esg(
                    esg_name,
                    desc,
                    self.config_params)
                ret = self._check_restapi_resp(
                    response, SupportedRestApi.NC_WB_UPDATE_DESC.value)
                if ret != 0:
                    LOG.error(_LE("NetSight PolicyManager updating network "
                                  "description failed with ERROR CODE :"
                                  "%(error_code)d : "
                                  "%(error)s after EndSystemGroup creation "
                                  "having network-id %(network_id)s with vni "
                                  "%(vni)d and VLAN %(vlan_id)d"),
                              {'error_code': ret,
                               'error': EMCErrorMessages[ret],
                               'network_id': network_id,
                               'vni': vni,
                               'vlan_id': vlan_id})
                    break
            else:
                LOG.error(_LE("Unable to get description"))
            if self.config_params['role'] != 'None':
                response = RestClient().add_vlan_egress_to_role(
                    esg_name,
                    self.config_params,
                )
                ret = self._check_restapi_resp(
                    response,
                    SupportedRestApi.NS_ADD_VLAN_TO_ROLE_BY_NAME.value)
                if ret != 0:
                    LOG.error(_LE("NetSight Add VLAN to Role "
                                  "failed with ERROR CODE %(error_code)d "
                                  "after EndSystemGroup creation "
                                  "having network-id %(network_id)s with vni "
                                  "%(vni)d and VLAN %(vlan_id)d"),
                              {'error_code': ret,
                               'network_id': network_id,
                               'vni': vni,
                               'vlan_id': vlan_id})
                    break
            # Adding another enforce on fabric after adding VLAN
            # in the pre-defined role (Openstack Controller).
            time.sleep(self.config_params['api_processing_delay'])
            response = RestClient().ns_pm_enforce_snmp(self.config_params)
            ret = self._check_restapi_resp(
                response, SupportedRestApi.NC_ENFORCE_SNMP.value)
            if ret != 0:
                LOG.error(_LE("NetSight PolicyManager Snmp Enforcement "
                              "failed with ERROR CODE %(error_code)d : "
                              "%(error)s after EndSystemGroup creation "
                              "having network-id %(network_id)s with vni "
                              "%(vni)d and VLAN %(vlan_id)d"),
                          {'error_code': ret,
                           'error': EMCErrorMessages[ret],
                           'network_id': network_id,
                           'vni': vni,
                           'vlan_id': vlan_id})
                break

            time.sleep(self.config_params['api_processing_delay'])
            response = RestClient().ns_enforce_nac_config(self.config_params)
            ret = self._check_restapi_resp(
                response, SupportedRestApi.NC_ENFORCE_CONFIG.value)
            if ret != 0:
                LOG.error(_LE("NetSight Nac Configuration Enforcement failed. "
                              "ERROR CODE %(error_code)d : %(error)s having "
                              "network id %(network_id)s with vni %(vni)d "
                              "and VLAN %(vlan_id)d"),
                          {'error_code': ret,
                           'error': EMCErrorMessages[ret],
                           'network_id': network_id,
                           'vni': vni,
                           'vlan_id': vlan_id})
                break
            return ret

    def create_network_postcommit(self, context):
        """create_network_postcommit."""
        LOG.debug("create_network_postcommit")

    def update_network_postcommit(self, context):
        """Upadtes the name field in the description.

        with current network name

        """
        LOG.debug("update_network_postcommit")
        if not self._is_valid_current_context(context,
                                              "update_network_postcommit"):
            return
        LOG.debug("update_network_postcommit called with network id : "
                  "%(network)s network name : %(name)s",
                  {'network': context.current['id'],
                   'name': context.original['name']})
        if context.original['name'] != context.current['name']:
            resp = {}
            old_net_name = context.original['name']
            new_net_name = context.current['name']
            network_id = context.current['id']
            vni = context.current['provider:segmentation_id']
            db_row = db.get_row_from_extreme_l2_mappings(network_id)
            if db_row is not None:
                if db_row.count() == 1:
                    for row in db_row:
                        vlan_id = row.vlan_id
                        LOG.debug("Fetching description for ESG with VLAN id :"
                                  " %(vlan)d.", {'vlan': vlan_id})
                    resp = RestClient().get_esg_description_by_vlanid(
                        vlan_id, self.config_params)
                    if resp is not None:
                        desc = resp.replace("description=", "")
                        desc2 = desc.replace(old_net_name, "")
                        desc2 += new_net_name
                        esg_name = self._to_esg_name_format(
                            vni,
                            row.original_netname
                        )
                        response = RestClient().update_description_for_esg(
                            esg_name, desc2, self.config_params)
                        ret = self._check_restapi_resp(
                            response, SupportedRestApi.NC_WB_UPDATE_DESC.value)
                        if ret != 0:
                            LOG.error(_LE("EndSystemGroup %(esg)s description "
                                          "update failed with ERROR"
                                          " CODE %(error_code)d : "
                                          "for network id %(network_id)s"
                                          " with "),
                                      {'esg': esg_name,
                                       'error_code': ret,
                                       'network_id': network_id})

                    else:
                        LOG.error(_LE("Unable to find description,"
                                      " description not updated for ESG"))
                else:
                    LOG.error(_LE("Multiple ESG found with same VLAN ID "))
            else:
                LOG.error(_LE("update_network_postcommit : There is no "
                              "entry for %(network_id)s in table "
                              "extreme"
                              "_l2_mappings"), {'network_id': network_id})

    def delete_network_precommit(self, context):
        """Delete DB entry, ESG and associated resources ."""
        LOG.debug("delete_network_precommit")

        if not self._is_valid_current_context(context,
                                              "delete_network_precommit"):
            return

        network_id = context.current['id']
        vlan_id = -1
        original_netname = None
        db_row = db.get_row_from_extreme_l2_mappings(network_id)
        if db_row is not None:
            if db_row.count() == 1:
                for row in db_row:
                    vlan_id = row.vlan_id
                    original_netname = row.original_netname
        else:
            return
        if vlan_id == -1:
            return
        vni = context.current['provider:segmentation_id']
        esg_name = self._to_esg_name_format(vni, original_netname)
        LOG.debug("delete_network_precommit EndSystemGroup %(esg)s is "
                  "deleting, having network id %(network_id)s, vni "
                  "%(vni)d and VLAN %(vlan_id)d",
                  {'esg': esg_name,
                   'network_id': network_id,
                   'vni': vni,
                   'vlan_id': vlan_id})
        resp = RestClient().delete_esg(esg_name, vlan_id, self.config_params)
        ret = self._check_restapi_resp(resp, SupportedRestApi.DELETE_ESG.value)
        if ret != 0:
            LOG.error(_LE("EndSystemGroup %(esg)s deletion "
                          "failed with ERROR CODE %(error_code)d : "
                          "for network id %(network_id)s with "
                          "vni %(vni)d and VLAN %(vlan_id)d"),
                      {'esg': esg_name,
                       'error_code': ret,
                       'network_id': network_id,
                       'vni': vni,
                       'vlan_id': vlan_id})
        else:
            db.delete_row_from_extreme_l2_mappings(vlan_id)

    def delete_network_postcommit(self, context):
        """delete_network_postcommit ."""
        LOG.debug("delete_network_postcommit")

    def create_port_postcommit(self, context):
        """create_port_postcommit."""
        LOG.debug("create_port_postcommit")

    def bind_port(self, context):
        """Maps VxLAN VNI to VLAN-ID."""
        LOG.info(_LI("bind port on host %s"), context.host)
        # We can only bind at top level i.e if binding should not be in
        # progress
        if not self._is_valid_current_context(context, "bind_port"):
            return

        port = context.current
        LOG.debug("bind_port binding_levels details: %(binding_levels)s",
                  {'binding_levels': context.binding_levels})
        if context.binding_levels:
            LOG.debug("bind_port binding_levels details: Port %(port_id)s "
                      "has a top binding already,top bound segment is "
                      "%(vni)s Network id is %(network_id)s",
                      {'port_id': port['id'],
                       'vni': context.top_bound_segment['segmentation_id'],
                       'network_id': port['network_id']})
            return

        # Check type of network, so to decide allocation of dyanamic segment
        if context.segments_to_bind[0]['network_type'] == 'vlan':
            next_segment = OrderedDict([
                ('id',
                 context.segments_to_bind[0]['id']),
                ('segmentation_id',
                 context.segments_to_bind[0]['segmentation_id']),
                ('physical_network',
                 context.segments_to_bind[0]['physical_network']),
                ('network_type',
                 context.segments_to_bind[0]['network_type']),
                ('mtu', context.network.current['mtu'])])
        else:
            # Since the network is of type VXLAN
            # allocate a dynamic segment of VLAN type for same network
            next_segment = context.allocate_dynamic_segment(
                {'id': context.network.current, 'network_type': 'vlan'})

        LOG.debug("bind_port next segment details: %(nextseg)s",
                  {'nextseg': next_segment})

        LOG.debug("bind_port port details: Allocated Dynamic VLAN segment "
                  "for port id %(port_id)s assigned IPv4 address "
                  "%(port_ip)s network id %(network_id)s is %(dynamic_seg)s",
                  {'port_id': port['id'],
                   'port_ip': port['fixed_ips'][0]['ip_address'],
                   'network_id': port['network_id'],
                   'dynamic_seg': next_segment['segmentation_id']})

        LOG.info(_LI("bind_port: VXLAN Static SEG ID %(vni)d "
                     "VLAN Dynamic SEG ID %(dynamic_seg)d "),
                 {'vni': context.segments_to_bind[0]['segmentation_id'],
                  'dynamic_seg': next_segment['segmentation_id']})

        context.continue_binding(context.segments_to_bind[0]['id'],
                                 [next_segment])

    def update_port_postcommit(self, context):
        """Creates ESG,if not already created ."""
        """ Adds port's MAC to its corresponding EndSystemGroup."""
        # 'from driver_api.py comments
        # Raising an exception will
        # result in the deletion of the resource'
        # From the observations during unit test, port is not getting deleted'
        # For physnet and VLAN mapping misconfig, port is getting deleted'
        # If we cannot create an ESG or cannot addMAC, traffic flows for
        # the port will not be configured'

        if not self._is_valid_current_context(context,
                                              "update_port_postcommit") or\
                not self._is_valid_top_bound_seg(context,
                                                 "update_port_postcommit") or\
                not self._is_valid_bottom_bound_seg(context,
                                                    "update_port_postcommit"):
            return
        if context.status != constants.PORT_STATUS_ACTIVE or \
                context.original_status != constants.PORT_STATUS_BUILD:
            return
        port = context.current
        network_id = port['network_id']

        LOG.debug("update_port_postcommit binding_levels details: "
                  "%(bindinglevels)s",
                  {'bindinglevels': context.binding_levels})

        if context.binding_levels[0]['bound_driver'] != EXTREMENET_MECH_DRIVER:
            LOG.error(_LE("update_port_postcommit binding details: "
                          " Driver not bound to the "
                          "Port %(port_id)s of Network-id %(network_id)s"),
                      {'port_id': port['id'],
                       'network_id': network_id})
            return

        vlan_id = context.bottom_bound_segment['segmentation_id']
        vni = context.top_bound_segment['segmentation_id']
        LOG.debug("update_port_postcommit port details: Dynamic VLAN segment "
                  "for port id %(port_id)s network id %(network_id)s "
                  "is %(dynamic_seg)d",
                  {'port_id': port['id'],
                   'network_id': port['network_id'],
                   'dynamic_seg': vlan_id})
        network_name = Util().get_network_name(network_id)
        esg_name = self._to_esg_name_format(vni, network_name)

        ret = self._create_logical_network(
            network_id,
            vni, vlan_id, esg_name, network_name,
        )
        if ret:
            return
        # Add the port's MAC to the corresponding EndSystemGroup
        port_mac_addr = context.current['mac_address']
        host_id = port[portbindings.HOST_ID]
        response = RestClient().add_mac_to_esg(
            port_mac_addr, host_id, esg_name, self.config_params)
        ret = self._check_restapi_resp(response,
                                       SupportedRestApi.ADD_MAC_ESG.value)

        if ret:
            LOG.error(_LE(" update_port_postcommit error details: "
                          "adding MAC to esg %(esg)s failed "
                          "with ERROR CODE %(error_code)d : %(error)s "
                          "with network-id: %(network_id)s vni "
                          "%(vni)d and VLAN %(vlan_id)d "
                          "port_id %(port_id)s port_mac %(port_mac)s"),
                      {'esg': esg_name,
                       'error_code': ret,
                       'error': EMCErrorMessages[ret],
                       'network_id': network_id,
                       'vni': vni,
                       'vlan_id': vlan_id,
                       'port_id': port['id'],
                       'port_mac': port_mac_addr})

        LOG.info(_LI("update_port_postcommit on host %s"), context.host)

    def delete_port_postcommit(self, context):
        """Deletes MAC from ESG by invoking EMC API ."""
        LOG.debug("delete_port_postcommit on host %s", context.host)
        if not self._is_valid_current_context(context,
                                              "delete_port_postcommit") or\
                not self._is_valid_top_bound_seg(context,
                                                 "delete_port_postcommit"):
            return
        port = context.current
        network_id = port['network_id']
        mac_address = port['mac_address']
        vni = context.top_bound_segment['segmentation_id']
        esg_name = None
        original_netname = None
        db_row = db.get_row_from_extreme_l2_mappings(network_id)
        if db_row is not None:
            if db_row.count() == 1:
                for row in db_row:
                    original_netname = row.original_netname
                esg_name = self._to_esg_name_format(vni, original_netname)
        else:
            LOG.error(_LE("delete_port_postcommit : There is no "
                          "entry for network %(network_id)s in table "
                          "database table"
                          " extreme"
                          "_l2_mappings"), {'network_id': network_id})
            return

        LOG.debug("delete_port_postcommit port details: port belongs to "
                  "ESG %(esg)s Network id %(network_id)s "
                  "VNI %(vni)d MAC address %(mac)s",
                  {'esg': esg_name,
                   'network_id': network_id,
                   'vni': vni,
                   'mac': mac_address})
        resp = RestClient().remove_mac_from_esg(mac_address, esg_name,
                                                self.config_params)
        ret = self._check_restapi_resp(
            resp,
            SupportedRestApi.DELETE_MAC_ESG.value,
        )
        if ret:
            LOG.error(_LE("delete_port_postcommit port details:Deleting"
                          " port failed with ERROR CODE %(error_code)d :"
                          " %(error)s from %(esg)s having MAC address "
                          "%(mac_addr)s from "
                          "network %(network_id)s with vni %(vni)d"),
                      {'esg': esg_name,
                       'error_code': ret,
                       'error': EMCErrorMessages[ret],
                       'mac_addr': mac_address,
                       'network_id': network_id,
                       'vni': vni})
