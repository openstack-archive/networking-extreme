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
import re as regex
import time
import xml.etree.ElementTree as ET

from collections import OrderedDict
from oslo_config import cfg
from oslo_log import log
from oslo_serialization import jsonutils

import requests
import six

from enum import Enum
from neutron.common import constants
from neutron.common import utils
from neutron.db import api as db_api
from neutron.db import models_v2
from neutron.extensions import portbindings
from neutron.i18n import _LE
from neutron.i18n import _LI
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2 import models

from neutron.plugins.ml2.drivers.extremenet import config

NETSIGHTNAMESPACE = '{http://ws.web.server.tam.netsight.enterasys.com}return'
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
SWITCH_URL = '{scheme}://{user}:@{switch_ip}/{jsonrpc}'

OPENVSWITCH_MECH_DRIVER = 'openvswitch'
LINUXBRIDGE_MECH_DRIVER = 'linuxbridge'
EXTREMENET_MECH_DRIVER = 'extremenet_mech'
ESG_PREFIX = 'VNI'
DELIMITER = '-'


class NetSightErrorCode(Enum):
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


class SupportedRestApi(Enum):
    # This property name for Creating EndSystemGroup(ESG)
    CREATE_ESG = "createVirtualAndPhysicalNetwork"
    # This property name for Removing EndSystemGroup(ESG)
    DELETE_ESG = "removeNamedList"
    # This property name for Adding MAC addr to ESG
    ADD_MAC_ESG = "addMACToEndSystemGroup"
    # This property name for deleting MAC addr from ESG
    DELETE_MAC_ESG = "removeMACFromEndSystemGroup"
    # This property name for Enforcing SNMP Domain
    NS_PM_ENFORCE_SNMP = "netsightPolicyManagerSnmpEnforceDomain"
    # This property name for Enforcing NAC configuration
    NS_ENFORCE_NAC_CONFIG =\
        "netsightNacConfigurationEnforceAllNacAppliances"
    CONF_VLAN_SWITCH = "conf_vlan_on_switch_port"


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
    def _process_netsight_url(requested_url, api_name, config_params):
        LOG.debug("%(api)s request URL is %(url)s",
                  {'api': api_name,
                   'url': requested_url})
        try:
            response = requests.get(requested_url, timeout=REST_API_TIMEOUT,
                                    auth=(config_params['ns_user_name'],
                                          config_params['ns_passwd']),
                                    verify=config_params['ssl_cert_verify'])

            return response
        except requests.exceptions.Timeout as ex:
            LOG.exception(_LE("REST API %(api)s requested URL %(url)s "
                              "timed out %(reason)s"),
                          {'api': api_name,
                           'url': requested_url,
                           'reason': ex})
            return NetSightErrorCode.CONN_TIMED_OUT.value
        except requests.ConnectionError as ex:
            LOG.exception(_LE("REST API %(api)s requested URL %(url)s "
                              "ConnectionError %(reason)s"),
                          {'api': api_name,
                           'url': requested_url,
                           'reason': ex})
            return NetSightErrorCode.HTTP_CONN_ERROR.value
        except Exception as ex:
            LOG.exception(_LE("REST API %(api)s requested URL %(url)s "
                              "failed. Reason: %(reason)s"),
                          {'api': api_name,
                           'url': requested_url,
                           'reason': ex})
            return NetSightErrorCode.UNKNOWN_ERROR.value

    @staticmethod
    def _post_command_to_switch(requested_url, rest_api, query_params,
                                cli_command, config_params):
        headers = {"content-type": "application/json"}
        LOG.debug("REST API %(api)s request URL %(url)s and "
                  "cli command is %(cli)s",
                  {'api': rest_api, 'url': requested_url,
                   'cli': cli_command})
        try:
            response = requests.post(requested_url,
                                     jsonutils.dumps(query_params),
                                     headers=headers,
                                     timeout=REST_API_TIMEOUT,
                                     auth=(config_params['switch_username'],
                                           config_params['switch_password']))
            return response
        except requests.exceptions.Timeout as ex:
            LOG.exception(_LE("REST API %(api)s requested URL %(url)s "
                              "and cli command %(cli)s timed "
                              "out %(reason)s"),
                          {'api': rest_api, 'url': requested_url,
                           'cli': cli_command,
                           'reason': ex})
            return NetSightErrorCode.CONN_TIMED_OUT.value
        except requests.ConnectionError as ex:
            LOG.exception(_LE("REST API %(api)s requested URL %(url)s "
                              "and cli command %(cli)s Connection Error "
                              "%(reason)s"),
                          {'api': rest_api,
                           'url': requested_url,
                           'cli': cli_command,
                           'reason': ex})
            return NetSightErrorCode.HTTP_CONN_ERROR.value
        except Exception as ex:
            LOG.exception(_LE("REST API %(api)s requested URL %(url)s "
                              "and cli command %(cli)s failed "
                              "%(reason)s"),
                          {'api': rest_api,
                           'url': requested_url,
                           'cli': cli_command,
                           'reason': ex})
            return NetSightErrorCode.UNKNOWN_ERROR.value

    def create_esg(self, vlan, esg_name, config_params):
        es_create_url = NAC_CONF_WS_URL.format(
            scheme=config_params['scheme'],
            server_ip=config_params['ns_server_ip'],
            port=config_params['ns_server_port'],
            service=SupportedRestApi.CREATE_ESG.value)
        query_params = OrderedDict([('name', esg_name),
                                    ('nacConfig', config_params['nac_config']),
                                    ('domain', config_params['policy_domain']),
                                    ('isPrivateVlan', "false"),
                                    ('primaryVlanId', vlan),
                                    ('secondaryVlanId', 0),
                                    ('mode', "promiscuous"),
                                    ('forwardAsTagged', "true")])
        es_create_url += self._dict_to_query_params(query_params)
        response = self._process_netsight_url(
            es_create_url, SupportedRestApi.CREATE_ESG.value, config_params)
        return response

    def remove_named_list(self, esg_name, config_params):

        """NetSight API to remove the namedList

           within the switch fabric domain
        """

        del_net_url = NAC_ES_WS_URL.format(
            scheme=config_params['scheme'],
            server_ip=config_params['ns_server_ip'],
            port=config_params['ns_server_port'],
            service=SupportedRestApi.DELETE_ESG.value)
        query_params = {'listName': esg_name}
        del_net_url += self._dict_to_query_params(query_params)
        response = self._process_netsight_url(
            del_net_url, SupportedRestApi.DELETE_ESG.value, config_params)
        return response

    def ns_enforce_nac_config(self, config_params):
        enforce_nac_app_url = NAC_CONF_PUSH_URL.format(
            scheme=config_params['scheme'],
            server_ip=config_params['ns_server_ip'],
            port=config_params['ns_server_port'],
            service=SupportedRestApi.NS_ENFORCE_NAC_CONFIG.value)
        path_params = OrderedDict([('forceMask', 0),
                                   ('ignoreWarnings', "false"),
                                   ('auditOnly', "false")])
        enforce_nac_app_url += self._dict_to_path_params(path_params)
        response = self._process_netsight_url(
            enforce_nac_app_url, SupportedRestApi.NS_ENFORCE_NAC_CONFIG.value,
            config_params)
        return response

    def ns_pm_enforce_snmp(self, config_params):
        enforce_domain_url = NAC_CONF_PUSH_URL.format(
            scheme=config_params['scheme'],
            server_ip=config_params['ns_server_ip'],
            port=config_params['ns_server_port'],
            service=SupportedRestApi.NS_PM_ENFORCE_SNMP.value)
        path_params = OrderedDict([('user', "admin"),
                                   ('domainName',
                                    config_params['policy_domain']),
                                   ('switches', "null"),
                                   ('wait', "false")])
        enforce_domain_url += self._dict_to_path_params(path_params)
        response = self._process_netsight_url(
            enforce_domain_url, SupportedRestApi.NS_PM_ENFORCE_SNMP.value,
            config_params)
        return response

    def conf_vlan_on_switch_port(self, vlan_id, config_params):
        config_vlan_url = SWITCH_URL.format(
            scheme='http', user=config_params['switch_username'],
            switch_ip=config_params['network_node_switch_ip'],
            jsonrpc='jsonrpc')

        cli_command = 'configure vlan' + ' ' + str(vlan_id) + ' ' + \
                      'add port' + ' ' + \
                      str(config_params['network_node_switch_port']) + \
                      ' ' + 'tagged'
        query_params = dict(method='cli', id='1', jsonrpc='2.0',
                            params=[cli_command])
        response = self._post_command_to_switch(
            config_vlan_url, SupportedRestApi.CONF_VLAN_SWITCH.value,
            query_params, cli_command, config_params)
        return response

    def delete_esg(self, esg_name, config_params):
        return self.remove_named_list(esg_name, config_params)

    def add_mac_to_esg(self, mac_addr, host_id, esg_name, config_params):
        add_mac_url = NAC_ES_WS_URL.format(
            scheme=config_params['scheme'],
            server_ip=config_params['ns_server_ip'],
            port=config_params['ns_server_port'],
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
        response = self._process_netsight_url(
            add_mac_url, SupportedRestApi.ADD_MAC_ESG.value,
            config_params)
        return response

    def remove_mac_from_esg(self, mac_address, esg_name, config_params):
        delete_port_url = NAC_ES_WS_URL.format(
            scheme=config_params['scheme'],
            server_ip=config_params['ns_server_ip'],
            port=config_params['ns_server_port'],
            service=SupportedRestApi.DELETE_MAC_ESG.value)
        query_params = OrderedDict([('endSystemGroup', esg_name),
                                    ('mac', mac_address),
                                    ('reauthorize', "true")])
        delete_port_url += self._dict_to_query_params(query_params)
        response = self._process_netsight_url(
            delete_port_url, SupportedRestApi.DELETE_MAC_ESG.value,
            config_params)
        return response


class Util(object):

    """Util provides the utility API for the ExtremeNetMechanismDriver

        to access different Neutron DB tables
     """

    @staticmethod
    def get_number_ports(network_id):
        session = db_api.get_session()
        rows = (session.query(models_v2.Port).filter_by
                (network_id=network_id))
        return rows.count()

    @staticmethod
    def get_network_name(network_id):
        session = db_api.get_session()
        rows = (session.query(models_v2.Network).filter_by
                (id=network_id).first())
        return rows['name']

    @staticmethod
    def get_dynamic_seg_id(network_id):
        session = db_api.get_session()
        rows = (session.query(models.NetworkSegment).filter_by
                (network_id=network_id,
                 network_type='vlan',
                 is_dynamic=1).first())
        if rows:
            return rows['segmentation_id']
        else:
            return -1


class ExtremeNetMechanismDriver(api.MechanismDriver):

    """ExtremeNetMechanismDriver implements the ML2 MechanismDriver methods

    for network and port related events to utilize ExtremeNetworks Switches
    VxLAN encapsulation support, coupled with Hierarchical port
    binding feature.

    Communicates with the ExtremeNetworks NetSight Manager over REST API to
    enforce the network and port configuration within the Switch fabric.
    """

    def validate_config_params(self):
        if not self.config_params['ns_server_ip']:
            LOG.error(_LE("NetSight Switch Manager IP not configured"))
        if not self.config_params['ns_user_name']:
            LOG.error(_LE("NetSight Switch Manager user name not configured"))
        if not self.config_params['network_node_switch_ip']:
            LOG.error(_LE("Network node Switch IP not configured"))
        if not self.config_params['switch_username']:
            LOG.error(_LE("Switch user name not configured"))
        if not self.config_params['network_node_switch_port']:
            LOG.error(_LE("Network node Switch port not configured"))

    def initialize(self):
        LOG.info(_LI("ExtremeNetMechanismDriver initialize"))
        self.mechanism_drivers = cfg.CONF.ml2.mechanism_drivers
        self.config_params = {}

        if len(self.mechanism_drivers) >= 2:
            if self.mechanism_drivers[0] == EXTREMENET_MECH_DRIVER and \
                    self.mechanism_drivers[1] in [LINUXBRIDGE_MECH_DRIVER,
                                                  OPENVSWITCH_MECH_DRIVER]:
                self.config_params = config.get_netsight_config()
                LOG.info(_LI("Netsight configuration parameters %s"),
                         self.config_params)
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
    def _to_esg_name_format(vlan_id, network_id):
        network_name = Util().get_network_name(network_id)
        esg_name = ESG_PREFIX + DELIMITER + str(vlan_id) + \
            DELIMITER + network_name
        return esg_name

    @staticmethod
    def _is_valid_current_context(context, api_str):

        '''current may be port context or network context'''

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
            LOG.error(_LE("context.current attribute error for api %(api)s"),
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
                        NetSightErrorCode.SUCCESS_STR.value and \
                        resp_content['result'][1]['vlanMap']['vlanName'] == \
                        esg_name:
                    LOG.debug("%(api)s: REST API request success response "
                              "is %(result)s",
                              {'api': rest_api,
                               'result': resp_content['result']})
                    return NetSightErrorCode.SUCCESS.value
                else:
                    LOG.error(_LE("%(api)s: REST API request failed "
                                  "response is %(result)s"),
                              {'api': rest_api,
                               'result': resp_content['result']})
                    return -1
            else:
                LOG.error(_LE("%(api)s: REST API failed with error code: "
                              "%(code)d"),
                          {'api': rest_api,
                           'code': resp.status_code})
                return resp.status_code
        else:
            LOG.error(_LE("%(api)s: REST API failed with reason: %(reason)s"),
                      {'api': rest_api,
                       'reason': resp})
            return NetSightErrorCode.UNKNOWN_ERROR.value

    @staticmethod
    def _process_response_str(resp, api_name):
        match_found = False
        ret_value = -1
        xml_tree = ET.fromstring(resp.text)
        for child_element in xml_tree.findall(NETSIGHTNAMESPACE):
            if regex.search(NetSightErrorCode.PROPERTY_EXISTS_STRING.value,
                            child_element.text):
                LOG.error(_LE("%(api)s:REST API request failed "
                              "with ERROR CODE %(error_code)d"),
                          {'api': api_name,
                           'error_code': NetSightErrorCode.EXISTS.value})
                match_found = True
                ret_value = NetSightErrorCode.EXISTS.value
                break
            if regex.search(NetSightErrorCode.ESG_SUCCESS_CRITERIA.value,
                            child_element.text):
                LOG.debug("%(api)s: REST API request success ",
                          {'api': api_name})
                match_found = True
                ret_value = NetSightErrorCode.SUCCESS.value
                break
            if regex.search(NetSightErrorCode.PROPERTY_ERROR_STRING.value,
                            child_element.text):
                split_strings = (child_element.text).split('=')
                # Expected error format is "errorsting = <text>
                # errorcode = <error id>"
                error_code = int(split_strings[2])
                LOG.error(_LE("%(api)s: REST API request failed "
                              "with ERROR CODE %(error_code)d"),
                          {'api': api_name, 'error_code': error_code})
                match_found = True
                ret_value = error_code
                break

        if match_found is True:
            return ret_value
        return NetSightErrorCode.UNKNOWN_ERROR.value

    def _check_restapi_resp(self, resp, api_name):
        if isinstance(resp, int):
            # HTTP connection timed out and connection error
            LOG.error(_LE("%(api)s: REST API failed with error code "
                          "%(error_code)d"), {'error_code': resp})
            return resp

        if resp is not None and resp.content:
            if resp.status_code in HTTP_SUCCESS_RESPONSE_CODES:
                if api_name in [SupportedRestApi.NS_ENFORCE_NAC_CONFIG.value,
                                SupportedRestApi.NS_PM_ENFORCE_SNMP.value]:
                    LOG.debug("%(api)s: REST API request success "
                              "response content is %(resp)s",
                              {'api': api_name,
                               'resp': resp.content})
                    return NetSightErrorCode.SUCCESS.value

                if api_name == SupportedRestApi.CREATE_ESG.value:
                    return self._process_response_str(resp, api_name)

                if api_name in [SupportedRestApi.ADD_MAC_ESG.value,
                                SupportedRestApi.DELETE_MAC_ESG.value,
                                SupportedRestApi.DELETE_ESG.value]:
                    xml_tree = ET.fromstring(resp.text)
                    ret_value = int(xml_tree.findall(
                        NETSIGHTNAMESPACE)[0].text)
                    if ret_value == NetSightErrorCode.SUCCESS.value:
                        LOG.debug(_LI("%(api)s: REST API request success "),
                                  {'api': api_name})
                    else:
                        LOG.error(_LE("%(api)s: REST API failed with "
                                      "error code: %(code)d"),
                                  {'api': api_name, 'code': ret_value})
                    return ret_value
            else:
                LOG.error(_LE("%(api)s: REST API failed with error code: "
                              "%(code)d"),
                          {'api': api_name, 'code': resp.status_code})
                return resp.status_code
        else:
            LOG.error(_LE("%(api)s:REST API failed with reason: %(reason)s"),
                      {'api': api_name, 'reason': resp})
            return NetSightErrorCode.UNKNOWN_ERROR.value

    @utils.synchronized('extremenet-mech')
    def _create_logical_network(self, network_id, vni, vlan_id, esg_name):
        num_ports = Util().get_number_ports(network_id)
        LOG.debug("_create_logical_network: number of ports in the "
                  "network id %(network_id)s is %(num_ports)d",
                  {'network_id': network_id,
                   'num_ports': num_ports})
        ret = 0
        while num_ports == 1:
            # Create logical resource in the switch fabric equivalent
            # to the tenant network, of this port
            LOG.info(_LI("First port of the network, creating "
                         "EndSystemGroup with name %(esg)s"),
                     {'esg': esg_name})
            response = RestClient().create_esg(
                vlan_id, esg_name, self.config_params)
            ret = self._check_restapi_resp(response,
                                           SupportedRestApi.CREATE_ESG.value)
            if ret:
                LOG.error(_LE("EndSystemGroup %(esg)s creation failed with "
                              "ERROR CODE %(error_code)d for network "
                              "%(network_id)s with vni %(vni)d "
                              "and vlan %(vlan_id)d"),
                          {'esg': esg_name,
                           'error_code': ret,
                           'network_id': network_id, 'vni': vni,
                           'vlan_id': vlan_id})
                break
            time.sleep(self.config_params['api_processing_delay'])
            response = RestClient().ns_enforce_nac_config(self.config_params)
            ret = self._check_restapi_resp(
                response, SupportedRestApi.NS_ENFORCE_NAC_CONFIG.value)
            if ret:
                LOG.error(_LE("NetSight Nac Configuration Enforcement failed "
                              "with ERROR CODE %(error_code)d having "
                              "network id %(network_id)s with vni %(vni)d "
                              "and vlan %(vlan_id)d"),
                          {'error_code': ret,
                           'network_id': network_id,
                           'vni': vni,
                           'vlan_id': vlan_id})
                break
            response = RestClient().ns_pm_enforce_snmp(self.config_params)
            ret = self._check_restapi_resp(
                response, SupportedRestApi.NS_PM_ENFORCE_SNMP.value)
            if ret:
                LOG.error(_LE("NetSight PolicyManager Snmp Enforcement "
                              "failed with ERROR CODE %(error_code)d after "
                              "EndSystemGroup creation "
                              "having network-id %(network_id)s with vni "
                              "%(vni)d and vlan %(vlan_id)d"),
                          {'error_code': ret,
                           'network_id': network_id,
                           'vni': vni,
                           'vlan_id': vlan_id})
                break
            time.sleep(self.config_params['api_processing_delay'])
            response = RestClient().conf_vlan_on_switch_port(
                vlan_id, self.config_params)
            ret = self._process_json_resp(
                response, esg_name, SupportedRestApi.CONF_VLAN_SWITCH.value)
            if ret:
                LOG.error(_LE("configuring vlan %(vlan-id)d on the switch "
                              "port %(port)d is failed for esg %(esg)s"),
                          {'vlan-id': vlan_id,
                           'port':
                           self.config_params['network_node_switch_port'],
                           'esg': esg_name})
            break

        return ret

    def create_network_postcommit(self, context):
        LOG.debug("create_network_postcommit")

    def update_network_postcommit(self, context):
        LOG.debug("update_network_postcommit")

    def delete_network_precommit(self, context):
        LOG.debug("delete_network_precommit")

        if not self._is_valid_current_context(context,
                                              "delete_network_precommit"):
            return

        network_id = context.current['id']
        vlan_id = Util().get_dynamic_seg_id(network_id)
        if vlan_id == -1:
            return
        vni = context.current['provider:segmentation_id']
        esg_name = self._to_esg_name_format(vlan_id, network_id)

        LOG.debug("delete_network_precommit EndSystemGroup %(esg)s is "
                  "deleting, having network id %(network_id)s, vni "
                  "%(vni)d and vlan %(vlan_id)d",
                  {'esg': esg_name,
                   'network_id': network_id,
                   'vni': vni,
                   'vlan_id': vlan_id})
        resp = RestClient().delete_esg(esg_name, self.config_params)
        ret = self._check_restapi_resp(resp, SupportedRestApi.DELETE_ESG.value)
        if ret:
            LOG.error(_LE("EndSystemGroup %(esg)s deletion "
                          "failed with ERROR CODE %(error_code)d "
                          "having network id %(network_id)s with "
                          "vni %(vni)d and vlan %(vlan_id)d"),
                      {'esg': esg_name,
                       'error_code': ret,
                       'network_id': network_id,
                       'vni': vni,
                       'vlan_id': vlan_id})

    def delete_network_postcommit(self, context):
        LOG.debug("delete_network_postcommit")

    def create_port_postcommit(self, context):
        LOG.debug("create_port_postcommit")

    def bind_port(self, context):
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

        # allocate a dynamic segment of VLAN type
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
        # 'from driver_api.py comments
        # Raising an exception will
        # result in the deletion of the resource.'
        # From the observations during unit test, port is not getting deleted'
        # For physnet and vlan mapping misconfig, port is getting deleted'
        # If we cannot create an ESG or cannot addMAC, traffic flows for
        # the port will not be configured'
        # should port be deleted ?'
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
                          "Driver not bound to the "
                          "Port %(port_id)s of Network-id %(network_id)s"),
                      {'port_id': port['id'],
                       'network_id': network_id})
            # TODO(Raise an exception as top_bound should have been us ?)
            return

        vlan_id = context.bottom_bound_segment['segmentation_id']
        vni = context.top_bound_segment['segmentation_id']
        LOG.debug("update_port_postcommit port details: Dynamic VLAN segment "
                  "for port id %(port_id)s network id %(network_id)s "
                  "is %(dynamic_seg)d",
                  {'port_id': port['id'],
                   'network_id': port['network_id'],
                   'dynamic_seg': vlan_id})
        esg_name = self._to_esg_name_format(vlan_id, network_id)
        ret = self._create_logical_network(network_id, vni, vlan_id, esg_name)
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
                          "with ERROR CODE %(error_code)d "
                          "with network-id: %(network_id)s vni "
                          "%(vni)d and vlan %(vlan_id)%d "
                          "port_id %(port_id)s port_mac %(port_mac)s"),
                      {'esg': esg_name,
                       'error_code': ret,
                       'network_id': network_id,
                       'vni': vni,
                       'vlan_id': vlan_id,
                       'port_id': port['id'],
                       'port_mac': port_mac_addr})

        LOG.info(_LI("update_port_postcommit on host %s"), context.host)

    def delete_port_postcommit(self, context):
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
        vlan_id = context.bottom_bound_segment['segmentation_id']
        esg_name = self._to_esg_name_format(vlan_id, network_id)
        LOG.debug("delete_port_postcommit port details: port belongs to "
                  "ESG %(esg)s Network id %(network_id)s "
                  "VNI %(vni)d MAC address %(mac)s",
                  {'esg': esg_name,
                   'network_id': network_id,
                   'vni': vni,
                   'mac': mac_address})
        resp = RestClient().remove_mac_from_esg(mac_address, esg_name,
                                                self.config_params)
        ret = self._check_restapi_resp(resp,
                                       SupportedRestApi.DELETE_MAC_ESG.value)
        if ret:
            LOG.error(_LE("delete_port_postcommit port details:Deleting port "
                          "failed with ERROR CODE %(error_code)d from %(esg)s "
                          "having MAC address %(mac_addr)s from "
                          "network %(network_id)s with vni %(vni)d"),
                      {'esg': esg_name,
                       'error_code': ret,
                       'mac_addr': mac_address,
                       'network_id': network_id,
                       'vni': vni})
