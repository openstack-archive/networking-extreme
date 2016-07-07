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

from oslo_config import cfg

EXTREME_MECHDRIVER_OPTS = [
    cfg.StrOpt('netsight_ip', default='',
               help='NetSight REST API Server IP'),
    cfg.IntOpt('netsight_port',
               default='8443',
               help='NetSight REST API Server Port'),
    cfg.StrOpt('scheme',
               default='https',
               help='Scheme for the NetSight REST API, http/https'),
    cfg.StrOpt('netsight_username',
               default='root',
               help='NetSight username'),
    cfg.StrOpt('netsight_passwd',
               default='',
               help='NetSight password'),
    cfg.BoolOpt('ssl_cert_verify',
                default=False,
                help='SSL certificate verification,True/False'),
    cfg.StrOpt('nac_config',
               default='Default',
               help='NAC Configuration'),
    cfg.StrOpt('policy_domain',
               default='Default Policy Domain',
               help='Policy Domain'),
    cfg.StrOpt('network_node_switch_ip',
               default='',
               help='OpenStack Network node Switch IP'),
    cfg.IntOpt('network_node_switch_port',
               default='',
               help='OpenStack Network node Switch Port'),
    cfg.StrOpt('switch_username',
               default='admin',
               help='Switch login user name'),
    cfg.StrOpt('switch_password',
               default='',
               help='Switch login password'),
    cfg.IntOpt('api_processing_delay',
               default='10',
               help='api processing delay')
]

cfg.CONF.register_opts(EXTREME_MECHDRIVER_OPTS, 'ml2_extreme')

NS_CONFIG = cfg.CONF.ml2_extreme


def get_netsight_config():
    """Net Sight server configuration parameters """
    config_params = {
        'ns_server_ip': NS_CONFIG.netsight_ip,
        'ns_server_port': NS_CONFIG.netsight_port,
        'scheme': NS_CONFIG.scheme,
        'ns_user_name': NS_CONFIG.netsight_username,
        'ns_passwd': NS_CONFIG.netsight_passwd,
        'ssl_cert_verify': NS_CONFIG.ssl_cert_verify,
        'nac_config': NS_CONFIG.nac_config,
        'policy_domain': NS_CONFIG.policy_domain,
        'network_node_switch_port': NS_CONFIG.network_node_switch_port,
        'network_node_switch_ip': NS_CONFIG.network_node_switch_ip,
        'switch_username': NS_CONFIG.switch_username,
        'switch_password': NS_CONFIG.switch_password,
        'api_processing_delay': NS_CONFIG.api_processing_delay
    }
    return config_params
