"""ExtremeNet ML2 Mech Config ."""
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
    cfg.StrOpt('emc_ip', default='',
               help='Extreme Management Center REST API Server IP'),
    cfg.IntOpt('emc_port',
               default='8443',
               help='Extreme Management Center REST API Server Port'),
    cfg.StrOpt('scheme',
               default='https',
               help='Scheme for the Extreme Management'
                    ' Center REST API, http/https'),
    cfg.StrOpt('emc_username',
               default='root',
               help='Extreme Management Center username'),
    cfg.StrOpt('emc_passwd',
               default='',
               help='Extreme Management Center password'),
    cfg.BoolOpt('ssl_cert_verify',
                default=False,
                help='SSL certificate verification,True/False'),
    cfg.StrOpt('nac_config',
               default='Default',
               help='NAC Configuration'),
    cfg.StrOpt('policy_domain',
               default='Default Policy Domain',
               help='Policy Domain'),
    cfg.StrOpt('role',
               default='Openstack Controller',
               help='Default Role'),
    cfg.IntOpt('api_processing_delay',
               default='10',
               help='api processing delay')
]

cfg.CONF.register_opts(EXTREME_MECHDRIVER_OPTS, 'ml2_extreme')

EMC_CONFIG = cfg.CONF.ml2_extreme


def get_emc_config():
    """Extreme Management Center server configuration parameters."""
    config_params = {
        'emc_server_ip': EMC_CONFIG.emc_ip,
        'emc_server_port': EMC_CONFIG.emc_port,
        'scheme': EMC_CONFIG.scheme,
        'emc_user_name': EMC_CONFIG.emc_username,
        'emc_passwd': EMC_CONFIG.emc_passwd,
        'ssl_cert_verify': EMC_CONFIG.ssl_cert_verify,
        'nac_config': EMC_CONFIG.nac_config,
        'policy_domain': EMC_CONFIG.policy_domain,
        'role': EMC_CONFIG.role,
        'api_processing_delay': EMC_CONFIG.api_processing_delay
    }
    return config_params
