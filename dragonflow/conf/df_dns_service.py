# Copyright (c) 2016 OpenStack Foundation.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.


from oslo_config import cfg

from dragonflow._i18n import _


df_dns_opts = [
    cfg.IPOpt(
        'ip',
        default='169.254.169.254',
        help=_('The IP to which the DF dns service is bound'),
    ),
    cfg.PortOpt(
        'port',
        default='10053',
        help=_('The port to which the DF DNS service is bound'),
    ),
    cfg.StrOpt(
        'dns_interface',
        default='tap-dns',
        help=_('The name of the interface to bind the dns'
               'service'))
]


def register_opts():
    cfg.CONF.register_opts(df_dns_opts, group='df_dns')


def list_opts():
    return {'df_dns': df_dns_opts}
