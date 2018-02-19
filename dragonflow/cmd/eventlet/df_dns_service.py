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

from oslo_log import log
from oslo_service import service

from neutron.agent.common import utils
from neutron.agent.linux import ip_lib
from neutron.common import config
from neutron import wsgi

from dragonflow import conf as cfg
from dragonflow.controller.apps import dns_service
from dragonflow.controller import service as df_service
from dragonflow.db import api_nb

import sys


LOG = log.getLogger(__name__)

DNS_ROUTE_TABLE_ID = '3'  #FIXME(lihi) Change this to something else


def environment_setup():
    bridge = cfg.CONF.df.integration_bridge
    interface = cfg.CONF.df_dns.dns_interface
    port = cfg.CONF.df_dns.port
    if ip_lib.device_exists(interface):
        LOG.info("Device %s already exists", interface)
        # Destroy the environment when the device exists.
        # We can re-initialize the environment correctly.
        environment_destroy()

    cmd = ["ovs-vsctl", "add-port", bridge, interface,
           "--", "set", "Interface", interface, "type=internal"]
    utils.execute(cmd, run_as_root=True)

    #FIXME(lihi) Should we set the ip to the interdace somewhere? Where do we receive the IP from?
    # ip = cfg.CONF.df_dns.ip
    # cmd = ["ip", "addr", "add", "dev", interface, "{}/0".format(ip)]
    # utils.execute(cmd, run_as_root=True)

    cmd = ["ip", "link", "set", "dev", interface, "up"]
    utils.execute(cmd, run_as_root=True)

    cmd = ["ip", "route", "add", "0.0.0.0/0", "dev", interface,
           "table", dns_ROUTE_TABLE_ID]
    utils.execute(cmd, run_as_root=True)

    # cmd = ["ip", "rule", "add", "from", ip, "table", dns_ROUTE_TABLE_ID]
    # utils.execute(cmd, run_as_root=True)

    cmd = ["iptables", '-I', 'INPUT', '-i', interface, '-p', 'tcp', '--dport',
           str(port), '-j', 'ACCEPT']
    utils.execute(cmd, run_as_root=True)


def environment_destroy():
    bridge = cfg.CONF.df.integration_bridge
    interface = cfg.CONF.df_dns.dns_interface
    cmd = ["ovs-vsctl", "del-port", bridge, interface]
    utils.execute(cmd, run_as_root=True, check_exit_code=[0])

    # ip = cfg.CONF.df_dns.ip
    # cmd = ["ip", "rule", "del", "from", ip, "table", dns_ROUTE_TABLE_ID]
    # utils.execute(cmd, run_as_root=True)


def main():
    config.init(sys.argv[1:])
    config.setup_logging()
    environment_setup()
    #FIXME(lihi):Do we might need pubusb
    cfg.CONF.set_override('enable_df_pub_sub', False, group='df')
    nb_api = api_nb.NbApi.get_instance(False)
    service_instance = dns_service.DFDnsHandler(
            cfg.CONF, nb_api)
    df_service.register_service(
            'df-dns-service', nb_api, service_instance)
    service.launch(cfg.CONF, service_instance).wait()
    # service = wsgi.Server('dragonflow-dns-service', disable_ssl=True)
    # service.start(
    #     service_instance,
    #     port=cfg.CONF.df_dns.port,
    # )
    service.wait()
    environment_destroy()
