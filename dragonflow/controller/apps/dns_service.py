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

import hashlib
import hmac

import httplib2
import netaddr
from oslo_log import log
from oslo_utils import encodeutils
from oslo_service import service

from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.ofproto import nicira_ext
import six
import six.moves.urllib.parse as urlparse
import webob

from dragonflow._i18n import _
from dragonflow.common import exceptions
from dragonflow import conf as cfg
from dragonflow.controller.common import arp_responder
from dragonflow.controller.common import constants as const
from dragonflow.controller import df_base_app
from dragonflow.db.models import constants as model_const
from dragonflow.db.models import l2
from dragonflow.db.models import ovs


LOG = log.getLogger(__name__)

FLOW_IDLE_TIMEOUT = 60

# TODO(oanson) The TCP_* flag constants have already made it into ryu
# master, but not to pip. Once that is done, they should be taken from
# there. (ryu.lib.packet.tcp.TCP_SYN and ryu.lib.packet.tcp.TCP_ACK)
TCP_SYN = 0x002
TCP_ACK = 0x010

DNS_SERVICE_IP = "1.1.1.1"  #FIXME(lihi) remove this



class DnsServiceApp(df_base_app.DFlowApp):
    def __init__(self, *args, **kwargs):
        super(DnsServiceApp, self).__init__(*args, **kwargs)
        self._arp_responder = None
        self._ofport = None
        self._interface_mac = ""
        self._port = cfg.CONF.df_dns.port
        self._interface = cfg.CONF.df_dns.dns_interface

    def switch_features_handler(self, ev):
        #TODO(lihi): add redirext to nect table
        LOG.debug("switch feature habdler for dns")
        # if self._interface_mac and self._ofport and self._ofport > 0:
        #     # For reconnection, if the mac and ofport is set, re-download
        #     # the flows.
        #     self._add_tap_dns_port(self._ofport, self._interface_mac)

#     @df_base_app.register_event(l2.Subnet, model_const.EVENT_CREATED)
#     @df_base_app.register_event(l2.Subnet, model_const.EVENT_UPDATED)
#     def subnet_updated(self, subnet, orig_subnet=None):
#         #TODO(lihi) Add redirect here from from subnet dns to dns tap port
#         ofport = subnet.ofport
#         mac = subnet.mac_in_use
#         if not ofport or not mac:
#             return
# 
#         if ofport <= 0:
#             return
# 
#         if ofport == self._ofport and mac == self._interface_mac:
#             return
# 
#         self._add_tap_dns_port(ofport, mac)
#         self._ofport = ofport
#         self._interface_mac = mac
# 
#     @df_base_app.register_event(l2.Subnet, model_const.EVENT_DELETED)
#     def subnet_deleted(self, subnet):
#         self._remove_dns_interface_flows(subnet)
# 
#     def _remove_dns_interface_flows(self, subnet):
#         if not self._ofport:
#             return
# 
#         parser = self.parser
#         ofproto = self.ofproto
# 
#         self.mod_flow(
#             table_id=const.INGRESS_CLASSIFICATION_DISPATCH_TABLE,
#             command=ofproto.OFPFC_DELETE,
#             priority=const.PRIORITY_MEDIUM,
#             match=parser.OFPMatch(in_port=self._ofport))
# 
#         self._ofport = None
#         self._interface_mac = ""
# 
#     def _add_tap_dns_port(self, ofport, mac):
#         """
#         Add the flows that can be added with the current available information:
#         Regular Client->Server packets have IP rewritten, and sent to OVS port
#         TCP Syn packets are sent to controller, so that response flows can be
#             added.
#         Packets from the OVS port are detected and sent for classification.
#         """
#         self._ofport = ofport
#         ofproto = self.ofproto
#         parser = self.parser
#         self._add_incoming_flows()
#         # Regular packet
#         match = parser.OFPMatch(eth_type=ethernet.ether.ETH_TYPE_IP)
#         actions = self._get_rewrite_ip_and_output_actions(ofproto, parser)
#         inst = [parser.OFPInstructionActions(
#             ofproto.OFPIT_APPLY_ACTIONS,
#             actions,
#         )]
#         self.mod_flow(
#             table_id=const.DNS_SERVICE_TABLE,
#             command=ofproto.OFPFC_ADD,
#             priority=const.PRIORITY_MEDIUM,
#             match=match,
#             inst=inst,
#         )
#         # TCP SYN packet
#         match = parser.OFPMatch(
#             eth_type=ethernet.ether.ETH_TYPE_IP,
#             ip_proto=ipv4.inet.IPPROTO_TCP,
#             tcp_flags=(TCP_SYN, TCP_SYN | TCP_ACK),
#         )
#         learn_actions = self._get_learn_actions(ofproto, parser)
#         learn_actions.extend(actions)
#         inst = [parser.OFPInstructionActions(
#             ofproto.OFPIT_APPLY_ACTIONS,
#             learn_actions,
#         )]
#         self.mod_flow(
#             table_id=const.DNS_SERVICE_TABLE,
#             command=ofproto.OFPFC_ADD,
#             priority=const.PRIORITY_HIGH,
#             match=match,
#             inst=inst,
#         )
# 
#         # ARP responder
#         match = parser.OFPMatch(in_port=ofport,
#                                 eth_type=ethernet.ether.ETH_TYPE_ARP)
#         actions = [
#             parser.NXActionResubmitTable(
#                 table_id=const.DNS_SERVICE_REPLY_TABLE),
#             parser.OFPActionOutput(ofproto.OFPP_IN_PORT, 0)]
#         inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
#                                              actions)]
#         self.mod_flow(
#             table_id=const.INGRESS_CLASSIFICATION_DISPATCH_TABLE,
#             command=ofproto.OFPFC_ADD,
#             priority=const.PRIORITY_MEDIUM,
#             match=match,
#             inst=inst,
#         )
#         self._create_arp_responder(mac)
# 
#         # Response packet
#         match = parser.OFPMatch(in_port=ofport,
#                                 eth_type=ethernet.ether.ETH_TYPE_IP)
#         actions = [
#             parser.NXActionResubmitTable(
#                 table_id=const.DNS_SERVICE_REPLY_TABLE),
#             parser.NXActionResubmitTable(
#                 table_id=const.INGRESS_DISPATCH_TABLE)
#         ]
#         inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
#                                              actions)]
#         self.mod_flow(
#             table_id=const.INGRESS_CLASSIFICATION_DISPATCH_TABLE,
#             command=ofproto.OFPFC_ADD,
#             priority=const.PRIORITY_MEDIUM,
#             match=match,
#             inst=inst,
#         )
# 
#     def _add_incoming_flows(self):
#         #TODO(lihi): In here:
#         # Get port subnet and dns address
#         # Redirect to port
#         ofproto = self.ofproto
#         parser = self.parser
# 
#         match = parser.OFPMatch(
#             eth_type=ethernet.ether.ETH_TYPE_IP,
#             ipv4_dst=DNS_SERVICE_IP,
#             ip_proto=ipv4.inet.IPPROTO_TCP,
#             tcp_dst=const.DNS_HTTP_PORT,
#         )
#         inst = [parser.OFPInstructionGotoTable(
#             const.SERVICES_CLASSIFICATION_TABLE)]
#         # Bypass the security group check for dns request.
#         self.mod_flow(
#             table_id=const.EGRESS_PORT_SECURITY_TABLE,
#             command=ofproto.OFPFC_ADD,
#             priority=const.PRIORITY_VERY_HIGH,
#             match=match,
#             inst=inst)
# 
#         inst = self._get_incoming_flow_instructions(ofproto, parser)
#         self.mod_flow(
#             table_id=const.SERVICES_CLASSIFICATION_TABLE,
#             command=ofproto.OFPFC_ADD,
#             priority=const.PRIORITY_MEDIUM,
#             match=match,
#             inst=inst)
# 
#     def _get_incoming_flow_instructions(self, ofproto, parser):
#         actions = self._get_incoming_flow_actions(ofproto, parser)
#         inst = []
#         if actions:
#             inst.append(
#                 parser.OFPInstructionActions(
#                     ofproto.OFPIT_APPLY_ACTIONS,
#                     actions
#                 ),
#             )
#         inst.append(
#             parser.OFPInstructionGotoTable(const.DNS_SERVICE_TABLE)
#         )
#         return inst
# 
#     def _get_incoming_flow_actions(self, ofproto, parser):
#         actions = []
#         if self._ip != DNS_SERVICE_IP:
#             actions.append(parser.OFPActionSetField(ipv4_dst=self._ip))
#         if self._port != const.DNS_HTTP_PORT:
#             actions.append(parser.OFPActionSetField(tcp_dst=self._port))
#         return actions
# 
#     def _get_rewrite_ip_and_output_actions(self, ofproto, parser):
#         """
#         Retrieve the actions that rewrite the dst IP field with the reg6
#         (the tunnel key), set the first bit of that field, and output to the
#         dns service OVS port.
#         The IP is set to <reg6> | 0x8000000, so that the transparent proxy
#         can extract the <reg6> from the source IP address, and be able to
#         identify the source VM. reg6 holds the local DF id identifying the VM.
#         """
#         return [
#             parser.NXActionRegMove(
#                 src_field='reg6',
#                 dst_field='ipv4_src',
#                 n_bits=32,
#             ),
#             parser.NXActionRegLoad(
#                 ofs_nbits=nicira_ext.ofs_nbits(31, 31),
#                 dst="ipv4_src",
#                 value=1,),
#             parser.OFPActionOutput(
#                 self._ofport,
#                 ofproto.OFPCML_NO_BUFFER,
#             )
#         ]
# 
#     def _get_learn_actions(self, ofproto, parser):
#         return [
#             # Return flow
#             parser.NXActionLearn(
#                 table_id=const.DNS_SERVICE_REPLY_TABLE,
#                 specs=[
#                     # Match
#                     parser.NXFlowSpecMatch(
#                         src=ethernet.ether.ETH_TYPE_IP,
#                         dst=('eth_type', 0),
#                         n_bits=16,
#                     ),
#                     parser.NXFlowSpecMatch(
#                         src=ipv4.inet.IPPROTO_TCP,
#                         dst=('ip_proto', 0),
#                         n_bits=8,
#                     ),
#                     parser.NXFlowSpecMatch(
#                         src=1,
#                         dst=('ipv4_dst', 31),
#                         n_bits=1,
#                     ),
#                     parser.NXFlowSpecMatch(
#                         src=('reg6', 0),
#                         dst=('ipv4_dst', 0),
#                         n_bits=31,
#                     ),
#                     parser.NXFlowSpecMatch(
#                         src=('tcp_src', 0),
#                         dst=('tcp_dst', 0),
#                         n_bits=16,
#                     ),
#                     # Actions
#                     parser.NXFlowSpecLoad(
#                         src=('ipv4_src', 0),
#                         dst=('ipv4_dst', 0),
#                         n_bits=32,
#                     ),
#                     parser.NXFlowSpecLoad(
#                         src=int(netaddr.IPAddress(DNS_SERVICE_IP)),
#                         dst=('ipv4_src', 0),
#                         n_bits=32,
#                     ),
#                     parser.NXFlowSpecLoad(
#                         src=const.DNS_HTTP_PORT,
#                         dst=('tcp_src', 0),
#                         n_bits=16,
#                     ),
#                     parser.NXFlowSpecLoad(
#                         src=('reg6', 0),
#                         dst=('reg7', 0),
#                         n_bits=32,
#                     ),
#                 ],
#                 fin_idle_timeout=1,
#                 fin_hard_timeout=1,
#             ),
#             # ARP responder
#             parser.NXActionLearn(
#                 table_id=const.DNS_SERVICE_REPLY_TABLE,
#                 priority=const.PRIORITY_HIGH,
#                 specs=[
#                     # Match
#                     parser.NXFlowSpecMatch(
#                         src=ethernet.ether.ETH_TYPE_ARP,
#                         dst=('eth_type', 0),
#                         n_bits=16,
#                     ),
#                     parser.NXFlowSpecMatch(
#                         src=('reg6', 0),
#                         dst=('arp_tpa', 0),
#                         n_bits=31,
#                     ),
#                     parser.NXFlowSpecMatch(
#                         src=arp.ARP_REQUEST,
#                         dst=('arp_op', 0),
#                         n_bits=8,
#                     ),
#                     # Actions
#                     parser.NXFlowSpecLoad(
#                         src=0,
#                         dst=('reg6', 0),
#                         n_bits=32,
#                     ),
#                     parser.NXFlowSpecLoad(
#                         src=arp.ARP_REPLY,
#                         dst=('arp_op', 0),
#                         n_bits=8,
#                     ),
#                     parser.NXFlowSpecLoad(
#                         src=('eth_dst', 0),
#                         dst=('arp_tha', 0),
#                         n_bits=48,
#                     ),
#                     parser.NXFlowSpecLoad(
#                         src=int(netaddr.IPAddress(self._ip)),
#                         dst=('arp_tpa', 0),
#                         n_bits=32,
#                     ),
#                     parser.NXFlowSpecLoad(
#                         src=('eth_src', 0),
#                         dst=('eth_src', 0),
#                         n_bits=48,
#                     ),
#                     parser.NXFlowSpecLoad(
#                         src=('eth_src', 0),
#                         dst=('arp_sha', 0),
#                         n_bits=48,
#                     ),
#                     parser.NXFlowSpecLoad(
#                         src=('reg6', 0),
#                         dst=('arp_spa', 0),
#                         n_bits=32,
#                     ),
#                     parser.NXFlowSpecLoad(
#                         src=1,
#                         dst=('arp_spa', 31),
#                         n_bits=1,
#                     ),
#                 ],
#                 idle_timeout=30,
#             )
#         ]
# 
#     def _create_arp_responder(self, mac):
#         self._arp_responder = arp_responder.ArpResponder(
#             self,
#             None,
#             DNS_SERVICE_IP,
#             mac
#         )
#         self._arp_responder.add()


class DFDnsHandler(service.Service):
    @webob.dec.wsgify(RequestClass=webob.Request)
    def __call__(self, req):
        try:
            LOG.debug("Request: %s", req)

            # return self.proxy_request(req)
        except Exception:
            LOG.exception("Unexpected error.")
            msg = _('An unknown error has occurred. '
                    'Please try your request again.')
            explanation = six.text_type(msg)
            return webob.exc.HTTPInternalServerError(explanation=explanation)

    def __init__(self, conf, nb_api):
        super(DFDnsHandler, self).__init__()
        self.conf = conf
        self.nb_api = nb_api

    def proxy_request(self, req):
        #TODO(lihi) remove nova stuff
        headers = self.get_headers(req)
        url = urlparse.urlunsplit((
            self.get_scheme(req),
            self.get_host(req),
            self.get_path_info(req),
            self.get_query_string(req),
            ''))
        h = self.create_http_client(req)
        resp, content = h.request(
            url,
            method=req.method,
            headers=headers,
            body=req.body
        )
        if resp.status == 200:
            LOG.debug(str(resp))
            return self.create_response(req, resp, content)
        elif resp.status == 403:
            LOG.warning(
                'The remote dns server responded with Forbidden. This '
                'response usually occurs when shared secrets do not match.')
            return webob.exc.HTTPForbidden()
        elif resp.status == 400:
            return webob.exc.HTTPBadRequest()
        elif resp.status == 404:
            return webob.exc.HTTPNotFound()
        elif resp.status == 409:
            return webob.exc.HTTPConflict()
        elif resp.status == 500:
            msg = (
                'Remote dns server experienced an internal server error.'
            )
            LOG.warning(msg)
            explanation = six.text_type(msg)
            return webob.exc.HTTPInternalServerError(explanation=explanation)
        else:
            raise Exception(_('Unexpected response code: %s') % resp.status)

    def get_headers(self, req):
        return req.headers

    def create_response(self, req, resp, content):
        req.response.content_type = resp['content-type']
        req.response.body = content
        return req.response

    def get_scheme(self, req):
        return req.scheme

    def get_host(self, req):
        return req.host

    def get_path_info(self, req):
        return req.path

    def get_query_string(self, req):
        return req.query_string

    def create_http_client(self, req):
        return httplib2.Http()

    def _get_logical_port_by_tunnel_key(self, tunnel_key):
        lports = self.nb_api.get_all(l2.LogicalPort)
        for lport in lports:
            if lport.unique_key == tunnel_key:
                return lport
        raise exceptions.LogicalPortNotFoundByTunnelKey(key=tunnel_key)
