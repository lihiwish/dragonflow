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

import eventlet
from eventlet.green import zmq
from oslo_config import cfg
from oslo_log import log as logging

from dragonflow.common import exceptions
from dragonflow.db import pub_sub_api

LOG = logging.getLogger(__name__)

SUPPORTED_TRANSPORTS = set(['tcp', 'epgm'])


class ZMQPubSub(pub_sub_api.PubSubApi):
    def __init__(self):
        super(ZMQPubSub, self).__init__()
        transport = cfg.CONF.df.publisher_transport
        if transport not in SUPPORTED_TRANSPORTS:
            message = ("zmq_pub_sub: Unsupported publisher_transport value "
                       "%(transport)s, expected %(expected)s")
            LOG.error(message, {
                'transport': transport,
                'expected': SUPPORTED_TRANSPORTS
            })
            raise exceptions.UnsupportedTransportException(transport=transport)
        self.subscriber = ZMQSubscriberAgent()
        self.publisher = ZMQPublisherAgent()

    def get_publisher(self):
        return self.publisher

    def get_subscriber(self):
        return self.subscriber


class ZMQPubSubMultiproc(pub_sub_api.PubSubApi):
    def __init__(self):
        super(ZMQPubSubMultiproc, self).__init__()
        self.subscriber = ZMQSubscriberMultiprocAgent()
        self.publisher = ZMQPublisherMultiprocAgent()

    def get_publisher(self):
        return self.publisher

    def get_subscriber(self):
        return self.subscriber


class ZMQPublisherAgentBase(pub_sub_api.PublisherAgentBase):
    def __init__(self):
        self.socket = None
        self.context = None

    # Necessary, since it appears in the abstract class
    def initialize(self):
        super(ZMQPublisherAgentBase, self).initialize()
        self._connect()

    def _connect(self):
        pass

    def _send_event(self, data, topic):
        if not self.socket:
            self._connect()

        self.socket.send_multipart([topic, data])

    def close(self):
        if self.socket:
            self.socket.close()
            self.socket = None


class ZMQPublisherAgent(ZMQPublisherAgentBase):
    def __init__(self):
        super(ZMQPublisherAgent, self).__init__()
        self._endpoint = "{}://{}:{}".format(
            cfg.CONF.df.publisher_transport,
            cfg.CONF.df.publisher_bind_address,
            cfg.CONF.df.publisher_port,
        )
        self.context = zmq.Context()

    def _connect(self):
        self.socket = self.context.socket(zmq.PUB)
        self.socket.setsockopt(zmq.LINGER, 0)
        LOG.debug("About to bind to network socket: %s", self._endpoint)
        self.socket.bind(self._endpoint)


class ZMQPublisherMultiprocAgent(ZMQPublisherAgentBase):
    def __init__(self):
        super(ZMQPublisherMultiprocAgent, self).__init__()
        self.context = zmq.Context()

    def _connect(self):
        self.socket = self.context.socket(zmq.PUSH)
        ipc_socket = cfg.CONF.df.publisher_multiproc_socket
        LOG.debug("About to connect to IPC socket: %s", ipc_socket)
        self.socket.connect('ipc://%s' % ipc_socket)


class ZMQSubscriberAgentBase(pub_sub_api.SubscriberAgentBase):
    def __init__(self):
        super(ZMQSubscriberAgentBase, self).__init__()
        self.sub_socket = None
        self.context = zmq.Context()

    def register_listen_address(self, uri):
        is_new = super(ZMQSubscriberAgentBase, self).register_listen_address(
                    uri)
        if is_new and self.sub_socket:
            self.sub_socket.connect(uri)

    def connect(self):
        """Connect to the publisher"""

    def unregister_listen_address(self, uri):
        super(ZMQSubscriberAgentBase, self).unregister_listen_address(
            uri)
        if self.sub_socket:
            self.sub_socket.disconnect(uri)

    def register_topic(self, topic):
        topic = topic.encode('ascii', 'ignore')
        is_new = super(ZMQSubscriberAgentBase, self).register_topic(topic)
        if is_new and self.sub_socket:
            self.sub_socket.setsockopt(zmq.SUBSCRIBE, topic)

    def unregister_topic(self, topic):
        topic = topic.encode('ascii', 'ignore')
        super(ZMQSubscriberAgentBase, self).unregister_topic(topic)
        if self.sub_socket:
            self.sub_socket.setsockopt(zmq.UNSUBSCRIBE, topic)

    def run(self):
        self.connect()
        LOG.info("Starting Subscriber on ports %(endpoints)s",
                 {'endpoints': self.uri_list})
        while True:
            try:
                eventlet.sleep(0)
                [topic, data] = self.sub_socket.recv_multipart()
                self._handle_incoming_event(data)
            except Exception as e:
                LOG.warning(e)
                self.sub_socket.close()
                self.connect()
                self.db_changes_callback(None, None, 'sync',
                                         None, None)

    def close(self):
        self.sub_socket.close()


class ZMQSubscriberMultiprocAgent(ZMQSubscriberAgentBase):
    def connect(self):
        self.sub_socket = self.context.socket(zmq.PULL)
        ipc_socket = cfg.CONF.df.publisher_multiproc_socket
        LOG.debug("About to bind to IPC socket: %s", ipc_socket)
        self.sub_socket.bind('ipc://%s' % ipc_socket)


class ZMQSubscriberAgent(ZMQSubscriberAgentBase):
    def connect(self):
        self.sub_socket = self.context.socket(zmq.SUB)
        for uri in self.uri_list:
            # TODO(gampel) handle exp zmq.EINVAL,zmq.EPROTONOSUPPORT
            LOG.debug("About to connect to network publisher at %s", uri)
            self.sub_socket.connect(uri)
        for topic in self.topic_list:
            self.sub_socket.setsockopt(zmq.SUBSCRIBE, topic)
