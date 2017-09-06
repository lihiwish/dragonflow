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

import etcd3gw
import threading

from oslo_config import cfg
from oslo_log import log as logging

# from dragonflow.common import exceptions
from dragonflow.db import pub_sub_api


LOG = logging.getLogger(__name__)

PUBSUB_DB_PREFIX = "pubsub"


def _get_topic_watch_prefix(topic):
    topic_prefix = "/{}/{}".format(PUBSUB_DB_PREFIX, topic)
    return topic_prefix


class EtcdPubSub(pub_sub_api.PubSubApi):
    def __init__(self):
        super(EtcdPubSub, self).__init__()
        self.subscriber = EtcdSubscriberAgent()
        self.publisher = EtcdPublisherAgent()

    def get_publisher(self):
        return self.publisher

    def get_subscriber(self):
        return self.subscriber


class EtcdPublisherAgent(pub_sub_api.PublisherAgentBase):
    def __init__(self):
        super(EtcdPublisherAgent, self).__init__()
        self.client = None

    def initialize(self):
        super(EtcdPublisherAgent, self).__init__()
        self.client = etcd3gw.client(host=cfg.CONF.df.remote_db_ip,
                                     port=cfg.CONF.df.remote_db_port)

    def _send_event(self, data, topic):
        topic_prefix = _get_topic_watch_prefix(topic)
        LOG.error("TFFF PUB 3 _send event to key=%s", topic_prefix)
        self.client.put(topic_prefix, data)

    def close(self):
        # TODO(lihi)
        pass


class WatcherThread(threading.Thread):
    def __init__(self, etcd_client, kwargs):
        super(WatcherThread, self).__init__(target=self.startWatch,
                                            kwargs=kwargs)
        self.daemon = True
        self.client = etcd_client

    def startWatch(self, topic, handle_event):
        topic_prefix = _get_topic_watch_prefix(topic)
        LOG.error("TFFF 2 in start watch with topic {}".format(topic_prefix))
        events, self._cancel = self.client.watch(topic_prefix)
        LOG.error("TFFF 2.1")
        for event in events:
            LOG.error("TFFF 4 Got event!!!! = topic = {} event = {}".format(
                topic,
                event))
            handle_event(event)

    def cancel(self):
        LOG.error("TFFF SUB in T cancel")
        self._cancel()


class EtcdSubscriberAgent(pub_sub_api.SubscriberApi):
    def __init__(self):
        self.topic_list = {}
        self.uri_list = []
        self.running = False
        self.client = None
        super(EtcdSubscriberAgent, self).__init__()

    def initialize(self, callback):
        self.db_changes_callback = callback
        self.stop_event = threading.Event()
        LOG.error("TFFF SUB starting subcscriber. host = {} ip={}".format(
            cfg.CONF.df.remote_db_ip,
            cfg.CONF.df.remote_db_port))
        self.client = etcd3gw.client(host=cfg.CONF.df.remote_db_ip,
                                     port=cfg.CONF.df.remote_db_port)

    def _get_topic_thread(self, topic):
        topic_thread = WatcherThread(
            etcd_client=self.client,
            kwargs={'topic': topic,
                    'handle_event': self.handle_event})
        return topic_thread

    def daemonize(self):
        # Start watching
        self.running = True
        for topic in self.topic_list:
            self.topic_list[topic].start()

    def close(self):
        # TODO(lihi): stop threads
        self.running = False
        for topic in self.topic_list:
            self._stop_topic_watch(self.topic_list[topic])

    def register_topic(self, topic):
        LOG.error('TFFF SUB 1 Register topic %s', topic)
        if topic not in self.topic_list:
            topic_thread = self._get_topic_thread(topic)
            self.topic_list[topic] = topic_thread
            if self.running:
                topic_thread.start()
            return True
        return False

    def unregister_topic(self, topic):
        LOG.info('Unregister topic %s', topic)
        LOG.error("TFFF SUB removing topic {} from watch".format(topic))
        if self.running:
            self._stop_topic_watch(self.topic_list[topic])
        del self.topic_list[topic]

    def _stop_topic_watch(self, topic_thread):
        LOG.error("TFFF calling stop on watcher")
        topic_thread.cancel()

    def handle_event(self, event):
        # TODO(lihi) not working.
        LOG.info(" TFFF SUB 5 event = {}".format(event))
        unpacked_event = pub_sub_api.unpack_message(event["kv"]["value"])
        LOG.info(" TFFF SUB 6 unpacked event = {}".format(unpacked_event))
        self.db_changes_callback(
            unpacked_event['table'],
            unpacked_event['key'],
            unpacked_event['action'],
            unpacked_event['value'],
            unpacked_event['topic'],
        )

    def register_listen_address(self, uri):
        # TODO(lihi)
        pass

    def unregister_listen_address(self, topic):
        # TODO(lihi)
        pass

    def run(self):
        # Not needed
        pass

    # TODO(lihi) these method ar mandatory. Add them ot the interface
    def set_subscriber_for_failover(self, sub, callback):
        pass

    def register_hamsg_for_db(self):
        pass

    def process_ha(self):
        pass
