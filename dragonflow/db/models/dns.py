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

from jsonmodels import fields

import dragonflow.db.field_types as df_fields
import dragonflow.db.model_framework as mf
from dragonflow.db.models import l2
from dragonflow.db.models import mixins

@mf.register_model
@mf.construct_nb_db_model
class DomainName(mf.ModelBase, mixins.Topic, mixins.Version, mixins.Name,
                    mixins.BasicEvents, mixins.UniqueKey):

    table_name = "domainname"
    domain_name = fields.StringField()
    subnet = df_fields.ReferenceField(l2.Subnet)


@mf.register_model
@mf.construct_nb_db_model
class DnsName(mf.ModelBase, mixins.Topic, mixins.Version, mixins.Name,
                    mixins.BasicEvents, mixins.UniqueKey):

    table_name = "dnsname"
    dns_name = fields.StringField()
    lport = df_fields.ReferenceField(l2.LogicalPort)


# TODO(lihi) add unique keys

