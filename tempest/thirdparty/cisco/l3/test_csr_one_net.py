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
import collections

import re

from tempest.api.network import common as net_common
from tempest.common import debug
from tempest.common.utils import data_utils
from tempest import config
from tempest.openstack.common import log as logging
from tempest.scenario import manager
from tempest import test
from tempest.scenario.test_network_basic_ops import TestNetworkBasicOps

CONF = config.CONF
LOG = logging.getLogger(__name__)


class TestCSROneNet(TestNetworkBasicOps):

    @classmethod
    def check_preconditions(cls):
        super(TestCSROneNet, cls).check_preconditions()
        LOG.debug("check_preconditions")

    @classmethod
    def setUpClass(cls):
        super(TestCSROneNet, cls).setUpClass()
        LOG.debug("setupUpClass")
        cls.tenant_id = cls.manager.identity_client.tenant_id
        #cls.check_preconditions()

    def cleanup_wrapper(self, resource):
        self.cleanup_resource(resource, self.__class__.__name__)
        LOG.debug("cleanup_wrapper")

    def setUp(self):
        super(TestCSROneNet, self).setUp()
        LOG.debug("setUp")

    def test_csr_one_net(self):
        LOG.debug("test_csr_one_net")
        LOG.debug("Tenant ID: {0}".format(self.tenant_id))
        self._create_new_network()
        LOG.debug("Network: {0}".format(self.new_net))
        pass
