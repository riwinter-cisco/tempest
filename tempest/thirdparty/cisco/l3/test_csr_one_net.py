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

CONF = config.CONF
LOG = logging.getLogger(__name__)


class TestCSROneNet(manager.NetworkScenarioTest):

    @classmethod
    def check_preconditions(cls):
        super(TestCSROneNet, cls).check_preconditions()
        LOG.debug("check_preconditions")

    @classmethod
    def setUpClass(cls):
        super(TestCSROneNet, cls).setUpClass()
        LOG.debug("setupUpClass")
        cls.tenant_id = cls.manager.identity_client.tenant_id
        LOG.debug("Tenant ID: {0}".format(cls.tenant_id))
        #cls.check_preconditions()

    def cleanup_wrapper(self, resource):
        self.cleanup_resource(resource, self.__class__.__name__)
        LOG.debug("cleanup_wrapper")

    def setUp(self):
        super(TestCSROneNet, self).setUp()
        LOG.debug("setUp")
        #self.security_group = self._create_security_group_neutron(tenant_id=self.tenant_id, namestart='csr')

    def _create_new_network(self):
        self.new_net = self._create_network(self.tenant_id)
        self.addCleanup(self.cleanup_wrapper, self.new_net)
        self.new_subnet = self._create_subnet(
            network=self.new_net,
            gateway_ip=None)
        self.addCleanup(self.cleanup_wrapper, self.new_subnet)

    def _create_server(self, name, network):
        keypair = self.create_keypair(name='keypair-%s' % name)
        self.addCleanup(self.cleanup_wrapper, keypair)
        #security_groups = [self.security_group.name]
        security_groups = ['default']
        create_kwargs = {
            'nics': [
                {'net-id': network.id},
            ],
            'key_name': keypair.name,
            'security_groups': security_groups,
        }
        server = self.create_server(name=name, create_kwargs=create_kwargs)
        self.addCleanup(self.cleanup_wrapper, server)
        return dict(server=server, keypair=keypair)

    def _check_network_internal_connectivity(self, network):
        """
        via ssh check VM internal connectivity:
        - ping internal gateway and DHCP port, implying in-tenant connectivity
        pinging both, because L3 and DHCP agents might be on different nodes
        """
        floating_ip, server = self.floating_ip_tuple
        # get internal ports' ips:
        # get all network ports in the new network
        internal_ips = (p['fixed_ips'][0]['ip_address'] for p in
                        self._list_ports(tenant_id=server.tenant_id,
                                         network_id=network.id)
                        if p['device_owner'].startswith('network'))

        self._check_server_connectivity(floating_ip, internal_ips)

    def test_csr_one_net(self):

        LOG.debug("test_csr_one_net")
        LOG.debug("Tenant ID: {0}".format(self.tenant_id))
        LOG.debug("CONF = {0}".format(CONF))

        seen_nets = self._list_networks()
        LOG.debug("Seen nets = {0}".format(seen_nets))
        for net in seen_nets:
            LOG.debug("===========================================")
            LOG.debug("Network:  {0}".format(net['name']))
            LOG.debug("  Status: {0}".format(net['status']))
            LOG.debug("  Provider Seg ID: {0}".format(net['provider:segmentation_id']))
            LOG.debug("  Subnets:{0}".format((net['subnets'])))
            #subnets = self._list_subnets()


        #self._create_new_network()
        #LOG.debug("New Network: {0}".format(self.new_net))
        #LOG.debug("New Subnet: {0}".format(self.new_subnet))

        ## Create a VM on the network
        #serv_dict = self._create_server("TVM1", self.new_net)
        #self.servers[serv_dict['server']] = serv_dict['keypair']
        #LOG.debug("Server dictionary:  {0}".format(serv_dict))

        ## Create a 2nd VM on the network
        #serv_dict = self._create_server("TVM2", self.new_net)
        #self.servers[serv_dict['server']] = serv_dict['keypair']
        #LOG.debug("Server dictionary:  {0}".format(serv_dict))

