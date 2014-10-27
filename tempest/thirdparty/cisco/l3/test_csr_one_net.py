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
from tempest import exceptions

CONF = config.CONF
LOG = logging.getLogger(__name__)

Floating_IP_tuple = collections.namedtuple('Floating_IP_tuple',
                                           ['floating_ip', 'server'])


class TestCSROneNet(manager.NetworkScenarioTest):

    @classmethod
    def check_preconditions(cls):
        super(TestCSROneNet, cls).check_preconditions()
        LOG.debug("check_preconditions: Start")
        if not (CONF.network.tenant_networks_reachable
                or CONF.network.public_network_id):
            msg = ('Either tenant_networks_reachable must be "true", or '
                   'public_network_id must be defined.')
            cls.enabled = False
            raise cls.skipException(msg)
        LOG.debug("check_preconditions: End")

    @classmethod
    def setUpClass(cls):
        LOG.debug("setUpClass: Start")
        # Create no network resources for these tests.
        cls.set_network_resources()
        super(TestCSROneNet, cls).setUpClass()

        cls.tenant_id = cls.manager.identity_client.tenant_id
        LOG.debug("Tenant ID: {0}".format(cls.tenant_id))
        for ext in ['router', 'security-group']:
            if not test.is_extension_enabled(ext, 'network'):
                msg = "%s extension not enabled." % ext
                raise cls.skipException(msg)
        cls.check_preconditions()
        LOG.debug("setUpClass: End")

    def cleanup_wrapper(self, resource):
        self.cleanup_resource(resource, self.__class__.__name__)
        LOG.debug("cleanup_wrapper")

    def setUp(self):
        super(TestCSROneNet, self).setUp()
        LOG.debug("setUp: Start")
        self.security_group = self._create_security_group_neutron(tenant_id=self.tenant_id, namestart='csr1')
        self.addCleanup(self.cleanup_wrapper, self.security_group)
        self.servers = {}

        self.network1, self.subnet, self.router = self._create_networks(tenant_id=self.tenant_id)
        for r in [self.network1, self.router, self.subnet]:
            self.addCleanup(self.cleanup_wrapper, r)
        self.network = self.network1
        self.check_networks()

        name = data_utils.rand_name('server-net1')
        serv_dict = self._create_server(name, self.network1)
        self.servers[serv_dict['server']] = serv_dict['keypair']

        LOG.debug("Router {0} ID is {1}".format(self.router, self.router.id))
        CONF.network.public_router_id = self.router.id
        self.network2, self.subnet, self.router = self._create_networks(tenant_id=self.tenant_id)
        for r in [self.network2, self.subnet]:
            self.addCleanup(self.cleanup_wrapper, r)
        self.network = self.network2
        self.check_networks()

        name = data_utils.rand_name('server-net2')
        LOG.debug("Attempting to bring up server {0}".format(name))
        LOG.debug("   Network: {0}".format(self.network2))
        serv_dict = self._create_server(name, self.network2)
        self.servers[serv_dict['server']] = serv_dict['keypair']

        self._check_tenant_network_connectivity()
        self._create_and_associate_floating_ips()
        LOG.debug("setUp: End")

    def _check_tenant_network_connectivity(self):
        ssh_login = CONF.compute.image_ssh_user
        for server, key in self.servers.iteritems():
            # call the common method in the parent class
            super(TestCSROneNet, self).\
                _check_tenant_network_connectivity(
                    server, ssh_login, key.private_key,
                    servers_for_debug=self.servers.keys())

    def check_networks(self):
        """
        Checks that we see the newly created network/subnet/router via
        checking the result of list_[networks,routers,subnets]
        """
        seen_nets = self._list_networks()
        seen_names = [n['name'] for n in seen_nets]
        seen_ids = [n['id'] for n in seen_nets]
        self.assertIn(self.network.name, seen_names)
        self.assertIn(self.network.id, seen_ids)

        seen_subnets = self._list_subnets()
        seen_net_ids = [n['network_id'] for n in seen_subnets]
        seen_subnet_ids = [n['id'] for n in seen_subnets]
        self.assertIn(self.network.id, seen_net_ids)
        self.assertIn(self.subnet.id, seen_subnet_ids)

        seen_routers = self._list_routers()
        seen_router_ids = [n['id'] for n in seen_routers]
        seen_router_names = [n['name'] for n in seen_routers]
        self.assertIn(self.router.name,
                      seen_router_names)
        self.assertIn(self.router.id,
                      seen_router_ids)

    def _create_and_associate_floating_ips(self):
        public_network_id = CONF.network.public_network_id
        for server in self.servers.keys():
            floating_ip = self._create_floating_ip(server, public_network_id)
            self.floating_ip_tuple = Floating_IP_tuple(floating_ip, server)
            self.addCleanup(self.cleanup_wrapper, floating_ip)

    def _create_new_network(self):
        LOG.debug("_create_new_network: Start")
        self.new_net = self._create_network(self.tenant_id)
        self.addCleanup(self.cleanup_wrapper, self.new_net)
        self.new_subnet = self._create_subnet(
            network=self.new_net,
            namestart='csr-smoke',
            gateway_ip=None)
        self.addCleanup(self.cleanup_wrapper, self.new_subnet)
        LOG.debug("_create_new_network: End")

    def _create_server(self, name, network):
        LOG.debug("_create_server: Start")
        keypair = self.create_keypair(name='keypair-%s' % name)
        self.addCleanup(self.cleanup_wrapper, keypair)
        security_groups = [self.security_group.name]
        #'security_groups': security_groups,
        create_kwargs = {
            'nics': [
                {'net-id': network.id},
            ],
            'key_name': keypair.name,
        }
        server = self.create_server(name=name, create_kwargs=create_kwargs)
        self.addCleanup(self.cleanup_wrapper, server)
        LOG.debug("_create_server: End")
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

    def _check_network_external_connectivity(self):
        """
        ping public network default gateway to imply external connectivity

        """
        if not CONF.network.public_network_id:
            msg = 'public network not defined.'
            LOG.info(msg)
            return

        subnet = self.network_client.list_subnets(
            network_id=CONF.network.public_network_id)['subnets']
        self.assertEqual(1, len(subnet), "Found %d subnets" % len(subnet))

        external_ips = [subnet[0]['gateway_ip']]
        self._check_server_connectivity(self.floating_ip_tuple.floating_ip,
                                        external_ips)

    def _check_server_connectivity(self, floating_ip, address_list):
        ip_address = floating_ip.floating_ip_address
        private_key = self.servers[self.floating_ip_tuple.server].private_key
        ssh_source = self._ssh_to_server(ip_address, private_key)

        for remote_ip in address_list:
            try:
                self.assertTrue(self._check_remote_connectivity(ssh_source,
                                                                remote_ip),
                                "Timed out waiting for %s to become "
                                "reachable" % remote_ip)
            except Exception:
                LOG.exception("Unable to access {dest} via ssh to "
                              "floating-ip {src}".format(dest=remote_ip,
                                                         src=floating_ip))
                debug.log_ip_ns()
                raise

    def _check_public_network_connectivity(self, should_connect=True,
                                           msg=None):
        ssh_login = CONF.compute.image_ssh_user
        floating_ip, server = self.floating_ip_tuple
        ip_address = floating_ip.floating_ip_address
        private_key = None
        if should_connect:
            private_key = self.servers[server].private_key
        # call the common method in the parent class
        super(TestCSROneNet, self)._check_public_network_connectivity(
            ip_address, ssh_login, private_key, should_connect, msg,
            self.servers.keys())

    def test_csr_one_net(self):

        LOG.debug("test_csr_one_net: Start")
        LOG.debug("Tenant ID: {0}".format(self.tenant_id))
        LOG.debug("Current Creds: {0}".format(self.credentials()))
        LOG.debug("Admin Creds: {0}".format(self.admin_credentials()))
        LOG.debug("Pub-network = {0}".format(CONF.network.public_network_id))

        current_nets = self._list_networks()
        for net in current_nets:
            LOG.debug("===========================================")
            LOG.debug("Network:  {0}".format(net['name']))
            LOG.debug("  Status: {0}".format(net['status']))
            LOG.debug("  Provider Seg ID: {0}".format(net['provider:segmentation_id']))
            LOG.debug("  Subnets:{0}".format((net['subnets'])))
            subnet = self._list_subnets(id=net['subnets'].pop()).pop()
            LOG.debug("   Subnet: {0}".format(subnet['name']))
            LOG.debug("    CIDR: {0}".format(subnet['cidr']))
            LOG.debug("===========================================")

        LOG.debug("Servers: {0}".format(self.servers))
        LOG.debug("Check Public Network Connectivity: Start")
        self._check_public_network_connectivity(should_connect=True)
        LOG.debug("Check Public Network Connectivity: End")
        LOG.debug("Check Network Internal Connectivity for Network1: Start")
        self._check_network_internal_connectivity(self.network1)
        LOG.debug("Check Network Internal Connectivity for Network1: End")
        LOG.debug("Check Network Internal Connectivity for Network2: Start")
        self._check_network_internal_connectivity(self.network2)
        LOG.debug("Check Network Internal Connectivity for Network2: End")
        LOG.debug("Check Network External Connectivity: Start")
        self._check_network_external_connectivity()
        LOG.debug("Check Network External Connectivity: End")
        LOG.debug("test_csr_one_net: End")

