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
import time

from sys import stdin
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

        self.network, self.subnet, self.router = self._create_networks(tenant_id=self.tenant_id)
        for r in [self.network, self.router, self.subnet]:
            self.addCleanup(self.cleanup_wrapper, r)
        self.check_networks()

        name = data_utils.rand_name('server')
        serv_dict = self._create_server(name, self.network)
        self.servers[serv_dict['server']] = serv_dict['keypair']

        #name = data_utils.rand_name('server')
        #serv_dict = self._create_server(name, self.network)
        #self.servers[serv_dict['server']] = serv_dict['keypair']

        self._check_tenant_network_connectivity()
        self._create_and_associate_floating_ips()
        LOG.debug("setUp: End")

    def _check_tenant_network_connectivity(self):
        LOG.debug("_check_tenant_network_connectivity: Start")
        ssh_login = CONF.compute.image_ssh_user
        LOG.debug("SSH Login: {0}".format(ssh_login))
        for server, key in self.servers.iteritems():
            LOG.debug("Server {0}, key {1}".format(server, key))
            # call the common method in the parent class
            super(TestCSROneNet, self).\
                _check_tenant_network_connectivity(
                    server, ssh_login, key.private_key,
                    servers_for_debug=self.servers.keys())
        LOG.debug("_check_tenant_network_connectivity: End")

    def check_networks(self):
        """
        Checks that we see the newly created network/subnet/router via
        checking the result of list_[networks,routers,subnets]
        """
        LOG.debug("check_networks: Start")
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
        LOG.debug("check_networks: End")

    def _create_and_associate_floating_ips(self):
        LOG.debug("_create_and_associate_floating_ips: Start")
        public_network_id = CONF.network.public_network_id
        for server in self.servers.keys():
            floating_ip = self._create_floating_ip(server, public_network_id)
            self.floating_ip_tuple = Floating_IP_tuple(floating_ip, server)
            self.addCleanup(self.cleanup_wrapper, floating_ip)
        LOG.debug("_create_and_associate_floating_ips: End")

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

        create_kwargs = {
            'nics': [
                {'net-id': network.id},
            ],
            'key_name': keypair.name,
            'security_groups': security_groups,
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
        LOG.debug("_check_network_internal_connectivity: Start")
        floating_ip, server = self.floating_ip_tuple
        # get internal ports' ips:
        # get all network ports in the new network
        internal_ips = (p['fixed_ips'][0]['ip_address'] for p in
                        self._list_ports(tenant_id=server.tenant_id,
                                         network_id=network.id)
                        if p['device_owner'].startswith('network'))
        LOG.debug("Checking server : {0}".format(server))
        LOG.debug("    Network     : {0}".format(network))
        LOG.debug("    Floating IP : {0}".format(floating_ip))
        LOG.debug("    Internal IPs: {0}".format(internal_ips))
        self._check_server_connectivity(floating_ip, internal_ips)
        LOG.debug("_check_network_internal_connectivity: End")

    def _check_network_external_connectivity(self):
        """
        ping public network default gateway to imply external connectivity

        """
        LOG.debug("_check_network_external_connectivity: Start")
        if not CONF.network.public_network_id:
            msg = 'public network not defined.'
            LOG.info(msg)
            return

        subnet = self.network_client.list_subnets(
            network_id=CONF.network.public_network_id)['subnets']
        self.assertEqual(1, len(subnet), "Found %d subnets" % len(subnet))

        external_ips = [subnet[0]['gateway_ip']]

        LOG.debug("External IPs: {0}".format(external_ips))
        LOG.debug("Floating IP : {0}".format(self.floating_ip_tuple.floating_ip))
        self._check_server_connectivity(self.floating_ip_tuple.floating_ip,
                                        external_ips)
        LOG.debug("_check_network_external_connectivity: End")

    def _check_server_connectivity(self, floating_ip, address_list):
        LOG.debug("_check_server_connectivity: Start")
        ip_address = floating_ip.floating_ip_address
        private_key = self.servers[self.floating_ip_tuple.server].private_key
        ssh_source = self._ssh_to_server(ip_address, private_key)
        LOG.debug(" IP Address : {0}".format(ip_address))
        LOG.debug(" Private Key: {0}".format(private_key))
        LOG.debug(" SSH Source : {0}".format(ssh_source))
        for remote_ip in address_list:
            LOG.debug("Checking remote IP: {0}".format(remote_ip))
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
        LOG.debug("_check_server_connectivity: Start")

    def _check_public_network_connectivity(self, should_connect=True, msg=None):
        LOG.debug("_check_public_network_connectivity: Start")
        ssh_login = CONF.compute.image_ssh_user
        floating_ip, server = self.floating_ip_tuple
        ip_address = floating_ip.floating_ip_address
        LOG.debug("ssh_login  : {0}".format(ssh_login))
        LOG.debug("floating ip: {0}".format(floating_ip))
        LOG.debug("IP Address : {0}".format(ip_address))
        private_key = None
        if should_connect:
            private_key = self.servers[server].private_key
        # call the common method in the parent class
        super(TestCSROneNet, self)._check_public_network_connectivity(
            ip_address, ssh_login, private_key, should_connect, msg,
            self.servers.keys())
        LOG.debug("_check_public_network_connectivity: End")

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
        LOG.debug("Check Network Internal Connectivity for Network: Start")
        LOG.debug("Floating IP Tuple: {0}".format(self.floating_ip_tuple))
        floating_ip, server = self.floating_ip_tuple
        LOG.debug("Floating IP: {0}".format(floating_ip.floating_ip_address))

        subnet = self.network_client.list_subnets(
            network_id=CONF.network.public_network_id)['subnets']

        external_ips = [subnet[0]['gateway_ip']]
        LOG.debug("External IPs: {0}".format(external_ips[0]))

        gw = external_ips[0]
        LOG.debug("Pinging GW: {0}".format(gw))
        ping_result = self._ping_ip_address(gw)
        LOG.debug("Ping result : {0}".format(ping_result))
        self.assertTrue(ping_result, "Ping of gw {0} failed".format(gw))

        time.sleep(60)
        LOG.debug("Pinging floating IP ")
        ping_result = False
        for i in range(0, 10):
            try:
                ping_result = self._ping_ip_address(floating_ip.floating_ip_address)
                LOG.debug("Ping result : {0}".format(ping_result))
                if ping_result is True:
                    break
            except exceptions.TimeoutException as e:
                pass

            time.sleep(2)

        self.assertTrue(ping_result,
                        "Ping of floating IP {0} failed".format(floating_ip.floating_ip_address))

        self._check_network_internal_connectivity(self.network)
        LOG.debug("Check Network Internal Connectivity for Network: End")
        LOG.debug("Check Network External Connectivity: Start")
        #self._check_network_external_connectivity()
        LOG.debug("Check Network External Connectivity: End")
        LOG.debug("Check Public Network Connectivity: Start")
        #self._check_public_network_connectivity(should_connect=True)
        LOG.debug("Check Public Network Connectivity: End")
        LOG.debug("test_csr_one_net: End")

