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

from tempest.common.utils import data_utils
from tempest import config
from tempest.openstack.common import log as logging
from tempest.scenario import manager
from tempest import test
from tempest import exceptions
from tempest.thirdparty.cisco.lib import nx_mgr

CONF = config.CONF
LOG = logging.getLogger(__name__)

Floating_IP_tuple = collections.namedtuple('Floating_IP_tuple',
                                           ['floating_ip', 'server'])


class TestCSROneNet(manager.NetworkScenarioTest):

    @classmethod
    def credentials(cls):
        return cls.admin_credentials()

    @classmethod
    def check_preconditions(cls):
        super(TestCSROneNet, cls).check_preconditions()
        if not (CONF.network.tenant_networks_reachable
                or CONF.network.public_network_id):
            msg = ('Either tenant_networks_reachable must be "true", or '
                   'public_network_id must be defined.')
            cls.enabled = False
            raise cls.skipException(msg)

        ## Variables used to determine if Cisco gear is defined
        ## in the tempest.conf file
        cls.setup_has_cisco_n1kv = False
        cls.setup_has_cisco_csr = False
        cls.setup_has_leaf_sw = False

        if CONF.cisco.vsm_ip:
            cls.vsm_ip = CONF.cisco.vsm_ip
            if cls.vsm_ip is not None:
                cls.setup_has_cisco_n1kv = True
            ## These attributes have defaults
            cls.vsm_username = CONF.cisco.vsm_username
            cls.vsm_password = CONF.cisco.vsm_password

        if CONF.cisco.csr_ip:
            cls.csr_ip = CONF.cisco.csr_ip
            if cls.csr_ip is not None:
                cls.setup_has_cisco_csr = True
            ## These attributes have defaults
            cls.csr_username = CONF.cisco.csr_username
            cls.csr_password = CONF.cisco.csr_password

        if CONF.cisco.leaf_sws:
            cls.leaf_sws = CONF.cisco.leaf_sws

            if cls.leaf_sws is not None:
                cls.setup_has_leaf_sw = True
                if not CONF.cisco.leaf_sw_connections:
                    msg = "leaf_sw_connections must be defined when leaf_sws is specified"
                    cls.enabled = False
                    raise cls.skipException(msg)

    @classmethod
    def setUpClass(cls):
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

        cls.nx_onep = None
        if cls.setup_has_leaf_sw:
            ## This test requires one switch - mulit switch is not supported
            sw_attrs_data = (CONF.cisco.leaf_sws[0]).split(':')
            if len(sw_attrs_data) != 4:
                msg = 'Tempest config error: CONF.cisco.leaf_sws expected 4 values'
                raise cls.skipException(msg)

            cls.leaf_sw_attrs = {'ip':  sw_attrs_data[0],
                                 'username': sw_attrs_data[1],
                                 'password': sw_attrs_data[2],
                                 'ssh_port': sw_attrs_data[3]}

            cls.leaf_sw_conns = []
            for conn in CONF.cisco.leaf_sw_connections:
                conn_data = conn.split(':')
                if len(conn_data) != 3:
                    msg = 'Tempest config error: CONF.cisco.leaf_sw_connections expected 3 values'
                    raise cls.skipException(msg)

                conn_attrs = {'switch_ip': conn_data[0],
                              'node-name': conn_data[1],
                              'port': conn_data[2]}
            cls.leaf_sw_conns.append(conn_attrs)

            ## Create the NxMgr object based on OneP API
            cls.nx_onep = nx_mgr.NxOnePMgr(switch_ip=cls.leaf_sw_attrs['ip'],
                                           username=cls.leaf_sw_attrs['username'],
                                           password=cls.leaf_sw_attrs['password'])
            cls.nx_onep.connect()

    @classmethod
    def tearDownClass(cls):
        super(TestCSROneNet, cls).tearDownClass()
        ## Must tear down OneP connection here - heart beat thread will continue
        ## to run until disconnect called
        if cls.setup_has_leaf_sw and cls.nx_onep is not None:
            cls.nx_onep.disconnect()

    def cleanup_wrapper(self, resource):
        self.cleanup_resource(resource, self.__class__.__name__)

    def setUp(self):
        super(TestCSROneNet, self).setUp()
        self.servers = {}
        self.floating_ip_tuples = []
        self.linux_client = None
        self.imix_pkts = (64, 572, 1500)

        ## Security groups not supported on N1kv - so we don't configured them
        ## if there isn't a N1Kv vsm
        if not self.setup_has_cisco_n1kv:
            self.security_group = self._create_security_group_neutron(tenant_id=self.tenant_id)
            try:
                self._create_loginable_secgroup_rule_neutron(secgroup=self.security_group)
            except Exception as e:
                LOG.debug("Login sec group already exists: {0}".format(e))

            self.addCleanup(self.cleanup_wrapper, self.security_group)

        self.network, self.subnet, self.router = self._create_networks(tenant_id=self.tenant_id)

        if self.setup_has_leaf_sw:
            ## Setup vlan event monitor based on ports in found in tempest.config
            for leaf_connection in self.leaf_sw_conns:
                self.nx_onep.monitor_vlan_state(leaf_connection['port'], self.network['provider:segmentation_id'])

        for r in [self.network, self.router, self.subnet]:
            self.addCleanup(self.cleanup_wrapper, r)
        self.check_networks()

        name = data_utils.rand_name('server')
        serv_dict = self._create_server(name, self.network)
        self.servers[serv_dict['server']] = serv_dict['keypair']

        name = data_utils.rand_name('server')
        serv_dict = self._create_server(name, self.network)
        self.servers[serv_dict['server']] = serv_dict['keypair']

        if self.setup_has_leaf_sw:
            self.num_vlan_events = 0
            ## Collect the number of vlan events seen during VM creation
            for leaf_connection in self.leaf_sw_conns:
                self.num_vlan_events += \
                    self.nx_onep.get_num_interface_events(leaf_connection['port'],
                                                          self.network['provider:segmentation_id'])

            self.assertGreaterEqual(1, self.num_vlan_events, 'Minimum number of VLAN events is incorrect')

        self._check_tenant_network_connectivity()
        self._create_and_associate_floating_ips()

    def _check_tenant_network_connectivity(self):
        ssh_login = CONF.compute.image_ssh_user
        for server, key in self.servers.iteritems():
            LOG.debug("Server {0}, key {1}".format(server, key))
            # call the common method in the parent class
            super(TestCSROneNet, self)._check_tenant_network_connectivity(
                server, ssh_login, key.private_key, servers_for_debug=self.servers.keys())

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
            self.floating_ip_tuples.append(self.floating_ip_tuple)
            self.addCleanup(self.cleanup_wrapper, floating_ip)

    def _create_new_network(self):
        self.new_net = self._create_network(self.tenant_id)
        self.addCleanup(self.cleanup_wrapper, self.new_net)
        self.new_subnet = self._create_subnet(
            network=self.new_net,
            namestart='csr-smoke',
            gateway_ip=None)
        self.addCleanup(self.cleanup_wrapper, self.new_subnet)

    def _create_server(self, name, network):
        keypair = self.create_keypair(name='keypair-%s' % name)
        self.addCleanup(self.cleanup_wrapper, keypair)
        create_kwargs = {
            'nics': [
                {'net-id': network.id},
            ],
            'key_name': keypair.name,
        }
        ## This is done to support both test beds that have N1Kv vsm and
        ## test beds that do not.  Modify later when N1Kv vsm supports
        ## security groups
        try:
            security_groups = [self.security_group.name]
            create_kwargs['security_groups'] = security_groups
        except AttributeError as e:
            LOG.debug("Skipping security group config on server")

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
        self._check_server_connectivity(self.floating_ip_tuple.floating_ip, external_ips)

    def _check_server_connectivity(self, floating_ip, address_list):
        ip_address = floating_ip.floating_ip_address
        private_key = self.servers[self.floating_ip_tuple.server].private_key
        ssh_source = self._ssh_to_server(ip_address, private_key)

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

    def _check_public_network_connectivity(self, should_connect=True, msg=None):
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

    def _ping_east_by_southwest(self, linux_client, target_ip, count=1, size=56):
        """
        :param linux_client: A remote_client object
        :param target_ip: The IP Address to ping from the remote client
        :param count: How many pings
        :param size: The packet size
        :return: A dictionary with received pkts/byts, summary, round-trip data
        """
        ping_data = {}
        bytes_rx = 0
        pkts_rx = 0

        pings = re.compile("^([0-9]+) bytes from ([0-9\.]+): seq=([0-9]+) ttl=([0-9]+) time=([0-9\.]+) (.*)")
        pings_summary = re.compile("^([0-9]+) packets transmitted, ([0-9]+) packets received, ([0-9]+). packet loss")
        round_trip = re.compile("^round-trip min/avg/max = ([0-9\.]+)/([0-9\.]+)/([0-9\.]+) (.*)")

        ping_result = linux_client.ping_host(target_ip, count=count, size=(size-8)).splitlines()
        if ping_result is not None and len(ping_result) >= count:
            for line in ping_result:

                m = pings.match(line)
                if m is not None:
                    bytes_rx += int(m.group(1))
                    pkts_rx += 1
                    continue

                m = pings_summary.match(line)
                if m is not None:
                    ping_data['summary'] = {'pkts_tx': m.group(1),
                                            'pkts_rx': m.group(2),
                                            'loss': m.group(3)}
                    continue

                m = round_trip.match(line)
                if m is not None:
                    ping_data['round-trip'] = {'min': m.group(1),
                                               'ave': m.group(2),
                                               'max': m.group(3)}
                    continue

            ping_data['data-received'] = {'packets': pkts_rx, 'bytes': bytes_rx}
        return ping_data

    def _check_vm_to_vm_connectivity(self):
        """
        Selects one of the VMs created and uses it as a ping source to ping all other VMs.  Pings use a basic IMIX
        packet size set to obtain a sampling of ping packet sizes
        :return:
        """
        self.assertTrue(len(self.servers) >= 2, "Not enough servers to check VM to VM connectivity")
        ssh_login = CONF.compute.image_ssh_user

        if self.linux_client is None:
            # Use the first IP in the tuples list as the VM to ping all other VMs
            fip_tuple = self.floating_ip_tuples[0]
            linux_client_ip, server = fip_tuple
            private_key = self.servers[server].private_key
            try:
                self.linux_client = self.get_remote_client(server_or_ip=linux_client_ip.floating_ip_address,
                                                           username=ssh_login, private_key=private_key)
            except Exception as e:
                LOG.exception('SSH to server {0} failed'.format(linux_client_ip.floating_ip_address))
                self._log_console_output()
                # network debug is called as part of ssh init
                if not isinstance(e, test.exceptions.SSHTimeout):
                    debug.log_net_debug()
                raise

        total_expected_pkts = 0
        total_expected_bytes = 0
        total_actual_pkts = 0
        total_actual_bytes = 0
        test_pkt_count = 10

        # Cycle through the VMs pinging each one from the testing VM
        # First use floating IPs
        if self.floating_ip_tuples is not None:
            for i in range(1, len(self.floating_ip_tuples)):
                fip_tuple = self.floating_ip_tuples[i]
                target_ip, server = fip_tuple

                for pkt_size in self.imix_pkts:
                    LOG.debug("Testing connectivity from {0} to {1}".format(linux_client_ip.floating_ip_address,
                                                                            target_ip.floating_ip_address))
                    LOG.debug("Testing ICMP with packet size {0}".format(pkt_size))
                    ping_result = self._ping_east_by_southwest(self.linux_client, target_ip.floating_ip_address,
                                                               count=test_pkt_count, size=pkt_size)
                    self.assertIsNotNone(ping_result,
                                         "Ping from {0} to {1} failed".format(linux_client_ip.floating_ip_address,
                                                                              target_ip.floating_ip_address))
                    ## Calculate expected pkts/bytes
                    total_expected_pkts += test_pkt_count
                    total_expected_bytes += test_pkt_count * pkt_size
                    total_actual_pkts += int(ping_result['data-received']['packets'])
                    total_actual_bytes += int(ping_result['data-received']['bytes'])

        ## Use internal IPs to ping
        for network in self._list_networks():

            internal_ips = (p['fixed_ips'][0]['ip_address'] for p in
                            self._list_ports(tenant_id=server.tenant_id, network_id=network['id'])
                            if p['device_owner'].startswith('network'))

            for remote_ip in internal_ips:
                LOG.debug("Pinging IP {0}".format(remote_ip))
                for pkt_size in self.imix_pkts:
                    ping_result = self._ping_east_by_southwest(self.linux_client, remote_ip,
                                                               count=test_pkt_count, size=pkt_size)
                    self.assertIsNotNone(ping_result,
                                         "Ping from {0} to {1} failed".format(linux_client_ip.floating_ip_address,
                                                                              target_ip.floating_ip_address))
                    ## Calculate expected pkts/bytes
                    total_expected_pkts += test_pkt_count
                    total_expected_bytes += test_pkt_count * pkt_size
                    total_actual_pkts += int(ping_result['data-received']['packets'])
                    total_actual_bytes += int(ping_result['data-received']['bytes'])

        LOG.debug("Received {0} Packets containing {1} bytes".format(total_actual_pkts, total_actual_bytes))
        LOG.debug("Expected {0} Packets containing {1} bytes".format(total_expected_pkts, total_expected_bytes))
        self.assertEqual(total_expected_pkts, total_actual_pkts, "Total packets received failed")
        self.assertEqual(total_expected_bytes, total_actual_bytes, "Total bytes received failed")

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

        LOG.debug("Pinging floating IP ")
        ping_result = False
        for i in range(0, 3):
            try:
                ping_result = self._ping_ip_address(floating_ip.floating_ip_address)
                LOG.debug("Ping result : {0}".format(ping_result))
                time.sleep(1)
                if ping_result is True:
                    break
            except exceptions.TimeoutException as e:
                LOG.debug("Timeout during ping: {0}".format(e))
                pass

        self.assertTrue(ping_result,
                        "Ping of floating IP {0} failed".format(floating_ip.floating_ip_address))

        self._check_network_internal_connectivity(self.network)
        self._check_network_external_connectivity()
        self._check_public_network_connectivity(should_connect=True)
        self._check_vm_to_vm_connectivity()

        ## If the test bed has a Nexus leaf switch delete the VMs here
        ## so that we can capture the vlan events caused by the ML2 driver.
        if self.setup_has_leaf_sw:
            for server in self.servers.keys():
                LOG.info("Deleting Server {0}".format(server))
                ## Delete VM
                self.cleanup_resource(server, TestCSROneNet)

            self.total_vlan_events = 0
            for leaf_connection in self.leaf_sw_conns:
                self.total_vlan_events += \
                    self.nx_onep.get_num_interface_events(leaf_connection['port'],
                                                          self.network['provider:segmentation_id'])

            ## We should see the same number of vlan events as before when the
            ## VMs were created.
            self.assertEqual(self.num_vlan_events * 2, self.total_vlan_events, 'Number of VLAN events is incorrect')
            self.assertIsNone(self.nx_onep.trace_backs)

        LOG.debug("test_csr_one_net: End")
