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

from tempest.services.network import resources as net_resources
from tempest.common.utils import data_utils
from tempest import config
from tempest import exceptions
from tempest.openstack.common import log as logging
from tempest.scenario import manager
from tempest import test
from tempest.thirdparty.cisco.lib import nx_mgr

CONF = config.CONF
LOG = logging.getLogger(__name__)

Floating_IP_tuple = collections.namedtuple('Floating_IP_tuple',
                                           ['floating_ip', 'server'])


class ML2BaseTest(manager.NetworkScenarioTest):

    @classmethod
    def credentials(cls):
        return cls.admin_credentials()

    @classmethod
    def resource_setup(cls):
        # Create no network resources for these tests.
        cls.set_network_resources()
        super(ML2BaseTest, cls).resource_setup()

    @classmethod
    def check_preconditions(cls):
        if not (CONF.network.tenant_networks_reachable
                or CONF.network.public_network_id):
            msg = ('Either tenant_networks_reachable must be "true", or '
                   'public_network_id must be defined.')
            cls.enabled = False
            raise cls.skipException(msg)

        # Variables used to determine if Cisco gear is defined
        # in the tempest.conf file
        cls.setup_has_leaf_sw = False

        if CONF.cisco.leaf_sws:
            cls.leaf_sws = CONF.cisco.leaf_sws

            if cls.leaf_sws is not None:
                cls.setup_has_leaf_sw = True
                if not CONF.cisco.leaf_sw_connections:
                    msg = "leaf_sw_connections must be defined when " \
                          "leaf_sws is specified"
                    cls.enabled = False
                    raise cls.skipException(msg)

        super(ML2BaseTest, cls).check_preconditions()

    def _delete_aggregate(self, aggregate):
        self.aggregates_client.delete_aggregate(aggregate['id'])

    def _add_host(self, aggregate_id, host):
        _, aggregate = self.aggregates_client.add_host(aggregate_id, host)
        self.addCleanup(self._remove_host, aggregate['id'], host)
        self.assertIn(host, aggregate['hosts'])

    def _remove_host(self, aggregate_id, host):
        _, aggregate = self.aggregates_client.remove_host(aggregate_id, host)
        self.assertNotIn(host, aggregate['hosts'])

    def _create_server(self, name, network, zone=None):
        create_kwargs = self.srv_kwargs
        create_kwargs['networks'] = [{'uuid': network.id}]
        if zone is not None:
            create_kwargs['availability_zone'] = zone
        server = self.create_server(name=name, create_kwargs=create_kwargs)
        return dict(server=server, keypair=self.keypair)

    def setup_aggregates(self):
        '''
        Make Aggregates/Zones - one Hypervisor per zone
        '''
        self.aggregates_client = self.manager.aggregates_client
        self.hypervisor_client = self.manager.hypervisor_client
        self.hypervisors_list = self.hypervisor_client.get_hypervisor_list()

        # Verify the hypervisors are operational and make a list
        # of them for later use
        self.hypervisors = []
        self.aggregates = []
        i = 0
        for hypervisor in self.hypervisors_list[1]:
            if hypervisor['status'] == 'enabled' \
                    and hypervisor['state'] == 'up':
                self.hypervisors.append(hypervisor)
                # Create an aggregate/zone per hypervisor host
                aggregate_kwargs = {'name': 'Agg{0}'.format(i),
                                    'availability_zone': 'Zone{0}'.format(i)}
                i += 1
                _, aggregate = \
                    self.aggregates_client.create_aggregate(**aggregate_kwargs)
                self.addCleanup(self._delete_aggregate, aggregate)
                self.aggregates.append(aggregate)
                self._add_host(aggregate['id'],
                               hypervisor['hypervisor_hostname'])

    def setUp(self):
        super(ML2BaseTest, self).setUp()
        self.tenant_id = self.manager.identity_client.tenant_id
        self.servers = {}
        self.floating_ip_tuples = []
        self.linux_client = None
        # TODO(riwinter): Put Imix traffic pkt sizes in tempest config
        self.imix_pkts = (64, 572, 1400)
        self.keypair = self.create_keypair()
        self.srv_kwargs = {'key_name': self.keypair['name']}

        self.setup_aggregates()

        # TODO(riwinters) Find out limits on vCPUs and Networks dynamically
        # Base on Quota ??
        self.max_vcpus = 9
        self.num_vms_per_network = 1
        self.num_routers_per_tenant = 1

        # Each network will get 1 VM on the network for each hypervisor
        self.num_networks = int(self.max_vcpus / len(self.hypervisors))

        LOG.debug("Max VCPUs = {0}".format(self.max_vcpus))
        LOG.debug("Number of VMs per Network = {0}".
                  format(self.num_vms_per_network))
        LOG.debug("Number of Networks = {0}".format(self.num_networks))

        self.security_group = \
            self._create_security_group(tenant_id=self.tenant_id)
        self.srv_kwargs['security_groups'] = [self.security_group]
        try:
            self._create_loginable_secgroup_rule(secgroup=self.security_group)
        except Exception as e:
            LOG.debug("Login sec group already exists: {0}".format(e))

        self.setup_networks()
        self.setup_vms()

    def add_network(self, client=None, tenant_id=None, router=None):
        if CONF.baremetal.driver_enabled:
            # NOTE(Shrews): This exception is for environments where tenant
            # credential isolation is available, but network separation is
            # not (the current baremetal case). Likely can be removed when
            # test account mgmt is reworked:
            # https://blueprints.launchpad.net/tempest/+spec/test-accounts
            network = self._get_network_by_name(
                CONF.compute.fixed_network_name)
            router = None
            subnet = None
        else:
            network = self._create_network(client=client, tenant_id=tenant_id)
            if router is None:
                router = self._get_router(client=client, tenant_id=tenant_id)
            subnet = self._create_subnet(network=network, client=client)
            subnet.add_to_router(router.id)
        return network, subnet, router

    def setup_networks(self):
        self.networks = []
        router = None
        for i in range(0, self.num_networks):
            if i % (self.num_networks / self.num_routers_per_tenant) is 0:
                router = None
            self.network, self.subnet, router = \
                self.add_network(tenant_id=self.tenant_id, router=router)
            self.networks.append(self.network)

            if self.setup_has_leaf_sw:
                # Setup vlan event monitor based on ports in
                # found in tempest.config
                # self.network['provider:segmentation_id']
                for leaf_connection in self.leaf_sw_conns:
                    self.nx_onep.monitor_vlan_state(
                        leaf_connection['port'])

    def setup_vms(self):
        # Create each VM on a seperate hypervisor
        for network in self.networks:
            for aggregate in self.aggregates:
                name = data_utils.rand_name('server')
                for i in range(0, 2):
                    server_dict = None
                    try:
                        server_dict = \
                            self._create_server(name, network,
                                                zone=
                                                aggregate['availability_zone'])
                    except exceptions.ServerFault as e:
                        LOG.warn("Server Fault: {0}".format(e))
                        LOG.warn("Continuing test")
                        continue
                    break

                if server_dict is None:
                    LOG.warn("Too many server faults encountered")
                    # If still not set the raise an error here
                    raise

                self.servers[server_dict['server']['id']] = \
                    server_dict['keypair']

    def delete_vms(self):
        for server in self.servers.keys():
            LOG.debug("Deleting server {0}".format(server))
            self.servers_client.delete_server(server)
            self.servers_client.wait_for_server_termination(server)
            del self.servers[server]


    @classmethod
    def setUpClass(cls):
        super(ML2BaseTest, cls).setUpClass()
        for ext in ['router', 'security-group']:
            if not test.is_extension_enabled(ext, 'network'):
                msg = "%s extension not enabled." % ext
                raise cls.skipException(msg)

        cls.check_preconditions()
        cls.aggregates_client = cls.manager.aggregates_client
        cls.hypervisor_client = cls.manager.hypervisor_client

        cls.nx_onep = None
        if cls.setup_has_leaf_sw:
            # This test requires one switch - multi switch is not supported
            sw_attrs_data = (CONF.cisco.leaf_sws[0]).split(':')
            if len(sw_attrs_data) != 4:
                msg = 'Tempest config error: CONF.cisco.leaf_sws ' \
                      'expected 4 values'
                raise cls.skipException(msg)

            cls.leaf_sw_attrs = {'ip': sw_attrs_data[0],
                                 'username': sw_attrs_data[1],
                                 'password': sw_attrs_data[2],
                                 'ssh_port': sw_attrs_data[3]}

            cls.leaf_sw_conns = []
            for conn in CONF.cisco.leaf_sw_connections:
                conn_data = conn.split(':')
                if len(conn_data) != 3:
                    msg = 'Tempest config error: ' \
                          'CONF.cisco.leaf_sw_connections expected 3 values'
                    raise cls.skipException(msg)

                conn_attrs = {'switch_ip': conn_data[0],
                              'node-name': conn_data[1],
                              'port': conn_data[2]}
                cls.leaf_sw_conns.append(conn_attrs)

            # Create the NxMgr object based on OneP API
            cls.nx_onep = nx_mgr.NxOnePMgr(
                switch_ip=cls.leaf_sw_attrs['ip'],
                username=cls.leaf_sw_attrs['username'],
                password=cls.leaf_sw_attrs['password'])

            cls.nx_onep.connect()

    @classmethod
    def tearDownClass(cls):
        super(ML2BaseTest, cls).tearDownClass()
        # Must tear down OneP connection here - heart beat thread will continue
        # to run until disconnect called
        if cls.setup_has_leaf_sw and cls.nx_onep is not None:
            cls.nx_onep.disconnect()

    def verify_num_vlan_create_events(self):
        self.assertIsNotNone(self.leaf_sws)
        self.assertIsNotNone(self.nx_onep)
        self.total_vlan_events = 0
        for leaf_connection in self.leaf_sw_conns:
            self.total_vlan_events += \
                self.nx_onep.get_num_interface_events(
                    leaf_connection['port'])

        expected_events = len(self.networks) * len(self.hypervisors)
        self.assertEqual(self.total_vlan_events, expected_events)

    def verify_num_vlan_delete_events(self):
        self.assertIsNotNone(self.leaf_sws)
        self.assertIsNotNone(self.nx_onep)
        self.nx_onep.clear_interface_events('all')
        num_events = self.nx_onep.get_num_interface_events('all')
        LOG.debug("Number of VLAN events after clear: {0}".format(num_events))
        for server in self.servers.keys():
            LOG.info("Deleting Server {0}".format(server))
            # Delete VM
            self.servers_client.delete_server(server)
            self.servers_client.wait_for_server_termination(server)

        num_events = self.nx_onep.get_num_interface_events('all')
        LOG.debug("Number of VLAN events after delete: {0}".format(num_events))
        expected_events = len(self.networks) * len(self.hypervisors)
        self.assertEqual(self.total_vlan_events, expected_events)

    def _ping_east_by_southwest(self, linux_client, target_ip, count=1,
                                size=56):
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

        pings = re.compile("^([0-9]+) bytes from ([0-9\.]+): seq=([0-9]+) "
                           "ttl=([0-9]+) time=([0-9\.]+) (.*)")
        pings_summary = re.compile("^([0-9]+) packets transmitted, ([0-9]+) "
                                   "packets received, ([0-9]+). packet loss")
        round_trip = re.compile("^round-trip min/avg/max = "
                                "([0-9\.]+)/([0-9\.]+)/([0-9\.]+) (.*)")

        ping_result = linux_client.ping_host(target_ip, count=count,
                                             size=(size - 8)).splitlines()

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

            ping_data['data-received'] = \
                {'packets': pkts_rx, 'bytes': bytes_rx}

        return ping_data

    def verify_vm_to_vm_connectivity(self):
        """
        Selects one of the VMs created and uses it as a ping source to
        ping all other VMs.  Pings use a basic IMIX packet size set to
        obtain a sampling of ping packet sizes
        :return:
        """
        self.assertTrue(len(self.servers) >= 2,
                        "Not enough servers to check VM to VM connectivity")
        ssh_login = CONF.compute.image_ssh_user

        server = {}
        if self.linux_client is None:
            # Use the first IP in the tuples list as the VM to
            # ping all other VMs
            fip_tuple = self.floating_ip_tuples[0]
            linux_client_ip, server = fip_tuple
            private_key = self.servers[server['id']]['private_key']
            try:
                self.linux_client = \
                    self.get_remote_client(
                        server_or_ip=linux_client_ip.floating_ip_address,
                        username=ssh_login, private_key=private_key)
            except Exception as e:
                LOG.exception('SSH to server {0} '
                              'failed'
                              .format(linux_client_ip.floating_ip_address))
                self._log_console_output()
                # network debug is called as part of ssh init
                if not isinstance(e, test.exceptions.SSHTimeout):
                    LOG.debug("Exception during SSH: {0}".format(e))
                raise

        total_expected_pkts = 0
        total_expected_bytes = 0
        total_actual_pkts = 0
        total_actual_bytes = 0
        test_pkt_count = 10

        # Cycle through the VMs pinging each one from the testing VM
        # First use floating IPs
        target_ip = None
        if self.floating_ip_tuples is not None:
            for i in range(1, len(self.floating_ip_tuples)):
                fip_tuple = self.floating_ip_tuples[i]
                target_ip, server = fip_tuple

                for pkt_size in self.imix_pkts:
                    LOG.debug("Testing connectivity from {0} to {1}"
                              .format(linux_client_ip.floating_ip_address,
                                      target_ip.floating_ip_address))

                    LOG.debug("Testing ICMP with packet size {0}"
                              .format(pkt_size))
                    ping_result = self._ping_east_by_southwest(
                        self.linux_client, target_ip.floating_ip_address,
                        count=test_pkt_count, size=pkt_size)

                    self.assertIsNotNone(ping_result,
                                         "Ping from {0} to {1} "
                                         "failed".format(
                                             linux_client_ip
                                             .floating_ip_address,
                                             target_ip.floating_ip_address))
                    # Calculate expected pkts/bytes
                    total_expected_pkts += test_pkt_count
                    total_expected_bytes += test_pkt_count * pkt_size
                    total_actual_pkts += \
                        int(ping_result['data-received']['packets'])
                    total_actual_bytes += \
                        int(ping_result['data-received']['bytes'])

        # Use internal IPs to ping
        for network in self._list_networks():

            internal_ips = (p['fixed_ips'][0]['ip_address'] for p in
                            self._list_ports(tenant_id=server['tenant_id'],
                                             network_id=network['id'])
                            if p['device_owner'].startswith('network'))

            for remote_ip in internal_ips:
                LOG.debug("Pinging IP {0}".format(remote_ip))
                for pkt_size in self.imix_pkts:
                    ping_result = \
                        self._ping_east_by_southwest(self.linux_client,
                                                     remote_ip,
                                                     count=test_pkt_count,
                                                     size=pkt_size)

                    self.assertIsNotNone(ping_result,
                                         "Ping from {0} to {1} failed"
                                         .format(
                                             linux_client_ip
                                             .floating_ip_address,
                                             target_ip.floating_ip_address))

                    # Calculate expected pkts/bytes
                    total_expected_pkts += test_pkt_count
                    total_expected_bytes += test_pkt_count * pkt_size
                    total_actual_pkts += \
                        int(ping_result['data-received']['packets'])

                    total_actual_bytes += \
                        int(ping_result['data-received']['bytes'])

        LOG.debug("Received {0} Packets "
                  "containing {1} bytes".format(total_actual_pkts,
                                                total_actual_bytes))
        LOG.debug("Expected {0} Packets "
                  "containing {1} bytes".format(total_expected_pkts,
                                                total_expected_bytes))
        self.assertEqual(total_expected_pkts,
                         total_actual_pkts,
                         "Total packets received failed")

        self.assertEqual(total_expected_bytes,
                         total_actual_bytes,
                         "Total bytes received failed")

    def verify_tenant_network_connectivity_wrapper(self):
        ssh_login = CONF.compute.image_ssh_user
        for server, key in self.servers.iteritems():
            LOG.debug("Server {0}, key {1}".format(server, key))
            # call the common method in the parent class
            super(ML2BaseTest, self)._check_tenant_network_connectivity(
                server, ssh_login, key['private_key'],
                servers_for_debug=self.servers.keys())

    def create_floating_ips(self):
        for server_id in self.servers.keys():
            server = {'id': server_id, 'tenant_id': self.tenant_id}
            floating_ip = self.create_floating_ip(server)
            self.floating_ip_tuple = Floating_IP_tuple(floating_ip, server)
            self.floating_ip_tuples.append(self.floating_ip_tuple)

    def test_base(self):
        self.verify_num_vlan_create_events()
        self.verify_tenant_network_connectivity_wrapper()
        self.create_floating_ips()
        self.verify_vm_to_vm_connectivity()
        self.verify_num_vlan_delete_events()