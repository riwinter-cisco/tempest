# Copyright 2014 Cisco Systems, Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
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

from tempest.scenario import manager
from tempest import test
from tempest.common import sniffer
from tempest.common import radvd
from tempest.config import CONF


class TestNetworkIPv6(manager.NetworkScenarioTest):

    """This smoke test suite has the same assumption as TestNetworkBasicOps
    In addition, here we assume that network part of the cloud is configured
    either in IPv6 mode or in dual-stack mode.
    """
    _ip_version = 6

    network_resources = {'network': False, 'router': False, 'subnet': False,
                         'dhcp': False}

    @test.services('network')
    def test_large_prefix(self):
        import netaddr

        net = self ._create_network(tenant_id=self.tenant_id,
                                    namestart='net-125-126')
        for bits in [125, 126]:
            sub = self._create_subnet(network=net,
                                      namestart='subnet-{0}'.format(bits),
                                      net_max_bits=bits)
            start = netaddr.IPAddress(sub.allocation_pools[0]['start'])
            end = netaddr.IPAddress(sub.allocation_pools[0]['end'])
            n_addresses = end.value - start.value + 1
            self.assertEqual(expected=pow(2, 128 - bits)-3,
                             observed=n_addresses)


class TestRadvdIPv6(manager.NetworkScenarioTest):
    _ip_version = 6

    network_resources = {'network': True, 'router': True, 'subnet': True,
                         'dhcp': True, 'ip_version': 6}

    @test.services('compute', 'network')
    def test_internal_radvd(self):
        ex_net = CONF.network.public_network_id

        key_pair = self.create_keypair()
        sec_group = self._create_security_group_nova()
        kwargs = {'key_name': key_pair.id,
                  'security_groups': [sec_group.name]}
        server = self.create_server(create_kwargs=kwargs)
        r = sniffer.sniff(what=sniffer.SNIFF_RADVD, count=3)
        self.assertEqual(expected='icmp6', observed=r['what'])
        self.assertEqual(expected=3,
                         observed=r['count'],
                         message='Wrong number of radvd packets')
        self.assertEqual(expected=2,
                         observed=r['advertisement']['count'],
                         message='Wrong number of RA')
        self.assertEqual(expected=1,
                         observed=r['solicitation']['count'],
                         message='Wrong number of RS')

        if self.run_ssh:
            fip = self._create_floating_ip(thing=server,
                                           external_network_id=ex_net)
            server.add_floating_ip(fip.floating_ip_address)
            ssh = self.get_remote_client(server_or_ip=fip,
                                         private_key=key_pair.private_key)
            capture = ssh.exec_command(sniffer.sniff(what=sniffer.SNIFF_RADVD,
                                                     count=3,
                                                     is_remote=True))
            r = sniffer.sniff_analyzer_radvd(capture=capture)
            self.assertEqual(expected='icmp6', observed=r['what'])
            self.assertEqual(expected=3,
                             observed=r['count'],
                             message='Wrong number of radvd packets')
            self.assertEqual(expected=2,
                             observed=r['advertisement']['count'],
                             message='Wrong number of RA')
            self.assertEqual(expected=1,
                             observed=r['solicitation']['count'],
                             message='Wrong number of RS')

    @test.services('compute', 'network')
    def test_two_radvd(self):
        t_ex = sniffer.sniff_in_thread(what=sniffer.SNIFF_RADVD,
                                       interface='br-ex',
                                       count=100,
                                       timeout=120)
        t_in = sniffer.sniff_in_thread(what=sniffer.SNIFF_RADVD,
                                       interface='br-int',
                                       count=100,
                                       timeout=120)

        radvd.radvd_start_on(iface='br-ex', prefix='2009::/64')

        key_pair = self.create_keypair()
        sec_group = self._create_security_group_nova()
        kwargs = {'key_name': key_pair.id,
                  'security_groups': [sec_group.name]}
        self.create_server(create_kwargs=kwargs)

        t_ex.join()
        t_in.join()

        r_ex = t_ex.result
        r_in = t_in.result

        self.assertIn('2009::/64', r_ex['advertisement']['prefixes'])
        self.assertIn(CONF.network.public_network_ipv6_cidr,
                      r_in['advertisement']['prefixes'])
