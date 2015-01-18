# Copyright 2012 OpenStack Foundation
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

from tempest.api.compute import base


class BaseSecurityGroupsTest(base.BaseV2ComputeTest):

    @classmethod
    def resource_setup(cls):
        # A network and a subnet will be created for these tests
        cls.set_network_resources(network=True, subnet=True)
        super(BaseSecurityGroupsTest, cls).resource_setup()
