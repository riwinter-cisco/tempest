#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import httplib2
import logging
import os

# NetworkElement must be the first import or OnePk will fail for
# ImportError: No module named Shared.ttypes
from onep.element import NetworkElement
from onep.core.util import tlspinning
from onep.interfaces import InterfaceVlanListener
from onep.element import SyslogListener
from onep.interfaces import InterfaceFilter
from onep.interfaces import InterfaceStatus
from onep.interfaces import NetworkInterface
from onep.interfaces import InterfaceVlanFilter
from onep.element import SessionConfig
from onep.element import SyslogFilter
from onep.element import SyslogListener
from onep.discovery import ServiceSetDescription
from tempest import config

CONF = config.CONF
LOG = logging.getLogger(__name__)


class NxMgr(object):
    """
    NxMgr - base class for various NxMgr classes.

    Since the Nexus switch can be managed by various means this pseudo abstract
    class is designed to ensure all NxMgr type classes implement the required
    methods.  The goal is to isolate the tests from the actual method of
    Nexus switch control.

    Methods of controlling/monitoring the Nexus switch are:
        - Cisco OneP
        - JSON
        - XML
        - CLI
    """
    def __init__(self, switch_ip, username='admin', password='password',
                 api_version='latest', sw_type='3k'):
        self.switch_ip = switch_ip
        self.username = username
        self.sw_type = sw_type
        self.password = password
        self.api_version = api_version
        self.headers = None

    def connect(self):
        """
        Connects to the NX Switch and opens a channel of communication.
        """
        raise NotImplementedError("NxMgr connect not implemented")

    def disconnect(self):
        """
        Disconnects the channel of communication setup in the connect() method
        """
        raise NotImplementedError("NxMgr disconnect not implemented")

    def get_interface_names(self):
        """
        Queries the NX switch for its interfaces.
        :return: A list of interfaces names
        """
        raise NotImplementedError("NxMgr get_interfaces not implemented")

    def monitor_vlan_state(self, interface_name, vlan_id):
        """
        Record the vlan create/delete events
        :param interface_name:
        :param vlan_id:
        :return:
        """
        raise NotImplementedError("NxMgr monitor_vlan_state not implemented")

    def show_vlan_events(self):
        """
        Display the vlan events recorded
        :return: None
        """
        raise NotImplementedError("NxMgr show_vlan_events not implemented")

    def monitor_syslog(self, pattern):
        """
        Setup a Syslog receiver/recorder
        :return:
        """
        raise NotImplementedError("NxMgr monitor_syslog not implemented")

    def show_syslogs(self, pattern):
        """
        :return:
        """
        raise NotImplementedError("NxMgr show_syslogs not implemented")

    def monitor_config(self):
        """
        Setup a Config change receiver/recorder
        :return:
        """
        raise NotImplementedError("NxMgr monitor_config not implemented")

    def get_vlans(self):
        """
        :return:
        """
        raise NotImplementedError("NxMgr get_vlans not implemented")

    def add_interface_state_listener(self, listener, event_filter, event_type,
                                     client_data):
        """
        :param event_filter:
        :param event_type:
        :param client_data:
        :return:
        """
        raise NotImplementedError("NxMgr add_interface_state_listener "
                                  "not implemented")

    @property
    def trace_backs(self):
        raise NotImplementedError("NxMgr add_interface_state_listener "
                                  "not implemented")


class NxOnePMgr(NxMgr):

    xml_log_pattern = "sendCmd2Parser"

    def __init__(self, switch_ip, **kwargs):
        super(NxOnePMgr, self).__init__(switch_ip, **kwargs)
        self.api_format = 'onep'
        self.nx_mgr = None
        self.vlan_event_handle = None
        self.cli_event_handle = None
        self.session_handle = None
        self.syslog_xml_collector = None
        self.syslog_traceback_collector = None
        self.vlan_monitors = {}
        self.syslog_event_handle = None
        self.session_config = None
        self.root_cert_path = None
        self.client_cert_path = None
        self.client_key_path = None
        self.tls_pinning_file = None

    def connect(self):
        if self.nx_mgr is not None:
            return

        self.session_config = \
            SessionConfig(SessionConfig.SessionTransportMode.TLS)
        # Set all the TLS properties in session_config
        self.root_cert_path = None
        self.client_cert_path = None
        self.client_key_path = None
        self.tls_pinning_file = None
        self.session_config.ca_certs = self.root_cert_path
        self.session_config.keyfile = self.client_key_path
        self.session_config.certfile = self.client_cert_path
        self.session_config.set_tls_pinning(self.tls_pinning_file,
                                            PinningHandler(
                                                self.tls_pinning_file))

        ## Create the OneP NetworkElement
        self.nx_mgr = NetworkElement(self.switch_ip,
                                     "NxOnePMgr-{0}".format(os.getpid()))
        self.session_handle = \
            self.nx_mgr.connect(self.username,
                                self.password, self.session_config)

        ## xml collector to verify configuration
        self.syslog_xml_collector = NxSyslogCollector(self.nx_mgr,
                                                      "sendCmd2Parser")

        ## traceback collector to verify No Tracebacks occcured during the test
        self.syslog_traceback_collector = NxSyslogCollector(self.nx_mgr,
                                                            "Traceback")

        ## Record version information
        sd_list = self.nx_mgr.discover_service_set_list()
        if sd_list is None or len(sd_list) == 0:
            LOG.debug("Empty Service Set Description list")
        else:
            for sd in sd_list:
                logging.debug("NetworkElement IPAddress = {0} "
                              .format(sd.network_element.host_address))

                services = sd.service_set_list
                if services is not None:
                    for serviceName in services:
                        logging.debug("Service Name: {0}"
                                      .format(ServiceSetDescription
                                              .ServiceSetName
                                              .enumval(serviceName)))

                        logging.debug("Versions: {0}"
                                      .format(services.get(serviceName)))

    def disconnect(self):
        if self.nx_mgr is not None:
            self.nx_mgr.disconnect()

    def get_interface_names(self):
        if self.nx_mgr is None:
            return None

        interface_types = NetworkInterface.InterfaceTypes
        local_filter = InterfaceFilter(None,
                                       interface_types.ONEP_IF_TYPE_ETHERNET)
        int_list = self.nx_mgr.get_interface_list(local_filter)
        if_names = []

        for interface in int_list:
            int_config = NetworkInterface.get_config(interface)
            if_names.append(int_config.display_name)

        return if_names

    def get_network_interface(self, interface_name):
        target_interface = None
        interface_types = NetworkInterface.InterfaceTypes
        if_filter = InterfaceFilter(None,
                                    interface_types.ONEP_IF_TYPE_ETHERNET)
        int_list = self.nx_mgr.get_interface_list(if_filter)
        for interface in int_list:
            int_config = NetworkInterface.get_config(interface)
            if int_config.display_name == interface_name:
                target_interface = interface
                break

        if target_interface is None:
            raise NetworkInterfaceNotFoundError(interface_name)

        return target_interface

    def monitor_vlan_state(self, interface_name, vlan_id):
        if self.nx_mgr is None:
            return None

        vlan_mon = NxInterfaceVlanEventMonitor(self, interface_name)
        self.vlan_monitors.update({interface_name:  vlan_mon})
        LOG.debug("vlan_monitors {0}".format(self.vlan_monitors))
        return None

    def get_num_interface_events(self, interface_name):
        if self.nx_mgr is None:
            return None

        LOG.debug("vlan_monitors {0}".format(self.vlan_monitors))
        vlan_mon = self.vlan_monitors[interface_name]
        return vlan_mon.num_events

    def show_vlan_events(self):
        if self.nx_mgr is None or self.vlan_event_handle is None:
            return

        my_events = self.vlan_event_handle.vlan_events
        for event in my_events:
            LOG.debug("------------------------")
            LOG.debug("Event: {0}".format(event))

    def monitor_syslog(self, pattern):
        pass

    def show_xml_logs(self):
        LOG.debug("Syslog messages")
        self.syslog_xml_collector.show_msgs()

    def add_interface_state_listener(self, listener, event_filter, event_type,
                                     client_data):
        self.nx_mgr.add_interface_state_listener(listener,
                                                 event_filter,
                                                 event_type,
                                                 client_data)

    @property
    def trace_backs(self):
        return self.syslog_traceback_collector.num_msgs


class NxInterfaceVlanEventMonitor(InterfaceVlanListener):

    def __init__(self, nx_mgr, interface_name):
        super(NxInterfaceVlanEventMonitor, self).__init__()
        self.events = []
        self.nx_mgr = nx_mgr
        self.interface_name = interface_name
        interface_types = NetworkInterface.InterfaceTypes
        target_network_interface = \
            self.nx_mgr.get_network_interface(interface_name)
        self.client_data = "NxMgr-{0}".format(interface_name)

        self.if_filter = \
            InterfaceVlanFilter(interface=target_network_interface,
                                interface_type=
                                interface_types.ONEP_IF_TYPE_VLAN,
                                vlan_event_type=
                                InterfaceStatus.InterfaceVLANEventType
                                .ONEP_IF_VLAN_EVENT_ANY)

        self.nx_mgr.add_interface_state_listener(self, self.if_filter,
                                                 InterfaceStatus.
                                                 InterfaceVLANEventType.
                                                 ONEP_IF_VLAN_EVENT_ANY,
                                                 self.client_data)

    @property
    def num_events(self):
        if len(self.events) > 0:
            return len(self.events)
        return 0

    def handle_event(self, event, client_data):
        self.events.append(event)
        LOG.debug("---------------------------")
        LOG.debug("NxInterfaceVlanEventMonitor - Received")
        LOG.debug("  Interface      :\t{0}".format(event.interface.name))
        intf_cfg = event.interface.get_config()
        LOG.debug("    Description  :\t{0}".format(intf_cfg.description))
        LOG.debug("    Type         :\t{0}".
                  format(event.interface.interface_type))
        LOG.debug("    Encap        :\t{0}".format(intf_cfg.encap))
        LOG.debug("    Layer 2      :\t{0}".format(intf_cfg.islayer2))
        LOG.debug("  Interface State:\t{0}".format(event.interface_state))
        LOG.debug("  Event Type     :\t{0}".format(event.event_type))
        LOG.debug("  Line Proto     :\t{0}".format(event.lineProto))
        LOG.debug("  Link           :\t{0}".format(event.link))
        LOG.debug("  Client Data    :\t{0}".format(client_data))
        LOG.debug("---------------------------")


class NxSyslogCollector(SyslogListener):

    def __init__(self, nx_mgr, pattern, period=1000, occurs=1):
        """
        :param nx_mgr: OneP NetworkElement object
        :param pattern: The pattern in the syslog to look for
        :param period: How often to check the syslog for the pattern
        :param occurs: The number of time the pattern is seen before the
        event is triggered
        """
        super(NxSyslogCollector, self).__init__()
        self.nx_mgr = nx_mgr
        self.pattern = pattern
        self.messages = []
        self.syslog_filter = SyslogFilter(self.pattern)
        self.syslog_filter.periodMsec = period
        self.syslog_filter.priority = \
            NetworkElement.OnepSyslogSeverity.ONEP_SYSLOG_NOTICE
        self.syslog_filter.occurs = occurs
        self.syslog_event_handle = \
            self.nx_mgr.add_syslog_listener(self,
                                            self.syslog_filter,
                                            "Syslog-client-{0}".
                                            format(pattern))

    def handle_event(self, event, client_data):
        """
        :param event: The SyslogEvnet object received
        :param client_data: The client data configured when registering
        the listener
        """
        if event.msg_count is 1:
            self.messages.append(event.message)
        else:
            raise NotImplementedError("Handling multiple messages from "
                                      "SyslogEvent {0}".format(client_data))

    def show_msgs(self):
        """
        Displays events that have been collected.
        """
        LOG.debug("-----------------------------------------")
        LOG.debug("Messages received {0}".format(len(self.messages)))
        for msg in self.messages:
            LOG.debug("{0}".format(msg))
        LOG.debug("-----------------------------------------")

    @property
    def num_msgs(self):
        if len(self.messages) > 0:
            return len(self.messages)
        return 0


class NxSyslogListener(SyslogListener):
    name = str()

    def __init__(self, name):
        super(NxSyslogListener, self).__init__()
        self.name = name

    def handle_event(self, event, client_data):
        LOG.debug("---------------------------")
        LOG.debug("NxSyslogEvent - Received")
        LOG.debug("  Client data    = {0}".format(client_data))
        LOG.debug("  Message        = {0}".format(event.message))
        LOG.debug("  Message Count  = {0}".format(event.msg_count))
        LOG.debug("  Priority       = {0}".format(NetworkElement.
                                                  OnepSyslogSeverity.
                                                  enumval(event.priority)))
        LOG.debug("---------------------------")


class PinningHandler(tlspinning.TLSUnverifiedElementHandler):

    def __init__(self, pinning_file):
        self.pinning_file = pinning_file
        self.host = None
        self.hashtype = None
        self.finger_logger = None
        self.changed = None

    def handle_verify(self, host, hashtype, finger_logger, changed):
        """
        Callback to the app to determine whether to add a host to pinning DB
        Upon receipt of a certificate which fails to match based on server-name
        or IP address, and for which there is no match in the pinning database,
        this callback asks the application whether to accept the
        connection and/or whether to add the server to the pinning database.
        By default, the connection will be terminated and the pinning db will
        remain unchanged.
        """
        self.host = host
        self.hashtype = hashtype
        self.finger_logger = finger_logger
        self.changed = changed
        return tlspinning.DecisionType.ACCEPT_AND_PIN


class NxJsonMgr(NxMgr):

    def __init__(self, switch_ip, **kwargs):
        super(NxJsonMgr, self).__init__(switch_ip, **kwargs)
        self.api_format = 'json'
        self.headers['Content-Type'] = \
            "application/{0}".format(self.api_format)
        self.headers['Accept'] = "application/{0}".format(self.api_format)
        self.http = httplib2.Http(".cache", timeout=5.0)
        self.version = None
        self._auth_token = None


class NxXmlMgr(NxMgr):

    def __init__(self, switch_ip,  **kwargs):
        super(NxXmlMgr, self).__init__(switch_ip, **kwargs)
        self.api_format = 'json'


class NxCliMgr(NxMgr):

    def __init__(self, switch_ip, **kwargs):
        super(NxCliMgr, self).__init__(switch_ip, **kwargs)
        self.api_format = 'cli'


class NetworkInterfaceNotFoundError(Exception):

    def __init(self, interface_name, error_msg):
        super(NetworkInterfaceNotFoundError, self).__init__(interface_name,
                                                            error_msg)
        self.interface_name = interface_name
        self.error_msg = error_msg
