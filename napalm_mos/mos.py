# Copyright 2016 Dravetech AB. All rights reserved.
#
# The contents of this file are licensed under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with the
# License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.

"""
Napalm driver for Metamako MOS.

Utilizes JSONRPC interface in MOS 0.17.0

Piggybacks pyeapi Node class heavily.

Read https://napalm.readthedocs.io for more information.
"""

from __future__ import print_function
from __future__ import unicode_literals

# std libs
import ast
import difflib
import pyeapi
import re
import time
import inspect

from datetime import timedelta, datetime
from distutils.version import LooseVersion
from ipaddress import IPv4Network

from pyeapi.client import Node as EapiNode
from pyeapi.eapilib import ConnectionError

import napalm.base.helpers
from napalm.base import NetworkDriver
from napalm.base.utils import string_parsers
from napalm.base.exceptions import (
    ConnectionException,
    CommandErrorException,
    SessionLockedException,
)

from napalm_mos.constants import LLDP_CAPAB_TRANFORM_TABLE
import napalm.base.constants as c


class MOSDriver(NetworkDriver):
    """Napalm driver for Metamako MOS."""

    SUPPORTED_OC_MODELS = []

    _RE_UPTIME = re.compile(
        r"^((?P<day>\d+)\s+days?,\s+)?"
        r"(?P<hour>\d+):(?P<minute>\d+):(?P<second>\d+)",
        re.VERBOSE,
    )
    _RE_ARP = re.compile(
        r"^(?P<address>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
        r"\s+\S+\s+"
        r"(?P<hwAddress>([0-9A-F]{2}[:-]){5}([0-9A-F]{2}))"
        r"\s+\S+\s+"
        r"(?P<interface>\S+)$",
        re.VERBOSE | re.IGNORECASE,
    )
    _RE_NTP_SERVERS = re.compile(r"^ntp server (?P<server>\S+)", re.MULTILINE)
    _RE_SNMP_COMM = re.compile(
        r"\s*Community\sname:\s+(?P<community>\S+)\n"
        r"Community\saccess:\s+(?P<mode>\S+)"
        r"(\nCommunity\ssource:\s+(?P<v4_acl>\S+))?",
        re.VERBOSE,
    )

    _RE_IP = re.compile(r"ip address (?P<ip>[^\s]+) (?P<mask>.+)")

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """Constructor."""
        self.device = None
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.config_session = None
        self._current_config = None
        self._replace_config = False
        self._ssh = None
        self._version = LooseVersion("0")

        self.platform = "mos"

        self._process_optional_args(optional_args or {})

    def _process_optional_args(self, optional_args):
        self.enablepwd = optional_args.pop("enable_password", "")
        self.config_timeout = optional_args.pop("config_timeout", 300)

        transport = optional_args.get(
            "transport", optional_args.get("eos_transport", "https")
        )
        try:
            self.transport_class = pyeapi.client.TRANSPORTS[transport]
        except KeyError:
            raise ConnectionException("Unknown transport: {}".format(self.transport))
        init_args = inspect.getfullargspec(self.transport_class.__init__)[0]
        init_args.pop(0)  # Remove "self"
        init_args.append("enforce_verification")  # Not an arg for unknown reason

        filter_args = ["host", "username", "password", "timeout"]

        self.eapi_kwargs = {
            k: v
            for k, v in optional_args.items()
            if k in init_args and k not in filter_args
        }

    def _run_translated_commands(self, commands, **kwargs):
        """
        In 0.22.0+ some commands had their syntax change.  This function translates those command
        syntaxs to their post 0.22.0 version
        """
        if self._version >= LooseVersion("0.22.0"):
            # Map of translate command syntax to 0.23.0+ syntax
            translations = {
                "show snmp chassis-id": "show snmp v2-mib chassis-id",
                "show snmp location": "show snmp v2-mib location",
                "show snmp contact": "show snmp v2-mib contact",
                "show environment all": "show system environment all",
            }
            commands = [
                i if i not in translations.keys() else translations[i] for i in commands
            ]
        return self.device.run_commands(commands, **kwargs)

    def open(self):
        """Implementation of NAPALM method open."""
        try:
            connection = self.transport_class(
                host=self.hostname,
                username=self.username,
                password=self.password,
                timeout=self.timeout,
                **self.eapi_kwargs,
            )
            if self.device is None:
                self.device = EapiNode(connection, enablepwd=self.enablepwd)

            sw_version = self.device.run_commands(["show version"])[0].get(
                "softwareImageVersion", "0.0.0"
            )
            if LooseVersion(sw_version) < LooseVersion("0.17.9"):
                raise NotImplementedError(
                    "MOS Software Version 0.17.9 or better required"
                )
            self._version = LooseVersion(sw_version)
        except ConnectionError as ce:
            raise ConnectionException(ce.message)

    def close(self):
        """Implementation of NAPALM method close."""
        if self.config_session is not None:
            # Only doing this because discard_config is broke
            self.discard_config()

    def is_alive(self):
        return {"is_alive": True}

    def get_facts(self):
        """Implementation of NAPALM method get_facts."""
        commands_json = ["show version", "show interfaces status"]
        commands_text = ["show hostname"]
        result_json = self.device.run_commands(commands_json, encoding="json")
        result_text = self.device.run_commands(commands_text, encoding="text")

        version = result_json[0]
        hostname = result_text[0]["output"].splitlines()[0].split(" ")[-1]
        fqdn = result_text[0]["output"].splitlines()[1].split(" ")[-1]
        interfaces = result_json[1]["interfaces"].keys()
        interfaces = string_parsers.sorted_nicely(interfaces)

        u_match = re.match(self._RE_UPTIME, version["uptime"]).groupdict()
        if u_match["day"] is None:
            u_match["day"] = 0
        uptime = timedelta(
            days=int(u_match["day"]),
            hours=int(u_match["hour"]),
            minutes=int(u_match["minute"]),
            seconds=int(u_match["second"]),
        ).total_seconds()

        return {
            "hostname": hostname,
            "fqdn": fqdn,
            "vendor": "Metamako",
            "model": re.sub(r"^[Mm]etamako ", "", version["device"]),
            "serial_number": version["serialNumber"],
            "os_version": version["softwareImageVersion"],
            "uptime": float(uptime),
            "interface_list": interfaces,
        }

    def _lock(self):
        if self.config_session is None:
            self.config_session = "napalm_{}".format(datetime.now().microsecond)
            commands = ["copy running-config flash:{}".format(self.config_session)]
            self.device.run_commands(commands)
        if any(k for k in self._get_sessions() if k != self.config_session):
            self.device.run_commands(["delete flash:{}".format(self.config_session)])
            self.config_session = None
            raise SessionLockedException(
                "Session already in use - session file present on flash!"
            )

    def _unlock(self):
        if self.config_session is not None:
            self.device.run_commands(["delete flash:{}".format(self.config_session)])
            self.config_session = None
            self._replace_config = False

    def _get_sessions(self):
        return [
            line.split()[-1]
            for line in self.device.run_commands(["dir flash:"], encoding="text")[0][
                "output"
            ].splitlines()
            if "napalm_" in line.split()[-1]
        ]

    def _load_config(self, filename=None, config=None, replace=False):
        if filename and config:
            raise ValueError("Cannot simultaneously set filename and config")
        self._lock()

        self._candidate = ["copy running-config flash:rollback-0"]
        if replace:
            self._candidate.append("copy default-config running-config")
            self._replace_config = True
        self._candidate.append("configure terminal")

        if filename is not None:
            with open(filename, "r") as f:
                self._candidate = f.readlines()
        else:
            if isinstance(config, list):
                lines = config
            else:
                lines = config.splitlines()

        for line in lines:
            if line.strip() == "":
                continue
            if line.startswith("!"):
                continue
            self._candidate.append(line)

        self._candidate.append("end")
        if any(
            "source mac" in line for line in self._candidate
        ) and self._version < LooseVersion("0.19.2"):
            # Waiting for fixed release
            raise CommandErrorException(
                "Cannot set source mac in MOS versions prior to 0.19.2"
            )
        if any("banner motd" in line for line in self._candidate):
            raise CommandErrorException("Cannot set banner via JSONRPC API")

    def _wait_for_reload(self, timeout=None):
        timeout = timeout or self.config_timeout
        end_timeout = time.time() + timeout
        while True:
            time.sleep(10)
            try:
                self.device.run_commands(["show version"])
                break
            except pyeapi.eapilib.ConnectionError:
                if time.time() > end_timeout:
                    raise

    def load_merge_candidate(self, filename=None, config=None):
        self._load_config(filename=filename, config=config, replace=False)

    def load_replace_candidate(self, filename=None, config=None):
        self._load_config(filename=filename, config=config, replace=True)

    def compare_config(self):
        # There's no good way to do this yet
        if self._replace_config:
            cur = self.get_config("running")["running"].splitlines()[4:]
            return "\n".join(difflib.unified_diff(cur, self._candidate[3:]))
        else:
            return "\n".join(self._candidate[2:])

    def discard_config(self):
        if self.config_session is not None:
            self._candidate = None
            self._unlock()

    def commit_config(self, message="", revert_in=None):
        if revert_in is not None:
            raise NotImplementedError(
                "Commit confirm has not been implemented on this platform."
            )

        if message:
            raise NotImplementedError(
                "Commit message not implemented for this platform"
            )
        if self.config_session is not None and self._candidate:
            if self._replace_config:
                try:
                    self.device.run_commands(
                        self._candidate + ["copy running-config startup-config"]
                    )
                except pyeapi.eapilib.ConnectionError:
                    self._wait_for_reload()
            else:
                self.device.run_commands(
                    self._candidate + ["copy running-config startup-config"]
                )

        self._unlock()

    def rollback(self):
        commands = [
            "copy flash:rollback-0 running-config",
            "copy running-config startup-config",
        ]
        for command in commands:
            self.device.run_commands(command)

    def get_interfaces(self):
        def _parse_mm_speed(speed):
            """Parse the Metamako speed string from 'sh int status' into an Mbit/s int"""

            factormap = {"": 1e-6, "k": 1e-3, "M": 1.0, "G": 1e3, "T": 1e6}
            match = re.match(r"^(?P<speed>\d+)(?P<unit>\D)?$", speed)
            if match:
                match_dict = match.groupdict("")
                return float(match_dict["speed"]) * factormap[match_dict["unit"]]

            return 0.0

        commands = ["show interfaces status", "show interfaces description"]
        output = self.device.run_commands(commands, encoding="json")

        descriptions = {d["Port"]: d["Description"] for d in output[1]}

        interfaces = {}

        for interface, values in output[0]["interfaces"].items():
            interfaces[interface] = {}

            # A L1 device doesn't really have a line protocol.
            # Let's say an rx signal means line protocol is up for now.
            if values["rx"].startswith("up"):
                interfaces[interface]["is_up"] = True
                interfaces[interface]["is_enabled"] = True
            else:
                interfaces[interface]["is_up"] = False
                if "shutdown" in values["rx"]:
                    interfaces[interface]["is_enabled"] = False
                else:
                    interfaces[interface]["is_enabled"] = True

            interfaces[interface]["description"] = descriptions.get(interface, "")

            interfaces[interface]["last_flapped"] = 0.0

            interfaces[interface]["speed"] = _parse_mm_speed(values["speed"])
            interfaces[interface]["mac_address"] = ""
            # L1 device has no concept of MTU
            interfaces[interface]["mtu"] = -1

        return interfaces

    def get_interfaces_ip(self):
        run = self.device.run_commands(["show running-config"], encoding="json")[0]
        iface_keys = [
            k
            for k in run.keys()
            if k.startswith("interface") and not k.startswith("interfaceAp")
        ]
        interfaces = {}
        for k in iface_keys:
            for config_line in run[k]:
                m = self._RE_IP.match(config_line)
                if not m:
                    continue
                ip = m.group("ip")
                mask = m.group("mask")
                _net = IPv4Network(f"{ip}/{mask}", strict=False)
                prefix_length = _net.prefixlen
                # Ma1 is reported as interfaceMa1
                # Et1 as interfaceEt1, etc
                iface = k.replace("interface", "").lower()
                interfaces[iface] = {"ipv4": {ip: {"prefix_length": prefix_length}}}

        return interfaces

    def get_lldp_neighbors(self):
        commands = []
        commands.append("show lldp neighbor")
        output = self.device.run_commands(commands, encoding="json")[0]

        lldp = {}

        for n in output:
            # MOS Has a line for every port, regardless of neighbor
            if n["Neighbor_Device"] != "" and n["Neighbor_Port"] != "":
                if n["Port"] not in lldp.keys():
                    lldp[n["Port"]] = []

                lldp[n["Port"]].append(
                    {"hostname": n["Neighbor_Device"], "port": n["Neighbor_Port"]}
                )

        return lldp

    def get_interfaces_counters(self):
        commands = ["show interfaces counters", "show interfaces counters errors"]
        output = self.device.run_commands(commands, encoding="json")
        interface_counters = {}
        errors_dict = output[1]["interfaces"]
        for interface, counters in output[0]["interfaces"].items():
            interface_counters[interface] = {}
            interface_counters[interface].update(
                tx_errors=int(
                    errors_dict.get(interface, {}).get("tx", -1).replace(",", "")
                ),
                rx_errors=int(
                    errors_dict.get(interface, {}).get("tx", -1).replace(",", "")
                ),
                tx_discards=-1,  # Metamako discards?
                rx_discards=-1,
                tx_octets=int(counters.get("txoctets", -1).replace(",", "")),
                rx_octets=int(counters.get("rxoctets", -1).replace(",", "")),
                tx_unicast_packets=int(
                    counters.get("txucastpkts", -1).replace(",", "")
                ),
                rx_unicast_packets=int(
                    counters.get("rxucastpkts", -1).replace(",", "")
                ),
                tx_multicast_packets=int(
                    counters.get("txmcastpkts", -1).replace(",", "")
                ),
                rx_multicast_packets=int(
                    counters.get("rxmcastpkts", -1).replace(",", "")
                ),
                tx_broadcast_packets=int(
                    counters.get("txbcastpkts", -1).replace(",", "")
                ),
                rx_broadcast_packets=int(
                    counters.get("rxbcastpkts", -1).replace(",", "")
                ),
            )
        return interface_counters

    def get_environment(self):
        commands = ["show environment all"]
        output = self._run_translated_commands(commands, encoding="json")[0]
        environment_counters = {"fans": {}, "temperature": {}, "power": {}, "cpu": {}}

        # Fans
        for slot, data in output["systemCooling"]["fans"].items():
            environment_counters["fans"][slot] = {
                "status": False if data["status"] == "NOT WORKING" else True
            }

        # Temperature
        temps = {}
        for n, v in output["systemTemperature"]["sensors"].items():
            # Make sure all the temperatures are numbers, allow floats as well
            temp = v["temp(C)"] if v["temp(C)"].replace(".", "").isdigit() else -1
            alert_thres = (
                v["alertThreshold"]
                if v["alertThreshold"].replace(".", "").isdigit()
                else -1
            )
            crit_thres = (
                v["criticalThreshold"]
                if v["criticalThreshold"].replace(".", "").isdigit()
                else -1
            )
            temps[v["description"]] = {
                "temperature": float(temp),
                "is_alert": float(temp) > float(alert_thres),
                "is_critical": float(temp) > float(crit_thres),
            }
        environment_counters["temperature"].update(temps)

        # Power
        psu_dict = output["systemPower"]["powerSupplies"]
        for psu, data in output["systemPower"]["powerOutput"].items():
            environment_counters["power"][psu] = {
                "status": float(re.match(r"^([\d.]+)", data["inputVoltage"]).group())
                != 0.0,
                "capacity": float(
                    re.match(r"^([\d.]+)", psu_dict[psu]["capacity"]).group()
                ),
                "output": float(re.match(r"^([\d.]+)", data["outputPower"]).group()),
            }
        # CPU - No CLI command available. Need to be implemented in a different way
        environment_counters["cpu"][0] = {"%usage": float(-1)}

        # Memory - No CLI command available. Need to be implemented in a different way
        environment_counters["memory"] = {"available_ram": -1, "used_ram": -1}
        return environment_counters

    def _transform_lldp_capab(self, capabilities):
        return sorted(
            [
                LLDP_CAPAB_TRANFORM_TABLE[c.lower()]
                for c in capabilities.split(", ")
                if c
            ]
        )

    def get_lldp_neighbors_detail(self, interface=""):

        lldp_neighbors_out = {}

        commands = ["show lldp neighbor {} verbose".format(interface)]
        neighbors_str = self.device.run_commands(commands, encoding="text")[0]["output"]

        interfaces_split = re.split(r"^\*\s(\S+)$", neighbors_str, flags=re.MULTILINE)[
            1:
        ]
        interface_list = zip(*(iter(interfaces_split),) * 2)

        for interface, interface_str in interface_list:

            lldp_neighbors_out[interface] = []
            for neighbor_str in interface_str.strip().split("\n\n"):

                info_dict = {}

                for info_line in neighbor_str.strip().splitlines():
                    try:
                        key, value = info_line.split(":", 1)
                    except ValueError:
                        # Extremely long lines wrap
                        info_dict[key.strip()] = "{} {}".format(
                            info_dict[key.strip()], info_line
                        )
                    info_dict[key.strip()] = value.strip()

                # System capabilities
                try:
                    capabilities = ast.literal_eval(
                        info_dict.get("system capability", "{}")
                    )
                except Exception:
                    capabilities = {}
                system_capab = capabilities.get("capabilities", "").replace(",", ", ")
                enabled_capab = capabilities.get("enabled", "").replace(",", ", ")

                tlv_dict = {
                    "parent_interface": interface,
                    "remote_port": re.sub(
                        r"\s*\([^)]*\)\s*", "", info_dict.get("port id", "")
                    ),
                    "remote_port_description": info_dict.get("port description", ""),
                    "remote_chassis_id": re.sub(
                        r"\s*\([^)]*\)\s*", "", info_dict.get("chassis id", "")
                    ),
                    "remote_system_name": info_dict.get("system name", ""),
                    "remote_system_description": info_dict.get(
                        "system description", ""
                    ),
                    "remote_system_capab": self._transform_lldp_capab(system_capab),
                    "remote_system_enable_capab": self._transform_lldp_capab(
                        enabled_capab
                    ),
                }

                lldp_neighbors_out[interface].append(tlv_dict)

        return lldp_neighbors_out

    def cli(self, commands, encoding="text"):
        if encoding not in ("text", "json"):
            raise NotImplementedError("%s is not a supported encoding" % encoding)

        cli_output = {}

        if not isinstance(commands, list):
            raise TypeError("Please enter a valid list of commands!")

        for command in commands:
            try:
                cli_output[command] = self.device.run_commands(
                    [command], encoding=encoding
                )[0].get("output")
                # not quite fair to not exploit rum_commands
                # but at least can have better control to point to wrong command in case of failure
            except pyeapi.eapilib.CommandError:
                # for sure this command failed
                cli_output[command] = 'Invalid command: "{cmd}"'.format(cmd=command)
                raise CommandErrorException(str(cli_output))
            except Exception as e:
                # something bad happened
                msg = 'Unable to execute command "{cmd}": {err}'.format(
                    cmd=command, err=e
                )
                cli_output[command] = msg
                raise CommandErrorException(str(cli_output))

        return cli_output

    def get_arp_table(self, vrf=""):

        if vrf:
            raise NotImplementedError("Metamako MOS does not support multiple VRFs")

        arp_table = []

        commands = ["show arp numeric"]

        try:
            output = self.device.run_commands(commands, encoding="text")[0]["output"]
        except pyeapi.eapilib.CommandError:
            return []

        for line in output.split("\n"):
            match = self._RE_ARP.match(line)
            if match:
                neighbor = match.groupdict()
                interface = neighbor.get("interface")
                mac_raw = neighbor.get("hwAddress")
                ip = neighbor.get("address")
                age = 0.0
                arp_table.append(
                    {
                        "interface": interface,
                        "mac": napalm.base.helpers.mac(mac_raw),
                        "ip": napalm.base.helpers.ip(ip),
                        "age": age,
                    }
                )

        return arp_table

    def get_ntp_servers(self):
        config = self.get_config(retrieve="running")["running"]

        servers = self._RE_NTP_SERVERS.findall(config)

        return {server: {} for server in servers}

    def get_ntp_stats(self):
        ntp_stats = []

        REGEX = (
            r"^\s?(\+|\*|x|-)?([a-zA-Z0-9\.+-:]+)"
            r"\s+([a-zA-Z0-9\.]+)\s+([0-9]{1,2})"
            r"\s+(-|u)\s+([0-9h-]+)\s+([0-9]+)"
            r"\s+([0-9]+)\s+([0-9\.]+)\s+([\+0-9\.-]+)"
            r"\s+([0-9\.]+)\s?$"
        )

        commands = []
        commands.append("show ntp associations")

        # output = self.device.run_commands(commands)
        # pyeapi.eapilib.CommandError: CLI command 2 of 2 'show ntp associations'
        # failed: unconverted command
        # JSON output not yet implemented...

        ntp_assoc = self.device.run_commands(commands, encoding="text")[0].get(
            "output", "\n\n"
        )
        ntp_assoc_lines = ntp_assoc.splitlines()[2:]

        for ntp_assoc in ntp_assoc_lines:
            line_search = re.search(REGEX, ntp_assoc, re.I)
            if not line_search:
                continue  # pattern not found
            line_groups = line_search.groups()
            try:
                ntp_stats.append(
                    {
                        "remote": line_groups[1],
                        "synchronized": (line_groups[0] == "*"),
                        "referenceid": line_groups[2],
                        "stratum": int(line_groups[3]),
                        "type": line_groups[4],
                        "when": line_groups[5],
                        "hostpoll": int(line_groups[6]),
                        "reachability": int(line_groups[7]),
                        "delay": float(line_groups[8]),
                        "offset": float(line_groups[9]),
                        "jitter": float(line_groups[10]),
                    }
                )
            except Exception:
                continue  # jump to next line

        return ntp_stats

    def get_snmp_information(self):
        """get_snmp_information() for MOS."""

        # Default values
        snmp_dict = {"chassis_id": "", "location": "", "contact": "", "community": {}}

        commands = [
            "show snmp chassis-id",
            "show snmp location",
            "show snmp contact",
            "show snmp community",
        ]
        snmp_config = self._run_translated_commands(commands, encoding="text")
        snmp_dict["chassis_id"] = (
            snmp_config[0]["output"].replace("Chassis: ", "").strip()
        )
        snmp_dict["location"] = (
            snmp_config[1]["output"].replace("Location: ", "").strip()
        )
        snmp_dict["contact"] = snmp_config[2]["output"].replace("Contact: ", "").strip()

        community_outputs = snmp_config[3]["output"].split("\n\n")
        for community_output in community_outputs:

            match = self._RE_SNMP_COMM.search(community_output)
            if match:
                matches = match.groupdict("")
                snmp_dict["community"][match.group("community")] = {
                    "acl": matches["v4_acl"],
                    "mode": matches["mode"],
                }

        return snmp_dict

    def get_optics(self):
        # THIS NEEDS WORK

        command = ["show interfaces transceiver"]

        output = self.device.run_commands(command, encoding="json")[0]["interfaces"]

        # Formatting data into return data structure
        optics_detail = {}

        for port, port_values in output.items():
            port_detail = {}

            port_detail["physical_channels"] = {}
            port_detail["physical_channels"]["channel"] = []

            # Defaulting avg, min, max values to 0.0 since device does not
            # return these values
            try:
                rxpwr = float(port_values["rxPwr"])
            except ValueError:
                rxpwr = 0.0

            try:
                txpwr = float(port_values["txPwr"])
            except ValueError:
                txpwr = 0.0

            try:
                txbias = float(port_values["txBias"])
            except ValueError:
                txbias = 0.0

            optic_states = {
                "index": 0,
                "state": {
                    "input_power": {
                        "instant": rxpwr,
                        "avg": 0.0,
                        "min": 0.0,
                        "max": 0.0,
                    },
                    "output_power": {
                        "instant": txpwr,
                        "avg": 0.0,
                        "min": 0.0,
                        "max": 0.0,
                    },
                    "laser_bias_current": {
                        "instant": txbias,
                        "avg": 0.0,
                        "min": 0.0,
                        "max": 0.0,
                    },
                },
            }

            port_detail["physical_channels"]["channel"].append(optic_states)
            optics_detail[port] = port_detail
        return optics_detail

    def get_config(self, retrieve="all", full=False, sanitized=False):
        """get_config implementation for MOS."""

        get_startup = False
        get_running = False

        commands = ["#", "#"]
        if retrieve == "all" or retrieve == "startup":
            get_startup = True
            commands[0] = "show startup-config"
        if retrieve == "all" or retrieve == "running":
            get_running = True
            commands[1] = "show running-config"

        if not get_startup and not get_running:
            Exception("Wrong retrieve filter: {}".format(retrieve))

        output = self.device.run_commands(commands, encoding="text")

        if sanitized:
            output = [
                {
                    "output": napalm.base.helpers.sanitize_config(
                        config["output"], c.CISCO_SANITIZE_FILTERS
                    )
                }
                for config in output
            ]

        return {
            "startup": output[0]["output"] if get_startup else "",
            "running": output[1]["output"] if get_running else "",
            "candidate": "",
        }
