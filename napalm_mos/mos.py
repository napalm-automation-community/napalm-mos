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

Utilizes extremely experimental JSONRPC interface in MOS 0.13.4beta

Piggybacks pyeapi Node class heavily.

Read https://napalm.readthedocs.io for more information.
"""

from __future__ import print_function
from __future__ import unicode_literals

# std libs
import re

from datetime import timedelta

from pyeapi.client import Node as EapiNode
from pyeapi.eapilib import HttpsEapiConnection, HttpEapiConnection
from pyeapi.eapilib import ConnectionError

from napalm_base.base import NetworkDriver
from napalm_base.utils import string_parsers, py23_compat
from napalm_base.exceptions import (
    ConnectionException,
    )

TRANSPORTS = {
    'https': HttpsEapiConnection,
    'http':  HttpEapiConnection,
}


class MOSDriver(NetworkDriver):
    """Napalm driver for Metamako MOS."""

    SUPPORTED_OC_MODELS = []

    _RE_UPTIME = re.compile(r"""^((?P<day>\d+)\s+days?,\s+)?
                             (?P<hour>\d+):(?P<minute>\d+):(?P<second>\d+)""", re.VERBOSE)

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """Constructor."""
        self.device = None
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout

        if optional_args is None:
            optional_args = {}

        self.transport = optional_args.get('transport', 'https')

        if self.transport == 'https':
            self.port = optional_args.get('port', 443)
        else:
            self.port = optional_args.get('port', 80)

        self.path = optional_args.get('path', '/command-api')

    def open(self):
        """Implementation of NAPALM method open."""
        if self.transport not in TRANSPORTS:
            raise typeError('invalid transport specified')
        klass = TRANSPORTS[self.transport]
        try:
            connection = klass(
                self.hostname,
                port=self.port,
                path=self.path,
                username=self.username,
                password=self.password,
                timeout=self.timeout,
            )
            if self.device is None:
                self.device = EapiNode(connection)

            self.device.run_commands(['show version'], send_enable=False)
        except ConnectionError as ce:
            raise ConnectionException(ce.message)

    def close(self):
        """Implementation of NAPALM method close."""
        pass

    def is_alive(self):
        return {
            'is_alive': True
        }

    def get_facts(self):
        """Implementation of NAPALM method get_facts."""
        commands = ['show version', 'show hostname', 'show interfaces status']
        result = self.device.run_commands(commands)

        version = result[0]['output']
        hostname = result[1]['output'].splitlines()[0].split(" ")[-1]
        fqdn = result[1]['output'].splitlines()[1].split(" ")[-1]
        interfaces = result[2]['output']['interfaces'].keys()
        interfaces = string_parsers.sorted_nicely(interfaces)

        u_match = re.match(self._RE_UPTIME, version['uptime']).groupdict()
        if u_match['day'] is None:
            u_match['day'] = 0
        uptime = timedelta(days=int(u_match['day']), hours=int(u_match['hour']),
                           seconds=int(u_match['second'])).total_seconds()

        return {
            'hostname': hostname,
            'fqdn': fqdn,
            'vendor': 'Metamako',
            'model': version['device'],
            'serial_number': version['serialNumber'],
            'os_version': version['softwareImageVersion'],
            'uptime': int(uptime),
            'interface_list': interfaces,
        }
