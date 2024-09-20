# Copyright (C) 2024 Canonical
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""Device connector to provision Ubuntu OEM on systems
that support autoinstall and provision-image.sh script"""

import logging
import json
from typing import Any, Dict, Tuple

from testflinger_device_connectors.devices import (
    DefaultDevice,
    RecoveryError,
    catch,
)
from testflinger_device_connectors.devices.oem_autoinstall.oem_autoinstall import (  # noqa: E501
    OemAutoinstall,
)
from testflinger_device_connectors.devices.oem_autoinstall.zapper_oem import ZapperConnectorOem
logger = logging.getLogger(__name__)


class DeviceConnector(DefaultDevice):
    """Tool for provisioning baremetal with a given image."""

    @catch(RecoveryError, 46)
    def provision(self, args):
        """Method called when the command is invoked."""
        with open(args.job_data, encoding="utf-8") as job_json:
            self.job_data = json.load(job_json)

        provision_data = self.job_data.get("provision_data", {})
        use_zapper = provision_data.get("use_zapper")

        logger.info("Init oem_autoinstall")
        if use_zapper:
            logger.info("Using Zapper typecmux")
            device_with_zapper = ZapperConnectorOem()
            device_with_zapper.provision(args)
        else:
            logger.info("Using provision-image.sh script")
            device = OemAutoinstall(args.config, args.job_data)
            device.provision()
