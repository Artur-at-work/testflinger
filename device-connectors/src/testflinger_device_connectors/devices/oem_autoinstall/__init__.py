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
import yaml
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
#from testflinger_device_connectors.devices.zapper_kvm import DeviceConnector
from testflinger_device_connectors.devices.oem_autoinstall.zapper_oem import DeviceConnector
logger = logging.getLogger(__name__)


class DeviceConnector(DeviceConnector):
    """Tool for provisioning baremetal with a given image."""

    #PROVISION_METHOD = "OemAutoinstall"
    #TODO: add validate method
    # if use_zapper: true, then
    # device_with_zapper = ZapperConnector
    # validate link and user_data, then pass to zapper API
        # device_with_zapper.run(zapper_ip, kwargs)
    # else use legacy oem_autoinstall, device
        # device.provision()
    @catch(RecoveryError, 46)
    def provision(self, args):
        """Method called when the command is invoked."""
        with open(args.config, encoding="utf-8") as configfile:
            self.config = yaml.safe_load(configfile)
        with open(args.job_data, encoding="utf-8") as job_json:
            self.job_data = json.load(job_json)

        provision_data = self.job_data.get("provision_data", {})
        use_zapper = provision_data.get("use_zapper")

        logger.info("BEGIN provision")
        if use_zapper:
            logger.info("Provisioning device with zapper typecmux")
            (api_args, api_kwargs) = self._validate_configuration()
            self._run(self.config["control_host"], *api_args, **api_kwargs)
            # TODO: write own _validate_conf if dont need their alloem_url things
        else:
            logger.info("Provisioning device with provision_image.sh")
            device = OemAutoinstall(args.config, args.job_data)
            device.provision()

        logger.info("END provision")

    def _validate_configuration(
        self,
    ) -> Tuple[Tuple, Dict[str, Any]]:
        """
        Validate the job config and data and prepare the arguments
        for the Zapper `provision` API.
        """

        if "alloem_url" in self.job_data["provision_data"]:
            url = self.job_data["provision_data"]["alloem_url"]
            username = "ubuntu"
            password = "u"
            retries = max(
                2, self.job_data["provision_data"].get("robot_retries", 1)
            )
        else:
            url = self.job_data["provision_data"]["url"]
            username = self.job_data.get("test_data", {}).get(
                "test_username", "ubuntu"
            )
            password = self.job_data.get("test_data", {}).get(
                "test_password", "ubuntu"
            )
            retries = self.job_data["provision_data"].get("robot_retries", 1)

        logger.info(self.config["reboot_script"])
        provisioning_data = {
            "url": url,
            "username": username,
            "password": password,
            "robot_retries": retries,
            "autoinstall_conf": self._get_autoinstall_conf(),
            "reboot_script": self.config["reboot_script"],
            "device_ip": self.config["device_ip"],
            "robot_tasks": self.job_data["provision_data"]["robot_tasks"],
        }

        # Let's handle defaults on the Zapper side adding only the explicitly
        # specified keys to the `provision_data` dict.
        optionals = [
            "cmdline_append",
            "skip_download",
            "wait_until_ssh",
            "live_image",
            "ubuntu_sso_email",
        ]
        provisioning_data.update(
            {
                opt: self.job_data["provision_data"][opt]
                for opt in optionals
                if opt in self.job_data["provision_data"]
            }
        )

        return ((), provisioning_data)
