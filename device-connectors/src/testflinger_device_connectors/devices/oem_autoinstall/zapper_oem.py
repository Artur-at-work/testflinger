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

"""Zapper Connector for KVM provisioning."""

import base64
import binascii
import contextlib
import logging
import os
import subprocess
from typing import Any, Dict, Optional, Tuple
from pathlib import Path
import yaml

from testflinger_device_connectors.devices import ProvisioningError
from testflinger_device_connectors.devices.zapper import ZapperConnector

logger = logging.getLogger(__name__)
ATTACHMENTS_DIR = "attachments"
ATTACHMENTS_PROV_DIR = Path.cwd() / ATTACHMENTS_DIR / "provision"

class ZapperConnectorOem(ZapperConnector):
    """Tool for provisioning baremetal with a given image."""

    PROVISION_METHOD = "ProvisioningOEM"

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



    def _get_autoinstall_conf(self) -> Optional[Dict[str, Any]]:
        """
        Generate base64 autoinstall config based on user-data and authorized
        keys sent with attachments
        """
        provision_data = self.job_data.get("provision_data", {})
        user_data_file = self._get_attachment_file(provision_data.get("user_data"))
        authorized_keys_file = self._get_attachment_file(provision_data.get("authorized_keys"))
        # token_file = provision_data.get("token_file")
        # redeploy_cfg = provision_data.get("redeploy_cfg")
        # authorized_keys = provision_data.get("authorized_keys")
        with open(user_data_file, 'r', encoding='utf-8') as f:
            user_data = yaml.safe_load(f)

            if authorized_keys_file is not None and os.path.exists(authorized_keys_file):
                with open(authorized_keys_file, 'r', encoding='utf-8') as keys_file:
                    authorized_keys = keys_file.read().strip().splitlines()
                    authorized_keys = [key for key in authorized_keys if key]  # clean empty lines
                    if 'ssh_authorized_keys' not in user_data['autoinstall']['user-data']:
                        user_data['autoinstall']['user-data']['ssh_authorized_keys'] = []
                    user_data['autoinstall']['user-data']['ssh_authorized_keys'].extend(authorized_keys)
                    # TODO: add id_rsa.pub of this.host?
            user_data_str = yaml.dump(user_data, default_flow_style=False)
            user_data_64 = base64.b64encode(user_data_str.encode('utf-8')).decode('utf-8')

        autoinstall_conf = {}
        autoinstall_conf['base_user_data'] = user_data_64

        # for key, value in self.job_data["provision_data"].items():
        #     if "autoinstall_" not in key:
        #         continue

        #     key = key.replace("autoinstall_", "")
        #     with contextlib.suppress(AttributeError):
        #         getattr(self, f"_validate_{key}")(value)

        #     autoinstall_conf[key] = value

        # if not autoinstall_conf:
        #     logger.info("Autoinstall-related keys were not provided.")
        #     return None

        # with open(os.path.expanduser("~/.ssh/id_rsa.pub")) as pub:
        #     autoinstall_conf["authorized_keys"] = [pub.read()]

        return autoinstall_conf

    def _get_attachment_file(self, filepath):
        filepath = Path(filepath)
        if filepath.is_absolute():
            filepath = filepath.relative_to("/")
        return ATTACHMENTS_PROV_DIR / filepath

    def _validate_base_user_data(self, encoded_user_data: str):
        """
        Assert `base_user_data` argument is a valid base64 encoded YAML.
        """
        try:
            user_data = base64.b64decode(encoded_user_data.encode()).decode()
            yaml.safe_load(user_data)
        except (binascii.Error, ValueError) as exc:
            raise ProvisioningError(
                "Provided `base_user_data` is not base64 encoded."
            ) from exc
        except yaml.YAMLError as exc:
            raise ProvisioningError(
                "Provided `base_user_data` is not a valid YAML."
            ) from exc

    def _post_run_actions(self, args):
        super()._post_run_actions(args)

        if "alloem_url" in self.job_data["provision_data"]:
            self._post_run_actions_oem(args)

    def _post_run_actions_oem(self, args):
        """Post run actions for 22.04 OEM images."""
        try:
            self._change_password("ubuntu", "u")
            self._copy_ssh_id()
        except subprocess.CalledProcessError as exc:
            logger.error("Process failed with: %s", exc.output.decode())
            raise ProvisioningError(
                "Failed configuring SSH on the DUT."
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise ProvisioningError(
                "Timed out configuring SSH on the DUT."
            ) from exc

        self._run_oem_script(args)

    def _run_oem_script(self, args):
        """
        If "alloem_url" was in scope, the Zapper only restored
        the OEM reset partition. The usual oemscript will take care
        of the rest.
        """

        if not self.job_data["provision_data"].get("url"):
            logger.warning(
                "Provisioned with base `alloem` image, no test URL specified."
            )
            return

        oem = self.job_data["provision_data"].get("oem")
        oemscript = {
            "hp": HPOemScript,
            "dell": DellOemScript,
            "lenovo": LenovoOemScript,
        }.get(oem, OemScript)(args.config, args.job_data)

        oemscript.provision()

    def _copy_ssh_id(self):
        """Copy the ssh id to the device"""

        logger.info("Copying the agent's SSH public key to the DUT.")

        try:
            test_username = self.job_data.get("test_data", {}).get(
                "test_username", "ubuntu"
            )
            test_password = self.job_data.get("test_data", {}).get(
                "test_password", "ubuntu"
            )
        except AttributeError:
            test_username = "ubuntu"
            test_password = "ubuntu"

        cmd = [
            "sshpass",
            "-p",
            test_password,
            "ssh-copy-id",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            f"{test_username}@{self.config['device_ip']}",
        ]
        subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=60)

    def _change_password(self, username, orig_password):
        """Change password via SSH to the one specified in the job data."""

        password = self.job_data.get("test_data", {}).get(
            "test_password", "ubuntu"
        )
        logger.info("Changing the original password to %s", password)

        cmd = [
            "sshpass",
            "-p",
            orig_password,
            "ssh",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            f"{username}@{self.config['device_ip']}",
            f"echo 'ubuntu:{password}' | sudo chpasswd",
        ]

        subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=60)
