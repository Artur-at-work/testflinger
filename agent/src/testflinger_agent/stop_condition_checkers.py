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
# along with this program.  If not, see <http://www.gnu.org/licenses/>

import time
from typing import Optional, Tuple

from testflinger_common.enums import JobState, TestEvent

from .client import TestflingerClient


class JobCancelledChecker:
    def __init__(self, client: TestflingerClient, job_id: str):
        self.client = client
        self.job_id = job_id

    def __call__(self) -> Tuple[Optional[TestEvent], str]:
        if self.client.check_job_state(self.job_id) == JobState.CANCELLED:
            return (
                TestEvent.CANCELLED,
                "Job cancellation was requested, exiting.",
            )
        return None, ""


class GlobalTimeoutChecker:
    def __init__(self, timeout: int):
        self.timeout = timeout
        self.start_time = time.time()

    def __call__(self) -> Tuple[Optional[TestEvent], str]:
        if time.time() - self.start_time > self.timeout:
            return (
                TestEvent.GLOBAL_TIMEOUT,
                f"ERROR: Global timeout reached! ({self.timeout}s)",
            )
        return None, ""


class OutputTimeoutChecker:
    def __init__(self, timeout: int):
        self.timeout = timeout
        self.last_output_time = time.time()

    def __call__(self) -> Tuple[Optional[TestEvent], str]:
        if time.time() - self.last_output_time > self.timeout:
            return (
                TestEvent.OUTPUT_TIMEOUT,
                f"ERROR: Output timeout reached! ({self.timeout}s)",
            )
        return None, ""

    def update(self):
        """Update the last output time to the current time."""
        self.last_output_time = time.time()
