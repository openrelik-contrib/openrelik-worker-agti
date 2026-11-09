# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Celery application entrypoint for the OpenRelik AGTI worker."""

import os

from celery.app import Celery
from openrelik_common import telemetry
from openrelik_worker_common.debug_utils import start_debugger

telemetry.setup_telemetry("openrelik-worker-agti")

if os.getenv("OPENRELIK_PYDEBUG") == "1":
  start_debugger()

_REDIS_URL = os.getenv("REDIS_URL")
celery = Celery(
    broker=_REDIS_URL,
    backend=_REDIS_URL,
    include=["src.tasks", "src.yara_importer"],
    # Keep the Python loggers configured by openrelik_common.logging.
    worker_hijack_root_logger=False,
    worker_log_format="%(message)s",
    worker_task_log_format="%(message)s",
)

telemetry.instrument_celery_app(celery)
