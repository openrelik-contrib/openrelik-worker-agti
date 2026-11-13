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
"""Shared helpers for the OpenRelik AGTI worker tasks."""

from collections.abc import Mapping, Sequence
import dataclasses
import datetime
import json
import os
from typing import Any

from celery import signals
from celery.utils import log as celery_log
from openrelik_common import logging as openrelik_logging
from openrelik_common import telemetry
from openrelik_worker_common import file_utils
from openrelik_worker_common import task_utils

from . import agti_client
from . import ioc_utils

# Task config entry shared by every AGTI task for overriding GTI_API_KEY.
API_KEY_CONFIG = {
    "name": "api_key",
    "label": "GTI API Key (Optional Override)",
    "description": (
        "Optionally override the GTI_API_KEY environment variable. If left"
        " empty, the worker's GTI_API_KEY environment variable is used."
    ),
    "type": "text",
    "required": False,
}

_log_root = openrelik_logging.Logger()
_logger = _log_root.get_logger(__name__, celery_log.get_task_logger(__name__))


@dataclasses.dataclass(frozen=True)
class WorkItem:
  """A single text input to analyze.

  Attributes:
    display_name: Name of the input file or query shown in reports.
    content: Text content to analyze; empty for prompt-only queries.
  """

  display_name: str
  content: str


@signals.task_prerun.connect
def on_task_prerun(sender, task_id, task, args, kwargs, **_):
  """Binds task metadata to the structured logger prior to task execution.

  Args:
    sender: The Celery task class or sender object.
    task_id: Unique identifier of the executing Celery task.
    task: The Celery task instance being executed.
    args: Positional arguments passed to the task.
    kwargs: Keyword arguments passed to the task.
    **_: Additional signal keyword arguments ignored by this handler.
  """
  del sender, args, kwargs
  _log_root.bind(
      task_id=task_id,
      task_name=task.name,
      worker_name=task.metadata["display_name"],
  )


def start_task(task_name: str, workflow_id: str | None) -> None:
  """Binds the workflow to logs and telemetry and logs the task start.

  Args:
    task_name: Registered Celery task name.
    workflow_id: Identifier of the current OpenRelik workflow, or None.
  """
  _log_root.bind(workflow_id=workflow_id)
  telemetry.add_attribute_to_current_span("workflow_id", workflow_id)
  _logger.info("Starting %s for workflow %s", task_name, workflow_id)


def utc_timestamp() -> str:
  """Returns the current UTC time formatted for report headers."""
  return datetime.datetime.now(datetime.timezone.utc).strftime(
      "%Y-%m-%d %H:%M:%S UTC"
  )


def create_auth_error_result(
    output_path: str,
    workflow_id: str | None,
    error: agti_client.AgtiAuthError,
    command_name: str,
    task_display_name: str,
) -> str:
  """Writes an authentication failure Markdown report and returns a task result.

  Args:
    output_path: Destination directory path for created report files.
    workflow_id: Identifier of the current OpenRelik workflow, or None.
    error: The authentication error raised during client initialization.
    command_name: Identifier for the command in the OpenRelik task result.
    task_display_name: Display name of the task, used in the report heading.

  Returns:
    A base64-encoded JSON string representing the OpenRelik task result.
  """
  _logger.error("AGTI authentication error in %s: %r", command_name, error)
  err_file = file_utils.create_output_file(
      output_path,
      display_name=f"{command_name}_error_authentication",
      extension="md",
      data_type="text/markdown",
  )
  with open(err_file.path, "w", encoding="utf-8") as f:
    f.write(
        f"# ⚠️ {task_display_name}: authentication failure\n\n**Error:**"
        f" {error}\n\n**Resolution:**\n- Set the"
        " `GTI_API_KEY` environment variable in your OpenRelik worker"
        " configuration, or\n- Provide your GTI API key in the task"
        " configuration modal before launching the task.\n"
    )
  return task_utils.create_task_result(
      output_files=[err_file.to_dict()],
      workflow_id=workflow_id,
      command=command_name,
      meta={"error": str(error)},
  )


def collect_work_items(
    pipe_result: str | None,
    input_files: Sequence[Mapping[str, Any]] | None,
) -> tuple[list[WorkItem], list[dict[str, Any]]]:
  """Splits the task's input files into text work items and pass-through files.

  Binary files and disk images are passed through unchanged (but not
  re-registered in the database) so downstream workers can process them.
  Readable, non-empty text files become work items.

  Args:
    pipe_result: Optional base64-encoded result from the previous Celery task.
    input_files: Optional sequence of input file metadata dictionaries.

  Returns:
    A `(work_items, passthrough_files)` tuple.
  """
  resolved_input_files = task_utils.get_input_files(
      pipe_result, list(input_files or [])
  )
  telemetry.add_attribute_to_current_span(
      "input_files", [f.get("display_name") for f in resolved_input_files]
  )
  work_items: list[WorkItem] = []
  passthrough_files: list[dict[str, Any]] = []

  for input_file in resolved_input_files:
    file_path = input_file.get("path")
    if not file_path:
      continue
    display_name = str(
        input_file.get("display_name") or os.path.basename(file_path)
    )

    if ioc_utils.is_disk_or_binary_file(input_file):
      _logger.info(
          "Passing through binary/disk image '%s' for downstream workers",
          display_name,
      )
      passthrough_files.append(
          {**input_file, "display_name": display_name, "register_in_db": False}
      )
      continue

    try:
      with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()
    except OSError as e:
      _logger.error("Failed to read input file %s: %r", file_path, e)
      continue

    if not content.strip():
      _logger.warning("Input file is empty: %s", file_path)
      continue

    work_items.append(WorkItem(display_name=display_name, content=content))

  return work_items, passthrough_files


def run_agti_query(
    client: agti_client.AgtiClient,
    prompt: str,
    target_name: str,
) -> tuple[str, str, dict[str, Any]]:
  """Submits a prompt to AGTI and extracts the session ID and agent response.

  Args:
    client: Initialized AgtiClient instance.
    prompt: Formatted prompt string to send to AGTI.
    target_name: Display name of the target artifact or query for logging.

  Returns:
    A `(session_id, agent_answer, raw_response)` tuple. If an `AgtiError`
    occurs, returns an empty session ID, a Markdown error string, and an empty
    raw response dictionary.
  """
  try:
    _logger.info("Querying AGTI for '%s'...", target_name)
    raw_response = client.ask_agti(prompt)
  except agti_client.AgtiError as e:
    _logger.error("AGTI request failed for '%s': %r", target_name, e)
    return (
        "",
        f"**AGTI Analysis Error:** Failed to retrieve response from AGTI: {e}",
        {},
    )
  session_id = agti_client.extract_session_id(raw_response)
  _logger.info("AGTI query completed (session_id: %s)", session_id or "new")
  return (
      session_id,
      agti_client.extract_agent_response(raw_response),
      raw_response,
  )


def write_report_artifacts(
    output_path: str,
    md_display_name: str,
    json_display_name: str,
    markdown_text: str,
    json_data: Mapping[str, Any],
) -> list[dict[str, Any]]:
  """Writes paired Markdown and JSON task output artifacts to `output_path`.

  Args:
    output_path: Destination directory path for created report files.
    md_display_name: Display name for the generated `.md` output file.
    json_display_name: Display name for the generated `.json` output file.
    markdown_text: Formatted Markdown report content to write.
    json_data: Serializable dictionary payload to write as formatted JSON.

  Returns:
    The serialized dictionaries of the created Markdown and JSON output files.
  """
  md_output_file = file_utils.create_output_file(
      output_path,
      display_name=md_display_name,
      extension="md",
      data_type="text/markdown",
  )
  with open(md_output_file.path, "w", encoding="utf-8") as f:
    f.write(markdown_text)

  json_output_file = file_utils.create_output_file(
      output_path,
      display_name=json_display_name,
      extension="json",
      data_type="application/json",
  )
  with open(json_output_file.path, "w", encoding="utf-8") as f:
    json.dump(json_data, f, indent=2)

  return [md_output_file.to_dict(), json_output_file.to_dict()]


def finalize_task_result(
    generated_files: Sequence[dict[str, Any]],
    passthrough_files: Sequence[dict[str, Any]],
    workflow_id: str | None,
    command_name: str,
    task_name: str,
) -> str:
  """Packages generated and pass-through files into an OpenRelik task result.

  When binary/disk image inputs are passed through, they become the task's
  output files (so downstream workers receive them) and the generated reports
  are attached as task files instead.

  Args:
    generated_files: File metadata dicts created by the task.
    passthrough_files: Binary/disk image file dicts passed through to downstream
      pipeline workers.
    workflow_id: Identifier of the current OpenRelik workflow, or None.
    command_name: Command identifier recorded in the task result payload.
    task_name: Registered Celery task name recorded in result metadata.

  Returns:
    A base64-encoded JSON string representing the OpenRelik task result.
  """
  _logger.info(
      "Finished %s for workflow %s with %d generated files and %d"
      " pass-through files",
      task_name,
      workflow_id,
      len(generated_files),
      len(passthrough_files),
  )
  if passthrough_files:
    output_files, task_files = list(passthrough_files), list(generated_files)
  else:
    output_files, task_files = list(generated_files), []
  return task_utils.create_task_result(
      output_files=output_files,
      workflow_id=workflow_id,
      task_files=task_files,
      command=command_name,
      meta={"worker": task_name},
  )
