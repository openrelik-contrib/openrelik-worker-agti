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
"""OpenRelik worker task for enriching findings with Agentic GTI (AGTI)."""

from collections.abc import Mapping, Sequence
import dataclasses
from typing import Any

from celery.utils import log as celery_log
from openrelik_common import logging as openrelik_logging

from . import agti_client
from . import app
from . import ioc_utils
from . import utils

# Task name used to register and route the task to the Celery queue.
TASK_NAME = "openrelik-worker-agti.tasks.lookup"

# Task metadata registered with the OpenRelik core system.
TASK_METADATA = {
    "display_name": "Enrich Findings with Agentic GTI",
    "description": (
        "Queries Agentic Google Threat Intelligence (AGTI) to enrich IoCs,"
        " triage YARA scan results, or investigate hashes."
    ),
    "task_config": [
        {
            "name": "custom_prompt",
            "label": "Prompt / Custom Instructions",
            "description": (
                "Enter a standalone threat intelligence prompt, custom"
                " investigator instructions (e.g., 'Reverse engineer hash X',"
                " 'Focus on cronware persistence'), or leave blank to"
                " automatically triage upstream reports."
            ),
            "type": "textarea",
            "required": False,
        },
        utils.API_KEY_CONFIG,
    ],
}

_COMMAND_NAME = "agti_lookup"
_MAX_EVIDENCE_PROMPT_CHARS = 30_000
_MAX_IOCS_IN_MARKDOWN = 10

_ANALYST_ROLE = (
    "You are an expert malware analyst and threat intelligence investigator."
)
_DEFAULT_STANDALONE_PROMPT = (
    "Analyze the provided context and indicators, identifying any threat"
    " activity, malware families, and recommended containment steps."
)

_DEFAULT_ANALYSIS_SECTIONS: tuple[str, ...] = (
    "Please provide:",
    (
        "1. **Threat Verdict & Executive Summary**: Overall assessment"
        " (Malicious, Suspicious, Benign, Unknown) and severity."
    ),
    (
        "2. **Malware Families & Threat Actors**: Identified malware names,"
        " campaigns, and associated threat actors/APTs."
    ),
    (
        "3. **Capabilities & MITRE ATT&CK**: Observed capabilities,"
        " tactics, techniques, and procedures (TTPs)."
    ),
    (
        "4. **Indicator Verification**: Context and threat assessment for"
        " any hashes, network infrastructure, or artifacts mentioned."
    ),
    (
        "5. **Recommendations & Mitigations**: Actionable containment and"
        " remediation steps."
    ),
)

_logger = openrelik_logging.Logger().get_logger(
    __name__, celery_log.get_task_logger(__name__)
)


def _build_enrichment_prompt(content: str, custom_instructions: str) -> str:
  """Builds an AGTI prompt for forensic enrichment or a standalone inquiry.

  Args:
    content: Text extracted from an upstream report or artifact. If blank, a
      standalone inquiry prompt is built from `custom_instructions` alone.
    custom_instructions: Investigator instructions or question. May be blank.

  Returns:
    The formatted prompt string to send to AGTI.
  """
  content = content.strip()
  instructions = custom_instructions.strip()

  if not content:
    return "\n".join(
        [_ANALYST_ROLE, instructions or _DEFAULT_STANDALONE_PROMPT]
    )

  if len(content) > _MAX_EVIDENCE_PROMPT_CHARS:
    _logger.info(
        "Truncating evidence content from %d to %d characters for AGTI prompt.",
        len(content),
        _MAX_EVIDENCE_PROMPT_CHARS,
    )
    content = (
        content[:_MAX_EVIDENCE_PROMPT_CHARS]
        + "\n\n... [Evidence truncated for analysis prompt length] ..."
    )
  prompt_lines = [
      _ANALYST_ROLE,
      (
          "Perform a comprehensive malware and threat intelligence analysis on"
          " the following evidence/document:"
      ),
      "",
      "--- BEGIN EVIDENCE ---",
      content,
      "--- END EVIDENCE ---",
  ]
  if instructions:
    prompt_lines.extend(["", f"**Investigator Instructions:** {instructions}"])
  prompt_lines.extend(["", *_DEFAULT_ANALYSIS_SECTIONS])
  return "\n".join(prompt_lines)


def _format_ioc_bullet(label: str, values: Sequence[str]) -> str:
  """Formats a Markdown bullet summarizing up to 10 extracted indicators.

  Args:
    label: Indicator display label (e.g., `'SHA-256 Hashes'`).
    values: Sequence of extracted indicator strings.

  Returns:
    A formatted Markdown list item string.
  """
  preview = ", ".join(f"`{v}`" for v in values[:_MAX_IOCS_IN_MARKDOWN])
  extra_count = len(values) - _MAX_IOCS_IN_MARKDOWN
  extra = f" *(+{extra_count} more)*" if extra_count > 0 else ""
  return f"- **{label} ({len(values)}):** {preview or 'None'}{extra}"


def _format_markdown_report(
    file_display_name: str,
    workflow_id: str | None,
    now_utc: str,
    custom_prompt: str,
    session_id: str,
    iocs: ioc_utils.ExtractedIocs,
    agent_answer: str,
) -> str:
  """Formats the AGTI analysis results into a structured markdown report.

  Args:
    file_display_name: Display name of the analyzed target file or query.
    workflow_id: OpenRelik workflow identifier, or None if unset.
    now_utc: Formatted UTC timestamp string for the report header.
    custom_prompt: Custom investigator instructions used for the query, if any.
    session_id: AGTI session identifier returned by the API.
    iocs: Extracted indicators of compromise from the input artifact.
    agent_answer: Final markdown analysis text returned by AGTI.

  Returns:
    A formatted markdown document string.
  """
  report_lines = [
      "# 🛡️ AGTI Malware Analysis Report",
      (
          f"**Target:** `{file_display_name}` | **Workflow ID:**"
          f" `{workflow_id}` | **Date:** {now_utc}"
      ),
  ]
  if custom_prompt:
    report_lines.append(f"**Custom Instructions:** {custom_prompt}")
  if session_id:
    report_lines.append(f"**AGTI Session ID:** `{session_id}`")
  report_lines.extend([
      "",
      "---",
      "",
      "## 🎯 Extracted Indicators",
      _format_ioc_bullet("SHA-256 Hashes", iocs.sha256),
      _format_ioc_bullet("SHA-1 Hashes", iocs.sha1),
      _format_ioc_bullet("MD5 Hashes", iocs.md5),
      _format_ioc_bullet("IPv4 Addresses", iocs.ips),
      "",
      "---",
      "",
      "## 🔍 AGTI Analysis & Findings",
      "",
      agent_answer,
      "",
  ])
  return "\n".join(report_lines)


@app.celery.task(bind=True, name=TASK_NAME, metadata=TASK_METADATA)
def command(
    self,
    pipe_result: str | None = None,
    input_files: Sequence[Mapping[str, Any]] | None = None,
    output_path: str | None = None,
    workflow_id: str | None = None,
    task_config: Mapping[str, Any] | None = None,
) -> str:
  """Runs AGTI malware analysis on files, hashes, or standalone prompts.

  Args:
    self: The bound Celery task instance, used to emit progress events.
    pipe_result: Optional base64-encoded result from the previous Celery task if
      chained in a pipeline, or None if invoked directly.
    input_files: Optional sequence of input file metadata dictionaries, or None
      when using pipe_result or standalone prompts.
    output_path: Destination directory path for created report files, or None.
    workflow_id: Identifier of the current OpenRelik workflow, or None.
    task_config: Optional user configuration dictionary passed from the UI or
      CLI, or None to use defaults.

  Returns:
    A base64-encoded JSON string containing task output file metadata and
    execution details.
  """
  utils.start_task(TASK_NAME, workflow_id)

  config = task_config or {}
  custom_prompt = str(config.get("custom_prompt") or "").strip()

  try:
    client = agti_client.AgtiClient(api_key=config.get("api_key"))
  except agti_client.AgtiAuthError as e:
    return utils.create_auth_error_result(
        output_path=output_path,
        workflow_id=workflow_id,
        error=e,
        command_name=_COMMAND_NAME,
        task_display_name=TASK_METADATA["display_name"],
    )

  work_items, passthrough_files = utils.collect_work_items(
      pipe_result, input_files
  )
  # With only a prompt or only binary inputs, still run one AGTI query.
  if not work_items and (custom_prompt or passthrough_files):
    target_name = (
        passthrough_files[0]["display_name"]
        if passthrough_files
        else "prompt_query"
    )
    work_items = [utils.WorkItem(display_name=target_name, content="")]
  generated_files: list[dict[str, Any]] = []

  with client:
    for item in work_items:
      file_display_name = item.display_name
      iocs = ioc_utils.extract_iocs(item.content)
      _logger.info(
          "Processing '%s' (hashes found: %d)",
          file_display_name,
          iocs.total_hashes,
      )

      prompt = _build_enrichment_prompt(item.content, custom_prompt)
      self.send_event("task-progress", data={})
      session_id, agent_answer, raw_response = utils.run_agti_query(
          client=client, prompt=prompt, target_name=file_display_name
      )
      response_iocs = ioc_utils.extract_iocs(agent_answer)

      now_utc = utils.utc_timestamp()
      report_text = _format_markdown_report(
          file_display_name=file_display_name,
          workflow_id=workflow_id,
          now_utc=now_utc,
          custom_prompt=custom_prompt,
          session_id=session_id,
          iocs=iocs,
          agent_answer=agent_answer,
      )
      results_data = {
          "workflow_id": workflow_id,
          "file_name": file_display_name,
          "custom_prompt": custom_prompt,
          "session_id": session_id,
          "timestamp": now_utc,
          "extracted_iocs": dataclasses.asdict(iocs),
          "response_iocs": dataclasses.asdict(response_iocs),
          "agent_response": agent_answer,
          "prompt": prompt,
          "raw_response": raw_response,
      }
      generated_files.extend(
          utils.write_report_artifacts(
              output_path=output_path,
              md_display_name=f"agti_analysis_{file_display_name}",
              json_display_name=f"agti_results_{file_display_name}",
              markdown_text=report_text,
              json_data=results_data,
          )
      )

  return utils.finalize_task_result(
      generated_files=generated_files,
      passthrough_files=passthrough_files,
      workflow_id=workflow_id,
      command_name=_COMMAND_NAME,
      task_name=TASK_NAME,
  )
