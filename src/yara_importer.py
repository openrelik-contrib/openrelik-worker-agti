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
"""OpenRelik worker task for importing Crowdsourced YARA rules via AGTI."""

from collections.abc import Mapping, Sequence
import os
import re
from typing import Any

from celery.utils import log as celery_log
from openrelik_common import logging as openrelik_logging

from . import agti_client
from . import app
from . import ioc_utils
from . import utils

# Task name used to register and route the task to the Celery queue.
TASK_NAME = "openrelik-worker-agti.tasks.yara_importer"

_COMMAND_NAME = "agti_yara_importer"
_WORKER_DISPLAY_NAME = "Import YARA Rules from VirusTotal"

# Shared OpenRelik data volume mount points, checked in order.
_DEFAULT_OPENRELIK_DATA_DIRS = (
    "/mnt/openrelikvolume",
    "/usr/share/openrelik/data",
)

_MAX_YARA_RULES_CHOICES = ("25", "50", "100", "250")
_DEFAULT_MAX_YARA_RULES = "100"
_MAX_DISPLAYED_RULES_IN_MARKDOWN = 50

# Task metadata registered with the OpenRelik core system.
TASK_METADATA = {
    "display_name": _WORKER_DISPLAY_NAME,
    "description": (
        "Expands threat scenarios and keywords via AGTI, queries the"
        " VirusTotal Crowdsourced YARA Hub (/api/v3/yara_rules), and writes"
        " individual .yar rule files directly to the shared YARA folder."
    ),
    "task_config": [
        utils.API_KEY_CONFIG,
        {
            "name": "custom_prompt",
            "label": "Threat Scenario / Investigation Prompt",
            "description": (
                "Describe the threat scenario, malware family, or hunting"
                " objective (e.g., 'Find rules for Linux rootkits and"
                " webshells', 'Ransomware persistence mechanisms', or"
                " 'Suspected infostealer activity')."
            ),
            "type": "textarea",
            "required": False,
        },
        {
            "name": "yara_keywords",
            "label": "YARA Filter Keywords (Optional)",
            "description": (
                "Optional comma-separated keywords, malware families, tools,"
                " or threat categories (e.g., 'ransomware, infostealer,"
                " webshell, mimikatz') to query against the VirusTotal"
                " Crowdsourced YARA Hub (/api/v3/yara_rules)."
            ),
            "type": "text",
            "required": False,
        },
        {
            "name": "yara_output_dir",
            "label": "YARA Rules Output Folder",
            "description": (
                "Folder path where each identified YARA rule will be written"
                " as an individual .yar file (e.g., '/mnt/openrelikvolume/yara'"
                " or '/usr/share/openrelik/data/yara'). If left empty, the"
                " worker uses OPENRELIK_YARA_RULES_FOLDER or the yara folder on"
                " the shared volume."
            ),
            "type": "text",
            "required": False,
        },
        {
            "name": "max_yara_rules",
            "label": "Max YARA Rules to Fetch",
            "description": (
                "Maximum number of deduplicated Crowdsourced YARA rules to"
                " retrieve across expanded keywords (default: 100)."
            ),
            "type": "select",
            "items": list(_MAX_YARA_RULES_CHOICES),
            "value": _DEFAULT_MAX_YARA_RULES,
            "required": False,
        },
    ],
}

_logger = openrelik_logging.Logger().get_logger(
    __name__, celery_log.get_task_logger(__name__)
)


def resolve_shared_yara_dir(
    output_path: str, custom_shared_dir: str = ""
) -> str:
  """Resolves the folder where individual `.yar` rule files are written.

  Checks, in order: the task's `yara_output_dir` override, the
  `OPENRELIK_YARA_RULES_FOLDER` environment variable, a writable shared
  OpenRelik data volume, and finally the task output folder.

  Args:
    output_path: Task output directory path.
    custom_shared_dir: Explicit output directory override from task config.

  Returns:
    The filesystem path where `.yar` files should be written.
  """
  explicit_dir = (
      custom_shared_dir.strip()
      or (os.getenv("OPENRELIK_YARA_RULES_FOLDER") or "").strip()
  )
  if explicit_dir:
    return explicit_dir

  for data_dir in _DEFAULT_OPENRELIK_DATA_DIRS:
    if os.path.isdir(data_dir) and os.access(data_dir, os.W_OK):
      return os.path.join(data_dir, "yara")

  return os.path.join(output_path, "yara")


def _rule_file_stem(rule: Mapping[str, Any]) -> str:
  """Returns a filesystem-safe file name (without extension) for a YARA rule.

  Uses the rule's name, falling back to the identifier in its `rule <name>`
  declaration, and replaces any character that is not a letter, digit, `_`, or
  `-` with `_`.

  Args:
    rule: YARA rule dictionary returned by `search_crowdsourced_yara_rules`.

  Returns:
    The file name stem.
  """
  name = rule["name"]
  if not name:
    match = re.search(r"\brule\s+([a-zA-Z_][a-zA-Z0-9_]*)", rule["rule"])
    name = match.group(1) if match else ""
  return re.sub(r"[^a-zA-Z0-9_\-]", "_", name).strip("_") or "agti_rule"


def _format_yara_rule_file(
    rule: Mapping[str, Any], workflow_id: str | None
) -> str:
  """Returns `.yar` file content: provenance comments followed by the rule.

  Args:
    rule: YARA rule dictionary returned by `search_crowdsourced_yara_rules`.
    workflow_id: OpenRelik workflow identifier, or `None` if unavailable.

  Returns:
    The `.yar` file content.
  """
  return (
      "// Imported by OpenRelik AGTI YARA Rule Importer"
      f" (Workflow: {workflow_id})\n"
      f"// Rule: {rule['name']}\n"
      f"// Author: {rule['author']}\n"
      f"// Matches: {rule['matches']}\n"
      f"// Keyword: {rule['matched_keyword']}\n"
      f"// Crowdsourced YARA Hub: {rule['hub_url']}\n"
      f"{rule['rule']}\n"
  )


def write_yara_rules(
    rules: Sequence[Mapping[str, Any]],
    yara_dir: str,
    workflow_id: str | None,
) -> list[str]:
  """Writes each YARA rule to its own `.yar` file in `yara_dir`.

  Rules that share a name get a numeric suffix (`name.yar`, `name_1.yar`, ...).
  Existing files with the same name are overwritten, so re-running an import is
  idempotent.

  Args:
    rules: YARA rule dictionaries returned by `search_crowdsourced_yara_rules`.
    yara_dir: Folder to write the `.yar` files to; created if missing.
    workflow_id: OpenRelik workflow identifier, or `None` if unavailable.

  Returns:
    Paths of the written files, or an empty list if `rules` is empty or the
    folder could not be written.
  """
  if not rules:
    return []

  written_files: list[str] = []
  name_counts: dict[str, int] = {}
  try:
    os.makedirs(yara_dir, exist_ok=True)
    for rule in rules:
      stem = _rule_file_stem(rule)
      count = name_counts.get(stem, 0)
      name_counts[stem] = count + 1
      if count:
        stem = f"{stem}_{count}"
      file_path = os.path.join(yara_dir, f"{stem}.yar")
      with open(file_path, "w", encoding="utf-8") as f:
        f.write(_format_yara_rule_file(rule, workflow_id))
      written_files.append(file_path)
  except OSError as e:
    _logger.warning("Could not write YARA rules to %s: %r", yara_dir, e)
    return []

  _logger.info("Wrote %d YARA rule files to %s", len(written_files), yara_dir)
  return written_files


def _build_yara_keyword_expansion_prompt(
    user_prompt: str, file_context: str
) -> str:
  """Builds a prompt instructing AGTI to expand threat search keywords.

  Args:
    user_prompt: Threat scenario or investigation prompt from the user.
    file_context: Evidence text content. If blank, no evidence context block is
      included.

  Returns:
    The formatted prompt string instructing AGTI to return threat context and
    JSON search keywords without synthesizing new YARA rules.
  """
  prompt_lines = [
      "You are an expert malware analyst and threat intelligence investigator.",
      (
          "IMPORTANT: Do NOT generate, synthesize, or write new YARA rules."
          " Instead, help identify existing malware families, tools, and"
          " search keywords to query in the VirusTotal Crowdsourced YARA Hub."
      ),
      "",
      f"**Investigation Request:** {user_prompt.strip()}",
  ]
  if file_context and file_context.strip():
    prompt_lines.extend([
        "",
        "--- BEGIN EVIDENCE CONTEXT ---",
        file_context.strip(),
        "--- END EVIDENCE CONTEXT ---",
    ])
  prompt_lines.extend([
      "",
      "Please provide:",
      (
          "1. **Threat Context & Malware Families**: Brief overview of the"
          " relevant malware families, tools, threat actors, and key"
          " behavioral indicators associated with this investigation."
      ),
      (
          "2. **Crowdsourced YARA Hub Search Keywords**: At the very end of"
          " your response, output a JSON code block containing single-word"
          " threat category tags, synonym terms, malware family names, and"
          " tool names to filter on in `/api/v3/yara_rules`, using this exact"
          " format:"
      ),
      "```json",
      '{"keywords": ["family1", "tool2", "tag3"]}',
      "```",
  ])
  return "\n".join(prompt_lines)


def _format_yara_import_report(
    file_display_name: str,
    workflow_id: str | None,
    now_utc: str,
    session_id: str,
    yara_keywords: Sequence[str],
    crowdsourced_yara_rules: Sequence[Mapping[str, Any]],
    yara_dir: str,
    written_rule_files: Sequence[str],
    agent_answer: str,
) -> str:
  """Formats the YARA rule import summary into a structured Markdown report.

  Args:
    file_display_name: Display name of the target artifact or query.
    workflow_id: OpenRelik workflow identifier, or `None` if unavailable.
    now_utc: Formatted UTC timestamp string for the report header.
    session_id: AGTI session identifier returned by the API.
    yara_keywords: Sequence of expanded search keywords queried on VirusTotal.
    crowdsourced_yara_rules: Sequence of imported YARA rule metadata dicts.
    yara_dir: Folder the `.yar` files were written to.
    written_rule_files: Paths of the `.yar` files that were written.
    agent_answer: Threat context and keyword expansion text returned by AGTI.

  Returns:
    The formatted Markdown report string.
  """
  session_suffix = (
      f" | **AGTI Session ID:** `{session_id}`" if session_id else ""
  )
  report_lines = [
      "# 📜 AGTI Crowdsourced YARA Import Report",
      (
          f"**Target:** `{file_display_name}` | **Workflow ID:**"
          f" `{workflow_id}` | **Date:** {now_utc}"
      ),
      f"**Worker:** `{_WORKER_DISPLAY_NAME}`{session_suffix}",
      "",
      "---",
      "",
      "## 📜 Crowdsourced YARA Rules & Hub Filters",
      (
          f"- **Expanded Search Keywords ({len(yara_keywords)}):**"
          f" {', '.join(f'`{kw}`' for kw in yara_keywords) or 'None'}"
      ),
      (
          "- **Total Deduplicated YARA Rules Pulled:**"
          f" `{len(crowdsourced_yara_rules)}`"
      ),
  ]
  if written_rule_files:
    report_lines.extend([
        f"- **YARA Output Folder (for `Yara scan`):** `{yara_dir}`",
        f"- **Individual `.yar` Files Written:** `{len(written_rule_files)}`",
    ])

  if yara_keywords:
    report_lines.extend(["", "### 🔗 VirusTotal Crowdsourced YARA Hub Links"])
    for kw in yara_keywords:
      hub_url = agti_client.build_yara_hub_url(kw)
      report_lines.append(f"- **Filter `{kw}`:** [{hub_url}]({hub_url})")
    report_lines.append("")

  if crowdsourced_yara_rules:
    report_lines.extend([
        "### 📋 Imported YARA Rules",
        "",
        "| Rule Name | Author | Matches | Enabled | Keyword |",
        "| :--- | :--- | :---: | :---: | :--- |",
    ])
    for rule_obj in crowdsourced_yara_rules[:_MAX_DISPLAYED_RULES_IN_MARKDOWN]:
      enabled_str = "Yes" if rule_obj.get("enabled") else "No"
      report_lines.append(
          f"| `{rule_obj.get('name', '')}` |"
          f" {rule_obj.get('author', 'Unknown')} |"
          f" {rule_obj.get('matches', 0)} | {enabled_str} |"
          f" `{rule_obj.get('matched_keyword', '')}` |"
      )
    extra_count = (
        len(crowdsourced_yara_rules) - _MAX_DISPLAYED_RULES_IN_MARKDOWN
    )
    if extra_count > 0:
      report_lines.append(
          f"\n*(+{extra_count} additional rules written to shared YARA folder)*"
      )
    report_lines.append("")

  report_lines.extend([
      "---",
      "",
      "## 🔍 AGTI Threat Context & Keyword Expansion",
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
  """Expands threat keywords via AGTI and imports Crowdsourced YARA rules.

  Args:
    self: The bound Celery task instance, used to emit progress events.
    pipe_result: Base64-encoded result from the previous Celery task, or `None`
      if this task is the first node in the workflow.
    input_files: Sequence of input file metadata mappings, or `None` if inputs
      are provided via `pipe_result` or the task runs standalone.
    output_path: Destination directory path for generated report files, or
      `None` when not specified by the caller.
    workflow_id: Identifier of the current OpenRelik workflow, or `None` if
      unavailable.
    task_config: User configuration mapping passed from the OpenRelik UI or CLI,
      or `None` to use defaults.

  Returns:
    A base64-encoded JSON string representing the OpenRelik task result.
  """
  utils.start_task(TASK_NAME, workflow_id)

  config = task_config or {}
  custom_prompt = str(config.get("custom_prompt") or "").strip()
  yara_keywords_cfg = str(config.get("yara_keywords") or "").strip()
  yara_output_dir_cfg = str(config.get("yara_output_dir") or "").strip()
  max_rules_cfg = str(config.get("max_yara_rules") or _DEFAULT_MAX_YARA_RULES)
  if max_rules_cfg not in _MAX_YARA_RULES_CHOICES:
    max_rules_cfg = _DEFAULT_MAX_YARA_RULES
  max_yara_rules = int(max_rules_cfg)

  try:
    client = agti_client.AgtiClient(api_key=config.get("api_key"))
  except agti_client.AgtiAuthError as e:
    return utils.create_auth_error_result(
        output_path=output_path,
        workflow_id=workflow_id,
        error=e,
        command_name=_COMMAND_NAME,
        task_display_name=_WORKER_DISPLAY_NAME,
    )

  work_items, passthrough_files = utils.collect_work_items(
      pipe_result, input_files
  )
  # Without text inputs, still run one keyword expansion from the prompt,
  # configured keywords, or the name of the passed-through file.
  if not work_items:
    target_name = (
        passthrough_files[0]["display_name"]
        if passthrough_files
        else "yara_import"
    )
    work_items = [utils.WorkItem(display_name=target_name, content="")]
  yara_dir = resolve_shared_yara_dir(output_path, yara_output_dir_cfg)
  generated_files: list[dict[str, Any]] = []

  with client:
    for item in work_items:
      file_display_name = item.display_name
      effective_user_prompt = (
          custom_prompt
          or f"Find YARA rules related to: {yara_keywords_cfg or file_display_name}"
      )
      prompt = _build_yara_keyword_expansion_prompt(
          effective_user_prompt, item.content
      )
      self.send_event("task-progress", data={})
      session_id, agent_answer, raw_response = utils.run_agti_query(
          client=client, prompt=prompt, target_name=file_display_name
      )

      yara_keywords = ioc_utils.normalize_keywords(
          [yara_keywords_cfg, *ioc_utils.parse_agti_keywords(agent_answer)]
      )

      crowdsourced_yara_rules: list[dict[str, Any]] = []
      if yara_keywords:
        self.send_event("task-progress", data={})
        try:
          _logger.info(
              "Querying Crowdsourced YARA Hub for keywords: %s", yara_keywords
          )
          crowdsourced_yara_rules = client.search_crowdsourced_yara_rules(
              yara_keywords, max_total_rules=max_yara_rules
          )
          _logger.info(
              "Retrieved %d deduplicated Crowdsourced YARA rules",
              len(crowdsourced_yara_rules),
          )
        except agti_client.AgtiError as e:
          _logger.error("Crowdsourced YARA Hub query failed: %r", e)

      # Rules go ONLY to the shared YARA folder (never the task output folder).
      written_rule_files = write_yara_rules(
          crowdsourced_yara_rules, yara_dir, workflow_id
      )

      now_utc = utils.utc_timestamp()
      report_text = _format_yara_import_report(
          file_display_name=file_display_name,
          workflow_id=workflow_id,
          now_utc=now_utc,
          session_id=session_id,
          yara_keywords=yara_keywords,
          crowdsourced_yara_rules=crowdsourced_yara_rules,
          yara_dir=yara_dir,
          written_rule_files=written_rule_files,
          agent_answer=agent_answer,
      )
      results_data = {
          "workflow_id": workflow_id,
          "file_name": file_display_name,
          "worker": _WORKER_DISPLAY_NAME,
          "session_id": session_id,
          "timestamp": now_utc,
          "yara_keywords": yara_keywords,
          "yara_hub_urls": [
              agti_client.build_yara_hub_url(kw) for kw in yara_keywords
          ],
          "yara_output_dir": yara_dir,
          "yara_rule_files": written_rule_files,
          "crowdsourced_yara_rules": crowdsourced_yara_rules,
          "agent_response": agent_answer,
          "prompt": prompt,
          "raw_response": raw_response,
      }
      artifact_base_name = f"agti_yara_import_{file_display_name}"
      generated_files.extend(
          utils.write_report_artifacts(
              output_path=output_path,
              md_display_name=artifact_base_name,
              json_display_name=artifact_base_name,
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
