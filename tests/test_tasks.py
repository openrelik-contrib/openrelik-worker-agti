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

import json
import os
import tempfile
from typing import Any
import unittest
from unittest import mock

from src import tasks
from src import utils
from tests import helpers

_SHA256 = "44d88612fea8a8f36de82e1278abb02f1469e38d748f3b25da47481f185d2634"


class TestTasks(unittest.TestCase):

  def setUp(self):
    super().setUp()
    self.output_path = self.enterContext(tempfile.TemporaryDirectory())
    self.mock_send_event = self.enterContext(
        mock.patch.object(
            tasks.command, "send_event", autospec=True, spec_set=True
        )
    )

  def _write_input(self, name: str, content: str) -> dict[str, Any]:
    path = os.path.join(self.output_path, name)
    with open(path, "w", encoding="utf-8") as f:
      f.write(content)
    return {"path": path, "display_name": name}

  def test_task_metadata(self):
    self.assertEqual(tasks.TASK_NAME, "openrelik-worker-agti.tasks.lookup")
    self.assertEqual(
        tasks.TASK_METADATA["display_name"],
        "Enrich Findings with Agentic GTI",
    )
    self.assertEqual(
        tasks.TASK_METADATA["description"],
        (
            "Queries Agentic Google Threat Intelligence (AGTI) to enrich IoCs,"
            " triage YARA scan results, or investigate hashes."
        ),
    )
    config_names = [cfg["name"] for cfg in tasks.TASK_METADATA["task_config"]]
    self.assertCountEqual(config_names, ["api_key", "custom_prompt"])

  def test_command_missing_api_key_creates_error_report(self):
    input_file = self._write_input("dummy.txt", "test content")

    with mock.patch.dict(os.environ, {}, clear=True):
      with self.assertLogs(utils.__name__, level="ERROR") as logs:
        raw_res = helpers.decode_result(
            tasks.command(
                input_files=[input_file],
                output_path=self.output_path,
                workflow_id="wf-123",
                task_config={},
            )
        )

    self.assertIn("ERROR", [record.levelname for record in logs.records])
    self.assertEqual(raw_res["workflow_id"], "wf-123")
    self.assertEqual(len(raw_res["output_files"]), 1)
    self.assertIn("error", raw_res["meta"])
    with open(raw_res["output_files"][0]["path"], "r", encoding="utf-8") as f:
      err_text = f.read()
    self.assertIn(
        "Enrich Findings with Agentic GTI: authentication failure", err_text
    )
    self.assertIn("GTI_API_KEY", err_text)

  @mock.patch.object(
      tasks.agti_client, "AgtiClient", autospec=True, spec_set=True
  )
  def test_command_markdown_document_analysis(
      self, mock_client_cls: mock.MagicMock
  ):
    mock_client = mock_client_cls.return_value
    mock_client.ask_agti.return_value = helpers.agti_response(
        "sess-doc-123", "Analysis indicates BlackCat ransomware activity."
    )
    input_file = self._write_input(
        "notes.md",
        "# Incident Investigation Notes\nTarget host contacted 198.51.100.5.\n"
        f"Observed executable hash: {_SHA256}\n",
    )

    raw_res = helpers.decode_result(
        tasks.command(
            input_files=[input_file],
            output_path=self.output_path,
            workflow_id="wf-999",
            task_config={"api_key": "test-key-override"},
        )
    )

    self.assertEqual(raw_res["workflow_id"], "wf-999")
    self.assertEqual(len(raw_res["output_files"]), 2)
    mock_client.__exit__.assert_called_once()
    self.mock_send_event.assert_called_with("task-progress", data={})

    with open(
        helpers.find_output(raw_res, ".md")["path"], "r", encoding="utf-8"
    ) as f:
      md_content = f.read()
    self.assertIn("AGTI Malware Analysis Report", md_content)
    self.assertIn("BlackCat ransomware", md_content)
    self.assertIn(_SHA256, md_content)

    with open(
        helpers.find_output(raw_res, ".json")["path"], "r", encoding="utf-8"
    ) as f:
      json_data = json.load(f)
    self.assertEqual(json_data["session_id"], "sess-doc-123")
    self.assertIn("BlackCat ransomware", json_data["agent_response"])
    self.assertEqual(json_data["extracted_iocs"]["sha256"], [_SHA256])
    self.assertEqual(json_data["extracted_iocs"]["ips"], ["198.51.100.5"])

  @mock.patch.object(
      tasks.agti_client, "AgtiClient", autospec=True, spec_set=True
  )
  def test_command_hash_list_lookup(self, mock_client_cls: mock.MagicMock):
    mock_client = mock_client_cls.return_value
    mock_client.ask_agti.return_value = helpers.agti_response(
        "sess-hash-456", "Hash matches Emotet banking trojan loader."
    )
    input_file = self._write_input(
        "hashes.txt", f"{_SHA256}\n2fd4e1c67a2d28fced849ee1bb76e7391b93eb12\n"
    )

    raw_res = helpers.decode_result(
        tasks.command(
            input_files=[input_file],
            output_path=self.output_path,
            workflow_id="wf-hash-1",
            task_config={"api_key": "test-key-override"},
        )
    )

    self.assertEqual(len(raw_res["output_files"]), 2)
    mock_client.ask_agti.assert_called_once()
    self.assertIn(_SHA256, mock_client.ask_agti.call_args[0][0])

  @mock.patch.object(
      tasks.agti_client, "AgtiClient", autospec=True, spec_set=True
  )
  def test_command_standalone_prompt_lookup(
      self, mock_client_cls: mock.MagicMock
  ):
    mock_client = mock_client_cls.return_value
    mock_client.ask_agti.return_value = helpers.agti_response(
        "sess-prompt-1", "APT41 is a prolific state-sponsored threat group."
    )

    raw_res = helpers.decode_result(
        tasks.command(
            input_files=[],
            output_path=self.output_path,
            workflow_id="wf-prompt-1",
            task_config={
                "api_key": "test-key",
                "custom_prompt": "Summarize recent APT41 TTPs.",
            },
        )
    )

    self.assertEqual(raw_res["workflow_id"], "wf-prompt-1")
    self.assertEqual(len(raw_res["output_files"]), 2)
    with open(
        helpers.find_output(raw_res, ".json")["path"], "r", encoding="utf-8"
    ) as f:
      json_data = json.load(f)
    self.assertEqual(json_data["custom_prompt"], "Summarize recent APT41 TTPs.")
    self.assertIn("APT41", json_data["agent_response"])

  @mock.patch.object(
      tasks.agti_client, "AgtiClient", autospec=True, spec_set=True
  )
  def test_command_agti_error_writes_error_report(
      self, mock_client_cls: mock.MagicMock
  ):
    mock_client = mock_client_cls.return_value
    mock_client.ask_agti.side_effect = tasks.agti_client.AgtiError(
        "Backend failure"
    )

    with self.assertLogs(utils.__name__, level="ERROR") as logs:
      raw_res = helpers.decode_result(
          tasks.command(
              input_files=[],
              output_path=self.output_path,
              workflow_id="wf-err-2",
              task_config={
                  "api_key": "test-key",
                  "custom_prompt": "Analyze threat",
              },
          )
      )

    self.assertIn("ERROR", [record.levelname for record in logs.records])
    self.assertEqual(len(raw_res["output_files"]), 2)
    with open(
        helpers.find_output(raw_res, ".md")["path"], "r", encoding="utf-8"
    ) as f:
      self.assertIn("AGTI Analysis Error", f.read())


if __name__ == "__main__":
  unittest.main()
