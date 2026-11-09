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

from src import utils
from src import yara_importer
from tests import helpers

_HUB_URL = "https://www.virustotal.com/gui/crowdsourced-yara-hub?filter=xmrig"
_XMRIG_RULE = {
    "id": "01596a10c1|Multi_Cryptominer_Xmrig_f9516741",
    "name": "Multi_Cryptominer_Xmrig_f9516741",
    "author": "Elastic Security",
    "matches": 9530,
    "enabled": True,
    "tags": ["miner"],
    "rule": "rule Multi_Cryptominer_Xmrig_f9516741 {\n  condition: true\n}",
    "matched_keyword": "xmrig",
    "hub_url": _HUB_URL,
}


def _yara_rule(name: str, rule_text: str) -> dict[str, Any]:
  return {**_XMRIG_RULE, "id": f"id|{name}", "name": name, "rule": rule_text}


class TestYaraImporter(unittest.TestCase):

  def setUp(self):
    super().setUp()
    self.output_path = self.enterContext(tempfile.TemporaryDirectory())
    self.enterContext(
        mock.patch.object(
            yara_importer.command, "send_event", autospec=True, spec_set=True
        )
    )

  def test_task_metadata(self):
    self.assertEqual(
        yara_importer.TASK_NAME,
        "openrelik-worker-agti.tasks.yara_importer",
    )
    self.assertEqual(
        yara_importer.TASK_METADATA["display_name"],
        "Import YARA Rules from VirusTotal",
    )
    config_names = [
        cfg["name"] for cfg in yara_importer.TASK_METADATA["task_config"]
    ]
    self.assertCountEqual(
        config_names,
        [
            "api_key",
            "custom_prompt",
            "yara_keywords",
            "yara_output_dir",
            "max_yara_rules",
        ],
    )

  def test_missing_api_key_creates_error_report(self):
    with mock.patch.dict(os.environ, {}, clear=True):
      with self.assertLogs(utils.__name__, level="ERROR") as logs:
        raw_res = helpers.decode_result(
            yara_importer.command(
                input_files=[],
                output_path=self.output_path,
                workflow_id="wf-err-1",
                task_config={"custom_prompt": "Grab coinminer yara rules"},
            )
        )

    self.assertIn("ERROR", [record.levelname for record in logs.records])
    self.assertEqual(raw_res["workflow_id"], "wf-err-1")
    self.assertEqual(len(raw_res["output_files"]), 1)
    self.assertIn("error", raw_res["meta"])

  @mock.patch.object(
      yara_importer.agti_client, "AgtiClient", autospec=True, spec_set=True
  )
  def test_standalone_prompt_yara_hub_lookup(
      self, mock_client_cls: mock.MagicMock
  ):
    mock_client = mock_client_cls.return_value
    mock_client.ask_agti.return_value = helpers.agti_response(
        "sess-yara-789",
        "Coinminer investigations commonly involve XMRig and Sysrv.\n"
        '```json\n{"keywords": ["xmrig", "coinminer", "cryptominer",'
        ' "sysrv"]}\n```',
    )
    mock_client.search_crowdsourced_yara_rules.return_value = [
        _XMRIG_RULE,
        {
            "id": "01ac6df837|miner_lin_xmrig_strings",
            "name": "miner_lin_xmrig_strings",
            "author": "Sekoia.io",
            "matches": 2421,
            "enabled": True,
            "tags": [],
            "rule": "rule miner_lin_xmrig_strings {\n  condition: true\n}",
            "matched_keyword": "xmrig",
            "hub_url": _HUB_URL,
        },
    ]
    custom_yara_folder = os.path.join(self.output_path, "custom_yara_rules")

    raw_res = helpers.decode_result(
        yara_importer.command(
            input_files=[],
            output_path=self.output_path,
            workflow_id="wf-yara-1",
            task_config={
                "api_key": "test-key-override",
                "custom_prompt": (
                    "I am working on a coinminer investigation, can you grab"
                    " related yara rules?"
                ),
                "yara_output_dir": custom_yara_folder,
            },
        )
    )

    self.assertEqual(raw_res["workflow_id"], "wf-yara-1")
    self.assertEqual(len(raw_res["output_files"]), 2)
    mock_client.__exit__.assert_called_once()
    self.assertIn(
        "Do NOT generate, synthesize, or write new YARA rules",
        mock_client.ask_agti.call_args[0][0],
    )
    mock_client.search_crowdsourced_yara_rules.assert_called_once_with(
        ["xmrig", "coinminer", "cryptominer", "sysrv"], max_total_rules=100
    )
    self.assertTrue(
        os.path.exists(
            os.path.join(
                custom_yara_folder, "Multi_Cryptominer_Xmrig_f9516741.yar"
            )
        )
    )
    self.assertTrue(
        os.path.exists(
            os.path.join(custom_yara_folder, "miner_lin_xmrig_strings.yar")
        )
    )

    md_file = helpers.find_output(raw_res, ".md")
    self.assertIn("agti_yara_import_", md_file["display_name"])
    with open(md_file["path"], "r", encoding="utf-8") as f:
      md_content = f.read()
    self.assertIn("AGTI Crowdsourced YARA Import Report", md_content)
    self.assertIn("Multi_Cryptominer_Xmrig_f9516741", md_content)
    self.assertIn(custom_yara_folder, md_content)

    with open(
        helpers.find_output(raw_res, ".json")["path"], "r", encoding="utf-8"
    ) as f:
      json_data = json.load(f)
    self.assertEqual(json_data["worker"], "Import YARA Rules from VirusTotal")
    self.assertIn("xmrig", json_data["yara_keywords"])
    self.assertIn(_HUB_URL, json_data["yara_hub_urls"])
    self.assertEqual(len(json_data["crowdsourced_yara_rules"]), 2)
    self.assertEqual(json_data["yara_output_dir"], custom_yara_folder)
    self.assertEqual(len(json_data["yara_rule_files"]), 2)

  @mock.patch.object(
      yara_importer.agti_client, "AgtiClient", autospec=True, spec_set=True
  )
  def test_invalid_max_yara_rules_falls_back_to_default(
      self, mock_client_cls: mock.MagicMock
  ):
    mock_client = mock_client_cls.return_value
    mock_client.ask_agti.return_value = helpers.agti_response(
        "sess-1", "No keywords"
    )
    mock_client.search_crowdsourced_yara_rules.return_value = []

    yara_importer.command(
        input_files=[],
        output_path=self.output_path,
        workflow_id="wf-max-1",
        task_config={
            "api_key": "test-key",
            "yara_keywords": "xmrig",
            "max_yara_rules": "999999",
        },
    )

    mock_client.search_crowdsourced_yara_rules.assert_called_once_with(
        ["xmrig"], max_total_rules=100
    )

  def test_resolve_shared_yara_dir_prefers_explicit_override(self):
    with mock.patch.dict(
        os.environ, {"OPENRELIK_YARA_RULES_FOLDER": "/env/yara"}, clear=True
    ):
      self.assertEqual(
          yara_importer.resolve_shared_yara_dir(
              self.output_path, custom_shared_dir="/custom/yara"
          ),
          "/custom/yara",
      )
      self.assertEqual(
          yara_importer.resolve_shared_yara_dir(self.output_path), "/env/yara"
      )

  def test_resolve_shared_yara_dir_uses_shared_volume(self):
    fake_volume = os.path.join(self.output_path, "openrelik_data")
    os.makedirs(fake_volume)
    with (
        mock.patch.dict(os.environ, {}, clear=True),
        mock.patch.object(
            yara_importer, "_DEFAULT_OPENRELIK_DATA_DIRS", (fake_volume,)
        ),
    ):
      self.assertEqual(
          yara_importer.resolve_shared_yara_dir(self.output_path),
          os.path.join(fake_volume, "yara"),
      )

  def test_resolve_shared_yara_dir_falls_back_to_output_path(self):
    missing_volume = os.path.join(self.output_path, "missing")
    with (
        mock.patch.dict(os.environ, {}, clear=True),
        mock.patch.object(
            yara_importer, "_DEFAULT_OPENRELIK_DATA_DIRS", (missing_volume,)
        ),
    ):
      self.assertEqual(
          yara_importer.resolve_shared_yara_dir(self.output_path),
          os.path.join(self.output_path, "yara"),
      )

  def test_write_yara_rules_handles_name_collisions(self):
    rules = [
        _yara_rule(
            "Duplicated_Rule", "rule Duplicated_Rule { condition: true }"
        ),
        _yara_rule(
            "Duplicated_Rule", "rule Duplicated_v2 { condition: false }"
        ),
        _yara_rule("", "rule Unnamed_Rule { condition: true }"),
    ]
    export_dir = os.path.join(self.output_path, "collision_test")

    written_files = yara_importer.write_yara_rules(
        rules, export_dir, workflow_id="wf-coll-1"
    )

    self.assertCountEqual(
        [os.path.basename(path) for path in written_files],
        ["Duplicated_Rule.yar", "Duplicated_Rule_1.yar", "Unnamed_Rule.yar"],
    )
    with open(written_files[0], "r", encoding="utf-8") as f:
      content = f.read()
    self.assertIn("// Author: Elastic Security", content)
    self.assertTrue(
        content.endswith("rule Duplicated_Rule { condition: true }\n")
    )

  def test_write_yara_rules_skips_empty_rule_list(self):
    export_dir = os.path.join(self.output_path, "never_created")

    self.assertEqual(yara_importer.write_yara_rules([], export_dir, None), [])
    self.assertFalse(os.path.exists(export_dir))

  @mock.patch.object(
      yara_importer.agti_client, "AgtiClient", autospec=True, spec_set=True
  )
  def test_disk_image_passthrough_chaining(
      self, mock_client_cls: mock.MagicMock
  ):
    mock_client = mock_client_cls.return_value
    mock_client.ask_agti.return_value = helpers.agti_response(
        "sess-chain-1", '```json\n{"keywords": ["xmrig"]}\n```'
    )
    mock_client.search_crowdsourced_yara_rules.return_value = [_XMRIG_RULE]

    disk_image_path = os.path.join(self.output_path, "evidence.dd")
    with open(disk_image_path, "wb") as f:
      f.write(b"\x00\x01\x02\x03DISKIMAGE")
    yara_folder = os.path.join(self.output_path, "shared_yara")

    raw_res = helpers.decode_result(
        yara_importer.command(
            input_files=[{
                "path": disk_image_path,
                "display_name": "evidence.dd",
                "extension": "dd",
                "data_type": "disk:image:raw",
            }],
            output_path=self.output_path,
            workflow_id="wf-chain-1",
            task_config={
                "api_key": "test-key",
                "custom_prompt": "Grab coinminer yara rules",
                "yara_output_dir": yara_folder,
            },
        )
    )

    self.assertEqual(len(raw_res["output_files"]), 1)
    self.assertEqual(raw_res["output_files"][0]["path"], disk_image_path)
    self.assertFalse(raw_res["output_files"][0]["register_in_db"])
    self.assertEqual(len(raw_res["task_files"]), 2)
    self.assertTrue(
        os.path.exists(
            os.path.join(yara_folder, "Multi_Cryptominer_Xmrig_f9516741.yar")
        )
    )


if __name__ == "__main__":
  unittest.main()
