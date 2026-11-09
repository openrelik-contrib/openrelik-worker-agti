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

import os
import tempfile
from typing import Any
import unittest
from unittest import mock

from src import agti_client
from src import tasks
from src import utils
from src import yara_importer
from tests import helpers


class TestUtils(unittest.TestCase):

  def setUp(self):
    super().setUp()
    self.output_path = self.enterContext(tempfile.TemporaryDirectory())

  def _write_input(self, name: str, content: bytes) -> dict[str, Any]:
    path = os.path.join(self.output_path, name)
    with open(path, "wb") as f:
      f.write(content)
    return {"path": path, "display_name": name}

  def test_collect_work_items_separates_text_and_binary_files(self):
    text_file = self._write_input("notes.txt", b"suspicious activity")
    binary_file = self._write_input("evidence.bin", b"\x00\x01\x02")

    work_items, passthrough_files = utils.collect_work_items(
        None, [text_file, binary_file]
    )

    self.assertEqual(
        work_items,
        [
            utils.WorkItem(
                display_name="notes.txt", content="suspicious activity"
            )
        ],
    )
    self.assertEqual(len(passthrough_files), 1)
    self.assertEqual(passthrough_files[0]["path"], binary_file["path"])
    self.assertEqual(passthrough_files[0]["display_name"], "evidence.bin")
    self.assertFalse(passthrough_files[0]["register_in_db"])

  def test_collect_work_items_skips_empty_and_missing_files(self):
    empty_file = self._write_input("empty.txt", b"   ")
    missing_file = {"path": os.path.join(self.output_path, "missing.txt")}

    work_items, passthrough_files = utils.collect_work_items(
        None, [empty_file, missing_file]
    )

    self.assertEqual(work_items, [])
    self.assertEqual(passthrough_files, [])

  def test_collect_work_items_names_passthrough_after_basename(self):
    binary_file = self._write_input("disk.raw", b"\x00DISK")
    del binary_file["display_name"]

    _, passthrough_files = utils.collect_work_items(None, [binary_file])

    self.assertEqual(passthrough_files[0]["display_name"], "disk.raw")

  def test_run_agti_query_returns_error_text_on_failure(self):
    mock_client = mock.create_autospec(
        agti_client.AgtiClient, instance=True, spec_set=True
    )
    mock_client.ask_agti.side_effect = agti_client.AgtiError("boom")

    session_id, agent_answer, raw_response = utils.run_agti_query(
        mock_client, "prompt", "target"
    )

    self.assertEqual(session_id, "")
    self.assertIn("AGTI Analysis Error", agent_answer)
    self.assertEqual(raw_response, {})

  def test_on_task_prerun_binds_registered_task_metadata(self):
    for task, metadata in (
        (tasks.command, tasks.TASK_METADATA),
        (yara_importer.command, yara_importer.TASK_METADATA),
    ):
      self.assertEqual(task.metadata["display_name"], metadata["display_name"])
      utils.on_task_prerun(
          sender=task, task_id="task-1", task=task, args=(), kwargs={}
      )

  def test_finalize_task_result_moves_reports_to_task_files_on_passthrough(
      self,
  ):
    generated = [{"path": "/out/report.md"}]
    passthrough = [{"path": "/in/disk.raw", "register_in_db": False}]

    with_passthrough = helpers.decode_result(
        utils.finalize_task_result(
            generated, passthrough, "wf-1", "cmd", "task-name"
        )
    )
    without_passthrough = helpers.decode_result(
        utils.finalize_task_result(generated, [], "wf-1", "cmd", "task-name")
    )

    self.assertEqual(with_passthrough["output_files"], passthrough)
    self.assertEqual(with_passthrough["task_files"], generated)
    self.assertEqual(without_passthrough["output_files"], generated)
    self.assertEqual(without_passthrough["task_files"], [])


if __name__ == "__main__":
  unittest.main()
