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

import dataclasses
import os
import tempfile
import unittest
from unittest import mock
from src import ioc_utils


class TestIocUtils(unittest.TestCase):

  def test_extracted_iocs_dataclass(self):
    iocs = ioc_utils.ExtractedIocs(
        md5=("444bcb3a3fcf8389296c49467f2e9700",),
        sha1=("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",),
        sha256=(
            "44d88612fea8a8f36de82e1278abb02f1469e38d748f3b25da47481f185d2634",
        ),
        ips=("198.51.100.24",),
    )
    self.assertEqual(iocs.total_hashes, 3)
    with self.assertRaises(dataclasses.FrozenInstanceError):
      iocs.md5 = ()  # pytype: disable=cannot-assign

  def test_extract_iocs_empty(self):
    result = ioc_utils.extract_iocs("")
    self.assertEqual(result.md5, ())
    self.assertEqual(result.sha1, ())
    self.assertEqual(result.sha256, ())
    self.assertEqual(result.ips, ())
    self.assertEqual(result.total_hashes, 0)

  def test_extract_iocs_hashes_and_network(self):
    sample_text = """
        # Incident Triage Report
        Observed beaconing to 198.51.100.24 and domain bad-c2-server.com.
        Sample dropped payload:
        SHA256: 44d88612fea8a8f36de82e1278abb02f1469e38d748f3b25da47481f185d2634
        SHA1: 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12
        MD5: 444bcb3a3fcf8389296c49467f2e9700
        """
    result = ioc_utils.extract_iocs(sample_text)
    self.assertIn(
        "44d88612fea8a8f36de82e1278abb02f1469e38d748f3b25da47481f185d2634",
        result.sha256,
    )
    self.assertIn("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12", result.sha1)
    self.assertIn("444bcb3a3fcf8389296c49467f2e9700", result.md5)
    self.assertIn("198.51.100.24", result.ips)
    self.assertEqual(result.total_hashes, 3)

  def test_extract_iocs_ignores_path_directory_hashes(self):
    sample_path = (
        "/mnt/4ff907d1cb554361aa75d3c09719fc91/var/log/cron.log\t"
        "9f84ecefc895b8e987174868998daf2958f4988b7da22a78f8f5361c68fcfb92"
    )
    result = ioc_utils.extract_iocs(sample_path)
    self.assertNotIn("4ff907d1cb554361aa75d3c09719fc91", result.md5)
    self.assertEqual(result.md5, ())
    self.assertIn(
        "9f84ecefc895b8e987174868998daf2958f4988b7da22a78f8f5361c68fcfb92",
        result.sha256,
    )

  def test_extract_iocs_deduplication(self):
    sha256_hash = (
        "44d88612fea8a8f36de82e1278abb02f1469e38d748f3b25da47481f185d2634"
    )
    text = f"{sha256_hash.upper()}\n{sha256_hash.lower()}"
    result = ioc_utils.extract_iocs(text)
    self.assertEqual(result.sha256, (sha256_hash.lower(),))

  def test_is_disk_or_binary_file(self):
    self.assertTrue(
        ioc_utils.is_disk_or_binary_file({"data_type": "disk:image:raw"})
    )
    self.assertTrue(
        ioc_utils.is_disk_or_binary_file(
            {"data_type": "application/octet-stream"}
        )
    )
    self.assertFalse(ioc_utils.is_disk_or_binary_file({"extension": "iso"}))
    self.assertFalse(
        ioc_utils.is_disk_or_binary_file({
            "data_type": "text/markdown",
            "extension": "md",
            "path": "/path/to/notes.md",
        })
    )

  def test_is_disk_or_binary_file_allows_truncated_multibyte_text(self):
    with tempfile.TemporaryDirectory() as tmp_dir:
      tmp_path = os.path.join(tmp_dir, "notes.txt")
      # "é" is 2 bytes in UTF-8; 4095 ASCII bytes push its second byte past the
      # 4096-byte sniff window.
      with open(tmp_path, "w", encoding="utf-8") as f:
        f.write("a" * 4095 + "é" + "tail")
      self.assertFalse(ioc_utils.is_disk_or_binary_file({"path": tmp_path}))

  def test_is_disk_or_binary_file_content_inspection(self):
    with tempfile.TemporaryDirectory() as tmp_dir:
      tmp_path = os.path.join(tmp_dir, "artifact.raw")
      with open(tmp_path, "wb") as f:
        f.write(b"\xff\xfe\xfd\x80invalid_utf8_binary")
      with mock.patch.object(
          ioc_utils._logger, "debug", autospec=True
      ) as mock_debug:
        self.assertTrue(
            ioc_utils.is_disk_or_binary_file(
                {"path": tmp_path, "data_type": "text/plain"}
            )
        )
        mock_debug.assert_called()

      fifo_path = os.path.join(tmp_dir, "test.fifo")
      os.mkfifo(fifo_path)
      self.assertTrue(
          ioc_utils.is_disk_or_binary_file(
              {"path": fifo_path, "data_type": "text/plain"}
          )
      )

  def test_is_disk_or_binary_file_oserror_emits_debug_log(self):
    with mock.patch.object(
        os, "stat", side_effect=OSError("Permission denied")
    ):
      with mock.patch.object(
          ioc_utils._logger, "debug", autospec=True
      ) as mock_debug:
        self.assertFalse(
            ioc_utils.is_disk_or_binary_file({"path": "/unreadable/path"})
        )
        mock_debug.assert_called()

  def test_parse_agti_keywords(self):
    response_text = """
    ### Threat Context
    Coin mining activity on Linux hosts commonly involves XMRig and Kinsing.

    ```json
    {"keywords": ["xmrig", "kinsing", "skidmap", "sysrv"]}
    ```
    """
    keywords = ioc_utils.parse_agti_keywords(response_text)
    self.assertIn("xmrig", keywords)
    self.assertIn("kinsing", keywords)
    self.assertIn("skidmap", keywords)
    self.assertIn("sysrv", keywords)

  def test_parse_agti_keywords_invalid_json_emits_debug_log(self):
    response_text = """
    ```json
    {"keywords": invalid_json}
    ```
    """
    with mock.patch.object(
        ioc_utils._logger, "debug", autospec=True
    ) as mock_debug:
      keywords = ioc_utils.parse_agti_keywords(response_text)
      self.assertEqual(keywords, [])
      mock_debug.assert_called()

  def test_normalize_keywords(self):
    keywords = ioc_utils.normalize_keywords([
        "custom_miner, kinsing",
        "xmrig",
        "XMRig",
        "a/b; c2 not-a!word",
    ])
    self.assertEqual(keywords, ["custom_miner", "kinsing", "xmrig"])


if __name__ == "__main__":
  unittest.main()
