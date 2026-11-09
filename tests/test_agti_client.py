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
from typing import Any
import unittest
from unittest import mock

import requests
from src import agti_client


def _response(status_code: int, payload: Any = None) -> mock.MagicMock:
  response = mock.create_autospec(requests.Response, instance=True)
  response.status_code = status_code
  response.json.return_value = payload
  return response


def _yara_item(rule_id: str, name: str, **attrs: Any) -> dict[str, Any]:
  return {
      "id": rule_id,
      "attributes": {
          "name": name,
          "rule": f"rule {name} {{ condition: true }}",
          **attrs,
      },
  }


class TestAgtiClient(unittest.TestCase):

  def test_missing_api_key_raises_auth_error(self):
    with mock.patch.dict(os.environ, {}, clear=True):
      with self.assertRaises(agti_client.AgtiAuthError):
        agti_client.AgtiClient()
      with self.assertRaises(agti_client.AgtiAuthError):
        agti_client.AgtiClient(api_key="   ")

  def test_api_key_from_env(self):
    with mock.patch.dict(
        os.environ, {"GTI_API_KEY": "env-test-key"}, clear=True
    ):
      client = agti_client.AgtiClient()
    self.assertEqual(client.session.headers["x-apikey"], "env-test-key")

  def test_api_key_explicit_override(self):
    with mock.patch.dict(
        os.environ, {"GTI_API_KEY": "env-test-key"}, clear=True
    ):
      client = agti_client.AgtiClient(api_key="explicit-key")
    self.assertEqual(client.session.headers["x-apikey"], "explicit-key")

  def test_timeout_resolution(self):
    with mock.patch.dict(
        os.environ, {"AGTI_TIMEOUT_SECONDS": "1800"}, clear=True
    ):
      self.assertEqual(agti_client._get_default_timeout(), 1800)
    with mock.patch.dict(
        os.environ, {"AGTI_TIMEOUT_SECONDS": "invalid"}, clear=True
    ):
      self.assertEqual(agti_client._get_default_timeout(), 1200)

  def test_context_manager_and_close(self):
    with mock.patch.object(
        requests.Session, "close", autospec=True, spec_set=True
    ) as mock_close:
      with agti_client.AgtiClient(api_key="test-key") as client:
        self.assertIsInstance(client, agti_client.AgtiClient)
      mock_close.assert_called_once()

  @mock.patch.object(requests.Session, "request", autospec=True, spec_set=True)
  def test_ask_agti(self, mock_request: mock.MagicMock):
    mock_request.return_value = _response(
        200,
        {
            "data": {
                "id": "sess-456",
                "attributes": {
                    "events": [{
                        "message_type": "AGENT_FINAL_RESPONSE",
                        "text": "UNC3886 is an espionage actor.",
                    }]
                },
            }
        },
    )

    client = agti_client.AgtiClient(api_key="test-key")
    result = client.ask_agti("Provide threat overview of UNC3886")

    mock_request.assert_called_once_with(
        client.session,
        "POST",
        "https://www.virustotal.com/api/v3/agentspace/sessions",
        timeout=(10.0, 1200.0),
        data={"message": "Provide threat overview of UNC3886"},
    )
    self.assertEqual(agti_client.extract_session_id(result), "sess-456")
    self.assertEqual(
        agti_client.extract_agent_response(result),
        "UNC3886 is an espionage actor.",
    )

  @mock.patch.object(requests.Session, "request", autospec=True, spec_set=True)
  def test_ask_agti_unauthorized(self, mock_request: mock.MagicMock):
    mock_request.return_value = _response(401)

    client = agti_client.AgtiClient(api_key="invalid-key")
    with self.assertRaises(agti_client.AgtiAuthError):
      client.ask_agti("test prompt")

  @mock.patch.object(requests.Session, "request", autospec=True, spec_set=True)
  def test_ask_agti_rate_limited(self, mock_request: mock.MagicMock):
    mock_request.return_value = _response(429)

    client = agti_client.AgtiClient(api_key="test-key")
    with self.assertRaisesRegex(agti_client.AgtiError, "Rate limit"):
      client.ask_agti("test prompt")

  @mock.patch.object(requests.Session, "request", autospec=True, spec_set=True)
  def test_ask_agti_transport_error(self, mock_request: mock.MagicMock):
    mock_request.side_effect = requests.exceptions.ConnectionError(
        "Connection refused"
    )

    client = agti_client.AgtiClient(api_key="test-key")
    with self.assertRaises(agti_client.AgtiError):
      client.ask_agti("test prompt")

  def test_extract_session_id_empty_or_none(self):
    self.assertEqual(agti_client.extract_session_id({}), "")
    self.assertEqual(agti_client.extract_session_id({"data": None}), "")

  def test_extract_agent_response_with_widgets(self):
    session_data = {
        "data": {
            "id": "sess-789",
            "attributes": {
                "events": [{
                    "message_type": "AGENT_FINAL_RESPONSE",
                    "agent_final_response": {
                        "widgets": [
                            {
                                "markdown_text_widget": {
                                    "text": (
                                        "Malware analysis verdict: Malicious"
                                    )
                                }
                            },
                            {
                                "code_block_widget": {
                                    "text": (
                                        "rule Trojan_Sample { condition: true }"
                                    )
                                }
                            },
                        ]
                    },
                }]
            },
        }
    }
    extracted = agti_client.extract_agent_response(session_data)
    self.assertIn("Malware analysis verdict: Malicious", extracted)
    self.assertIn("rule Trojan_Sample { condition: true }", extracted)

  def test_extract_agent_response_with_error_event(self):
    session_data = {
        "data": {
            "attributes": {
                "events": [{
                    "message_type": "ERROR",
                    "error": {"description": "Backend timeout occurred."},
                }]
            }
        }
    }
    extracted = agti_client.extract_agent_response(session_data)
    self.assertEqual(extracted, "AGTI Error: Backend timeout occurred.")

  def test_extract_agent_response_null_data(self):
    self.assertEqual(
        agti_client.extract_agent_response({"data": None}),
        "No final response found.",
    )

  def test_build_yara_hub_url(self):
    self.assertEqual(
        agti_client.build_yara_hub_url("xmrig"),
        "https://www.virustotal.com/gui/crowdsourced-yara-hub?filter=xmrig",
    )

  @mock.patch.object(requests.Session, "request", autospec=True, spec_set=True)
  def test_search_crowdsourced_yara_rules_fanout_and_deduplication(
      self, mock_request: mock.MagicMock
  ):
    mock_request.side_effect = [
        _response(
            200,
            {
                "data": [
                    _yara_item(
                        "015109f1d5|Linux_Cryptominer_Xmrig_79b42b21",
                        "Linux_Cryptominer_Xmrig_79b42b21",
                        author="Elastic Security",
                        matches=25,
                        enabled=False,
                        tags=None,
                    ),
                    _yara_item(
                        "01596a10c1|Multi_Cryptominer_Xmrig_f9516741",
                        "Multi_Cryptominer_Xmrig_f9516741",
                        enabled=True,
                    ),
                ],
            },
        ),
        _response(
            200,
            {
                "data": [
                    _yara_item(
                        "01596a10c1|Multi_Cryptominer_Xmrig_f9516741",
                        "Multi_Cryptominer_Xmrig_f9516741",
                    ),
                    _yara_item(
                        "02abcdef01|Generic_Coinminer_Stratum",
                        "Generic_Coinminer_Stratum",
                    ),
                ],
            },
        ),
    ]

    client = agti_client.AgtiClient(api_key="test-key")
    rules = client.search_crowdsourced_yara_rules(
        ["xmrig", "coinminer"], max_total_rules=100
    )

    self.assertEqual(mock_request.call_count, 2)
    self.assertEqual(
        mock_request.call_args_list[0].kwargs["params"],
        {"limit": 40, "filter": "xmrig"},
    )
    self.assertEqual(
        [r["id"] for r in rules],
        [
            "015109f1d5|Linux_Cryptominer_Xmrig_79b42b21",
            "01596a10c1|Multi_Cryptominer_Xmrig_f9516741",
            "02abcdef01|Generic_Coinminer_Stratum",
        ],
    )
    self.assertEqual(
        rules[0]["hub_url"],
        "https://www.virustotal.com/gui/crowdsourced-yara-hub?filter=xmrig",
    )
    self.assertFalse(rules[0]["enabled"])
    self.assertEqual(rules[0]["tags"], [])
    self.assertEqual(rules[2]["matched_keyword"], "coinminer")

  @mock.patch.object(requests.Session, "request", autospec=True, spec_set=True)
  def test_search_crowdsourced_yara_rules_respects_max_total_rules(
      self, mock_request: mock.MagicMock
  ):
    mock_request.return_value = _response(
        200,
        {
            "data": [
                _yara_item("id1|Rule_1", "Rule_1"),
                _yara_item("id2|R2", "R2"),
            ]
        },
    )

    client = agti_client.AgtiClient(api_key="test-key")
    rules = client.search_crowdsourced_yara_rules(
        ["cryptominer", "xmrig"], max_total_rules=1
    )

    self.assertEqual([r["id"] for r in rules], ["id1|Rule_1"])
    mock_request.assert_called_once()
    self.assertEqual(
        mock_request.call_args.kwargs["params"],
        {"limit": 1, "filter": "cryptominer"},
    )


if __name__ == "__main__":
  unittest.main()
