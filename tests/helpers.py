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
"""Shared helpers for the openrelik-worker-agti unit tests."""

import base64
import json
from typing import Any


def decode_result(encoded_result: str) -> dict[str, Any]:
  """Decodes a base64-encoded OpenRelik task result into a dictionary."""
  return json.loads(base64.b64decode(encoded_result).decode("utf-8"))


def find_output(result: dict[str, Any], extension: str) -> dict[str, Any]:
  """Returns the first output file in `result` with the given extension."""
  return next(f for f in result["output_files"] if f["extension"] == extension)


def agti_response(session_id: str, text: str) -> dict[str, Any]:
  """Builds a minimal AGTI sessions API response with a final agent answer."""
  return {
      "data": {
          "id": session_id,
          "attributes": {
              "events": [{"message_type": "AGENT_FINAL_RESPONSE", "text": text}]
          },
      }
  }
