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
"""Client for interacting with Agentic Google Threat Intelligence (AGTI)."""

from collections.abc import Mapping, Sequence
import logging
import os
import types
from typing import Any, Self
import urllib.parse

import requests

_SESSIONS_URL = "https://www.virustotal.com/api/v3/agentspace/sessions"
_YARA_RULES_URL = "https://www.virustotal.com/api/v3/yara_rules"
_YARA_HUB_GUI_URL = "https://www.virustotal.com/gui/crowdsourced-yara-hub"
_DEFAULT_TIMEOUT_SECONDS = 1200
_CONNECT_TIMEOUT_SECONDS = 10.0
# Maximum page size accepted by /api/v3/yara_rules.
_MAX_VT_PAGE_LIMIT = 40

_logger = logging.getLogger(__name__)


def _get_default_timeout() -> int:
  """Resolves the default request timeout from the environment.

  Returns:
    The timeout in seconds from AGTI_TIMEOUT_SECONDS, or
    _DEFAULT_TIMEOUT_SECONDS (1200) if unset or invalid.
  """
  raw = os.getenv("AGTI_TIMEOUT_SECONDS")
  if raw is not None:
    try:
      return int(raw)
    except ValueError as e:
      _logger.debug("Failed to parse timeout value %r: %r", raw, e)
  return _DEFAULT_TIMEOUT_SECONDS


def build_yara_hub_url(keyword: str) -> str:
  """Builds the VirusTotal Crowdsourced YARA Hub GUI link for a filter.

  Args:
    keyword: Search keyword or filter term to URL-encode.

  Returns:
    The formatted Crowdsourced YARA Hub GUI URL string.
  """
  encoded = urllib.parse.quote_plus(keyword.strip())
  return f"{_YARA_HUB_GUI_URL}?filter={encoded}"


def extract_session_id(session_data: Mapping[str, Any]) -> str:
  """Extracts the session ID from AGTI response data.

  Args:
    session_data: Parsed JSON dictionary returned by the AGTI API.

  Returns:
    The session ID string if present, or an empty string otherwise.
  """
  data = session_data.get("data")
  if isinstance(data, dict):
    return str(data.get("id") or "")
  return ""


def _extract_widget_texts(widgets: Any) -> list[str]:
  """Extracts non-empty text blocks from a list of AGTI response widgets.

  Args:
    widgets: Candidate widget sequence from an `agent_final_response` payload.

  Returns:
    A list of stripped non-empty text strings extracted from the widgets.
  """
  if not isinstance(widgets, list):
    return []
  pieces: list[str] = []
  for widget in widgets:
    if not isinstance(widget, dict):
      continue
    # Text lives in a nested markdown or code widget, or on the widget itself.
    source = (
        widget.get("markdown_text_widget")
        or widget.get("code_block_widget")
        or widget
    )
    if not isinstance(source, dict):
      continue
    text = str(source.get("text") or "").strip()
    if text:
      pieces.append(text)
  return pieces


def extract_agent_response(session_data: Mapping[str, Any]) -> str:
  """Parses the session response payload and retrieves the final agent text.

  Supports both standard `text` attributes and widget-based payloads
  (e.g., markdown_text_widget, code_block_widget).

  Args:
    session_data: Parsed JSON dictionary returned by the AGTI sessions API.

  Returns:
    The extracted markdown/text response from the agent, an error description
    if an ERROR event occurred, or a fallback message if no response is found.
  """
  data = session_data.get("data")
  attrs = data.get("attributes") if isinstance(data, dict) else {}
  events = attrs.get("events") if isinstance(attrs, dict) else []
  if not isinstance(events, list):
    events = []

  for event in reversed(events):
    if not isinstance(event, dict):
      continue

    msg_type = event.get("message_type")
    if msg_type == "AGENT_FINAL_RESPONSE":
      text = event.get("text")
      if isinstance(text, str) and text.strip():
        return text.strip()

      agent_resp = event.get("agent_final_response")
      widgets = (
          agent_resp.get("widgets") if isinstance(agent_resp, dict) else []
      )
      widget_pieces = _extract_widget_texts(widgets)
      if widget_pieces:
        return "\n\n".join(widget_pieces)

    if msg_type == "ERROR":
      err_dict = event.get("error")
      err_desc = (
          (err_dict.get("description") if isinstance(err_dict, dict) else None)
          or event.get("text")
          or "Unknown AGTI error"
      )
      return f"AGTI Error: {err_desc}"

  return "No final response found."


class AgtiError(Exception):
  """Raised when an AGTI or VirusTotal request fails."""


class AgtiAuthError(AgtiError):
  """Raised when authentication fails (missing or invalid API key)."""


class AgtiClient:
  """Client for querying Agentic Google Threat Intelligence (AGTI).

  Attributes:
    session: Underlying requests.Session instance with configured auth headers.
  """

  def __init__(self, api_key: str | None = None):
    """Initializes the AGTI client.

    Args:
      api_key: Optional GTI API key. If None or empty, falls back to the
        GTI_API_KEY environment variable.

    Raises:
      AgtiAuthError: If no API key is provided or found in the environment.
    """
    resolved_key = (api_key or os.getenv("GTI_API_KEY") or "").strip()
    if not resolved_key:
      raise AgtiAuthError(
          "GTI API key is required. Please set the GTI_API_KEY environment "
          "variable or provide it in the task configuration."
      )

    self._timeout = (_CONNECT_TIMEOUT_SECONDS, float(_get_default_timeout()))
    self.session = requests.Session()
    self.session.headers.update({
        "accept": "application/json",
        "x-apikey": resolved_key,
    })

  def close(self) -> None:
    """Closes the underlying HTTP requests session."""
    self.session.close()

  def __enter__(self) -> Self:
    """Enters the runtime context and returns the client instance."""
    return self

  def __exit__(
      self,
      exc_type: type[BaseException] | None,
      exc_val: BaseException | None,
      exc_tb: types.TracebackType | None,
  ) -> None:
    """Exits the runtime context and closes the underlying HTTP session."""
    del exc_type, exc_val, exc_tb
    self.close()

  def _request(self, method: str, url: str, **kwargs: Any) -> dict[str, Any]:
    """Sends an HTTP request and returns the parsed JSON response.

    Args:
      method: HTTP method (e.g., `"GET"` or `"POST"`).
      url: Target URL.
      **kwargs: Additional arguments for `requests.Session.request` (e.g.,
        `data` or `params`).

    Returns:
      The parsed JSON dictionary from the response.

    Raises:
      AgtiAuthError: If HTTP 401 or 403 is returned.
      AgtiError: If the request fails, is rate limited (HTTP 429), returns an
        error status, or returns invalid JSON.
    """
    try:
      response = self.session.request(
          method, url, timeout=self._timeout, **kwargs
      )
    except requests.exceptions.RequestException as e:
      raise AgtiError(f"{method} {url} failed: {e}") from e

    if response.status_code in (401, 403):
      raise AgtiAuthError(
          f"Authentication error ({response.status_code}): Invalid or"
          " unauthorized GTI API key."
      )
    if response.status_code == 429:
      raise AgtiError(
          "Rate limit exceeded (HTTP 429) for GTI API. Please try again later."
      )

    try:
      response.raise_for_status()
      return response.json()
    except (requests.exceptions.RequestException, ValueError) as e:
      raise AgtiError(f"{method} {url} failed: {e}") from e

  def ask_agti(self, prompt: str) -> dict[str, Any]:
    """Sends a prompt to a new AGTI session and returns the parsed response.

    Args:
      prompt: The inquiry or forensic text to submit to AGTI.

    Returns:
      The parsed JSON response dictionary from AGTI.

    Raises:
      AgtiAuthError: If the API key is unauthorized or forbidden (401/403).
      AgtiError: If the request fails or the server returns an error.
    """
    return self._request("POST", _SESSIONS_URL, data={"message": prompt})

  def search_crowdsourced_yara_rules(
      self,
      keywords: Sequence[str],
      max_total_rules: int = 100,
  ) -> list[dict[str, Any]]:
    """Queries VirusTotal Crowdsourced YARA rules for each keyword.

    Fetches one page (up to 40 rules) per keyword and deduplicates rules across
    keywords.

    Args:
      keywords: Sequence of search filter keywords (e.g., ['xmrig',
        'coinminer']).
      max_total_rules: Maximum total deduplicated rules to return across all
        keywords.

    Returns:
      A list of deduplicated YARA rule metadata and rule content dictionaries.

    Raises:
      AgtiAuthError: If the API key is unauthorized or forbidden (401/403).
      AgtiError: If the request fails or the server returns an error.
    """
    deduped_rules: dict[str, dict[str, Any]] = {}

    for raw_kw in keywords:
      keyword = raw_kw.strip()
      remaining = max_total_rules - len(deduped_rules)
      if remaining <= 0:
        break
      if not keyword:
        continue

      payload = self._request(
          "GET",
          _YARA_RULES_URL,
          params={
              "limit": min(_MAX_VT_PAGE_LIMIT, remaining),
              "filter": keyword,
          },
      )
      items = payload.get("data")
      if not isinstance(items, list):
        continue

      hub_url = build_yara_hub_url(keyword)
      for item in items:
        if len(deduped_rules) >= max_total_rules:
          break
        if not isinstance(item, dict):
          continue
        attrs = item.get("attributes")
        if not isinstance(attrs, dict):
          continue
        rule_text = (attrs.get("rule") or "").strip()
        if not rule_text:
          continue
        rule_name = str(attrs.get("name") or "")
        rule_id = str(item.get("id") or rule_name or rule_text[:64])
        if rule_id in deduped_rules:
          continue
        deduped_rules[rule_id] = {
            "id": rule_id,
            "name": rule_name,
            "author": attrs.get("author") or "Unknown",
            "matches": int(attrs.get("matches") or 0),
            "enabled": bool(attrs.get("enabled", False)),
            "tags": list(attrs.get("tags") or []),
            "rule": rule_text,
            "matched_keyword": keyword,
            "hub_url": hub_url,
        }

    return list(deduped_rules.values())
