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
"""Utilities for extracting and classifying forensic indicators."""

import codecs
from collections.abc import Iterable, Mapping
import dataclasses
import json
import logging
import os
import re
import stat
from typing import Any

_logger = logging.getLogger(__name__)

# Indicator Regular Expressions
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)
_KEYWORD_RE = re.compile(r"[a-z0-9_\-]+")

_MAX_TEXT_SCAN_BYTES = 10 * 1024 * 1024
_CONTENT_SNIFF_BYTES = 4096

_JSON_CODE_BLOCK_RE = re.compile(
    r"[ \t]*```(?:json)?\s*\n\s*(\{.*?\}|\[.*?\])\s*```",
    re.IGNORECASE | re.DOTALL,
)
_RAW_JSON_KEYWORDS_RE = re.compile(
    r'(\{[^{}]*"keywords"\s*:\s*\[[^\]]*\][^{}]*\})',
    re.DOTALL,
)


@dataclasses.dataclass(frozen=True, slots=True)
class ExtractedIocs:
  """Immutable container for extracted indicators of compromise (IOCs).

  Attributes:
    md5: Tuple of deduplicated lowercase MD5 hashes.
    sha1: Tuple of deduplicated lowercase SHA-1 hashes.
    sha256: Tuple of deduplicated lowercase SHA-256 hashes.
    ips: Tuple of deduplicated IPv4 addresses.
  """

  md5: tuple[str, ...] = ()
  sha1: tuple[str, ...] = ()
  sha256: tuple[str, ...] = ()
  ips: tuple[str, ...] = ()

  @property
  def total_hashes(self) -> int:
    """Returns the total count of unique MD5, SHA-1, and SHA-256 hashes."""
    return len(self.md5) + len(self.sha1) + len(self.sha256)


def _is_text_data_type(data_type: str) -> bool:
  """Checks whether a MIME or OpenRelik data_type string represents text.

  Args:
    data_type: Lowercase data_type or MIME type string.

  Returns:
    True if the data type represents plain text or structured text (such as
    JSON, XML, YAML, CSV, or Markdown); False otherwise.
  """
  if data_type.startswith("text/"):
    return True
  return any(
      marker in data_type
      for marker in ("json", "xml", "yaml", "csv", "markdown")
  )


def is_disk_or_binary_file(input_file: Mapping[str, Any]) -> bool:
  """Determines whether an input file is a disk image or binary artifact.

  Inspects OpenRelik `data_type` metadata, then the file itself (regular file
  status, size limit, null bytes, and UTF-8 decodability).

  Args:
    input_file: OpenRelik input file metadata dictionary containing keys such as
      'data_type' and 'path'.

  Returns:
    True if the file has a non-text data type, is not a regular file, exceeds
    the maximum text scan size, or contains binary content; False otherwise
    (including when the file cannot be inspected).
  """
  data_type = str(input_file.get("data_type") or "").strip().lower()
  if data_type and not _is_text_data_type(data_type):
    return True

  file_path = str(input_file.get("path") or "").strip()
  if not file_path:
    return False

  try:
    st = os.stat(file_path)
    if not stat.S_ISREG(st.st_mode) or st.st_size > _MAX_TEXT_SCAN_BYTES:
      return True
    with open(file_path, "rb") as f:
      chunk = f.read(_CONTENT_SNIFF_BYTES)
  except OSError as e:
    _logger.debug("OSError inspecting candidate file %s: %r", file_path, e)
    return False

  # NUL bytes (0x00) indicate binary content (and are valid UTF-8, so the
  # UTF-8 decoder below would not reject them on its own).
  if b"\x00" in chunk:
    return True
  try:
    # Incremental decoding tolerates a multi-byte character cut off at the end
    # of the sniffed chunk.
    codecs.getincrementaldecoder("utf-8")().decode(chunk, final=False)
  except UnicodeDecodeError as e:
    _logger.debug("Non-UTF-8 content in candidate file %s: %r", file_path, e)
    return True
  return False


def _extract_hashes(pattern: re.Pattern[str], text: str) -> tuple[str, ...]:
  """Extracts candidate hashes while ignoring directory path segments.

  Args:
    pattern: Compiled regular expression matching a specific hex hash length.
    text: Input text to scan for hash strings.

  Returns:
    A deduplicated tuple of lowercase hash strings in discovery order.
  """
  matches = []
  for m in pattern.finditer(text):
    prev_char = text[m.start() - 1] if m.start() > 0 else ""
    next_char = text[m.end()] if m.end() < len(text) else ""
    if prev_char in "/\\" and next_char in "/\\":
      continue
    matches.append(m.group(0).lower())
  return tuple(dict.fromkeys(matches))


def extract_iocs(text: str) -> ExtractedIocs:
  """Extracts deduplicated indicators from text in discovery order.

  The hash patterns are anchored on word boundaries, so a shorter hash can never
  match inside a longer hex string.

  Args:
    text: Raw text or markdown content from which to extract indicators.

  Returns:
    An ExtractedIocs instance containing deduplicated hashes and IPv4 addresses.
  """
  return ExtractedIocs(
      md5=_extract_hashes(_MD5_RE, text),
      sha1=_extract_hashes(_SHA1_RE, text),
      sha256=_extract_hashes(_SHA256_RE, text),
      ips=tuple(dict.fromkeys(_IPV4_RE.findall(text))),
  )


def normalize_keywords(items: Iterable[str]) -> list[str]:
  """Splits raw keyword strings and returns deduplicated YARA Hub filters.

  Each item may be a single keyword or a comma/semicolon/space/slash-delimited
  phrase. Tokens shorter than 3 characters or containing characters other than
  letters, digits, `_`, and `-` are dropped.

  Args:
    items: Iterable of raw keyword strings or delimited phrases.

  Returns:
    A deduplicated list of lowercase keyword tokens in discovery order.
  """
  normalized: list[str] = []
  for item in items:
    for part in re.split(r"[,;\s/]+", item.lower()):
      cleaned = part.strip("\"'`.,;:()[]{}")
      if len(cleaned) >= 3 and _KEYWORD_RE.fullmatch(cleaned):
        normalized.append(cleaned)
  return list(dict.fromkeys(normalized))


def parse_agti_keywords(agent_response: str) -> list[str]:
  """Extracts YARA search keywords from an AGTI response payload.

  Looks for a JSON object `{"keywords": [...]}` or JSON list `[...]` in the
  response text.

  Args:
    agent_response: Raw text response returned by AGTI.

  Returns:
    A deduplicated list of normalized search keywords.
  """
  candidates: list[str] = []
  blocks = _JSON_CODE_BLOCK_RE.findall(agent_response) or (
      _RAW_JSON_KEYWORDS_RE.findall(agent_response)
  )
  for block in blocks:
    try:
      parsed = json.loads(block)
    except ValueError as e:
      _logger.debug("Failed to parse JSON keyword candidate %r: %r", block, e)
      continue
    if isinstance(parsed, dict) and isinstance(parsed.get("keywords"), list):
      candidates.extend(str(item) for item in parsed["keywords"])
    elif isinstance(parsed, list):
      candidates.extend(str(item) for item in parsed)

  return normalize_keywords(candidates)
