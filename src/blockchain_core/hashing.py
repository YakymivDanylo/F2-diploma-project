"""SHA-256 wrappers - the only place hashlib is called"""
from __future__ import annotations

import hashlib
import re
from typing import Any

from .canonical import canonicalize

HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
"""A 64-character lowercase-hex SHA-256 digest - the only accepted hash encoding."""


def sha256_hex(data: bytes) -> str:
  return hashlib.sha256(data).hexdigest()

def sha256_of_canonical(obj: Any) -> str:
  return sha256_hex(canonicalize(obj))
