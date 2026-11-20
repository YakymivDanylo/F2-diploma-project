"""Shared wire patterns for node messages (one definition, used by every codec)."""

from __future__ import annotations

import re

HASH_PATTERN = r"^[0-9a-f]{64}$"
HASH_RE = re.compile(HASH_PATTERN)  # a document / block hash: 64 lowercase hex characters
NODE_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")  # node_id / issuer_id on the wire
SIGNATURE_RE = re.compile(r"^(?:[0-9a-f]{2}){1,512}$")  # canonical hex, whole bytes only
REQUEST_ID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
CID_RE = re.compile(r"^[A-Za-z0-9]{1,128}$")  # an optional IPFS CID on a record
