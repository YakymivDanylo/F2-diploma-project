from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from blockchain_core import IssuerKeyPair, NodeKeyPair, public_key_to_pem


def pem_of(pair: IssuerKeyPair | NodeKeyPair) -> str:
  return public_key_to_pem(pair.public_key).decode("ascii")


@dataclass
class NodeEnv:
  root: Path
  env: dict[str, str]
  node_key: NodeKeyPair
  issuer_key: IssuerKeyPair
  validator_keys: dict[str, NodeKeyPair]  # node1..node4; node1 is node_key

  @property
  def validators_path(self) -> Path:
    return Path(self.env["VALIDATORS_PATH"])

  @property
  def issuers_path(self) -> Path:
    return Path(self.env["ISSUERS_PATH"])


def write_issuers(env: NodeEnv, entries: list[dict]) -> None:
  """Replace the IssuerRegistry file of `env` with `entries`."""
  import json

  env.issuers_path.write_text(json.dumps({"issuers": entries}), encoding="utf-8")


def issuer_entry(issuer_id: str, pair: IssuerKeyPair, **extra) -> dict:
  return {"issuer_id": issuer_id, "public_key": pem_of(pair), **extra}
