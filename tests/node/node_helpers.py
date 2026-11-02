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

  @property
  def validators_path(self) -> Path:
    return Path(self.env["VALIDATORS_PATH"])

  @property
  def issuers_path(self) -> Path:
    return Path(self.env["ISSUERS_PATH"])
