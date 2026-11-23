from __future__ import annotations

from collections.abc import Iterator
from dataclasses import replace
from typing import Any

import pytest
from chain_factory import pbft_chain, save_chain
from fastapi.testclient import TestClient
from node_helpers import NodeEnv, issuer_entry, write_issuers

from blockchain_core import DocumentRecord, ProofStep, sha256_hex, verify_proof
from node.config import load_config
from node.context import NodeContext
from node.main import create_app


def _serve(node_env: NodeEnv, blocks, **env: str) -> Iterator[tuple[TestClient, NodeContext]]:
  save_chain(node_env, blocks)
  app = create_app(load_config({**node_env.env, "INIT_CHAIN": "0", **env}))
  with TestClient(app) as client:
    yield client, app.state.context


def H(seed: int) -> str:
  return sha256_hex(f"document-{seed}".encode())


def _verify(body: dict[str, Any]) -> bool:
  record = DocumentRecord(**body["record"])
  proof = [ProofStep(s["position"], s["sibling_hash"]) for s in body["merkle_proof"]]
  return verify_proof(record, proof, body["merkle_root"])


def test_found_returns_data_and_a_verifying_proof(node_env: NodeEnv) -> None:  # CN-TC-13.1
  blocks = pbft_chain(node_env, 3)
  for client, _ in _serve(node_env, blocks):
    response = client.get(f"/documents/{H(2)}")
    assert response.status_code == 200
    body = response.json()
    assert body["issuer_id"] == "issuer1"
    assert body["block_index"] == 2
    assert body["issued_at"] == blocks[2].document_records[0].issued_at
    assert body["merkle_root"] == blocks[2].merkle_root
    assert _verify(body)


def test_unknown_hash_is_404_in_the_envelope(node_env: NodeEnv) -> None:  # CN-TC-13.2
  for client, _ in _serve(node_env, pbft_chain(node_env, 1)):
    response = client.get(f"/documents/{sha256_hex(b'never')}")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "not_found"


@pytest.mark.parametrize("bad", ["A" * 64, "ab" * 31, "g" * 64, "ab" * 33])
def test_malformed_hash_rejected_before_search(node_env: NodeEnv, bad: str) -> None:  # 13.3
  for client, context in _serve(node_env, pbft_chain(node_env, 1)):
    searched: list[str] = []
    original = context.documents.block_indexes

    def spy(document_hash: str, searched=searched, original=original) -> list[int]:
      searched.append(document_hash)
      return original(document_hash)

    context.documents.block_indexes = spy  # type: ignore[method-assign]
    response = client.get(f"/documents/{bad}")
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"
    assert searched == []


def test_lookup_works_on_an_invalid_chain(node_env: NodeEnv) -> None:  # CN-TC-13.4
  blocks = pbft_chain(node_env, 3)
  blocks[2] = replace(blocks[2], timestamp=blocks[2].timestamp + 1)  # breaks its hash
  for client, _ in _serve(node_env, blocks):
    assert client.get("/node/info").json()["chain_valid"] is False
    assert client.get(f"/documents/{H(2)}").status_code == 200  # raw stored data
    assert client.get(f"/documents/{H(1)}").status_code == 200


def test_hash_in_two_blocks_is_an_integrity_error(node_env: NodeEnv) -> None:  # CN-TC-13.5
  blocks = pbft_chain(node_env, 3)
  blocks[3] = replace(blocks[3], document_records=blocks[1].document_records)
  for client, _ in _serve(node_env, blocks):
    response = client.get(f"/documents/{H(1)}")
    assert response.status_code == 500  # never "the earliest match"
    error = response.json()["error"]
    assert error["code"] == "chain_integrity_error"
    assert error["details"]["block_indexes"] == [1, 3]


def test_tampered_record_content_fails_the_proof(node_env: NodeEnv) -> None:  # CN-TC-13.6
  blocks = pbft_chain(node_env, 2)
  original = blocks[2].document_records[0]
  forged = replace(original, metadata={"seed": 999})
  blocks[2] = replace(blocks[2], document_records=(forged,))
  for client, _ in _serve(node_env, blocks):
    response = client.get(f"/documents/{H(2)}")
    assert response.status_code == 200  # still "found" with the stored data
    assert _verify(response.json()) is False  # but it does not verify against merkle_root


def test_issuer_name_from_registry_and_fallback(node_env: NodeEnv) -> None:  # CN-TC-MI.7 / MI.8
  write_issuers(node_env, [issuer_entry("issuer1", node_env.issuer_key, name="Institution A")])
  for client, context in _serve(node_env, pbft_chain(node_env, 1)):
    assert client.get(f"/documents/{H(1)}").json()["issuer_name"] == "Institution A"
    assert context.issuers.name_of("ghost") == "ghost"  # an unknown issuer shows its id
  write_issuers(node_env, [issuer_entry("issuer1", node_env.issuer_key)])
  for client, _ in _serve(node_env, pbft_chain(node_env, 1)):
    assert client.get(f"/documents/{H(1)}").json()["issuer_name"] == "issuer1"


def test_name_is_outside_the_signed_data(node_env: NodeEnv) -> None:  # CN-TC-MI.9
  blocks = pbft_chain(node_env, 1)
  proofs = []
  for name in ("Name One", "Name Two"):
    write_issuers(node_env, [issuer_entry("issuer1", node_env.issuer_key, name=name)])
    for client, _ in _serve(node_env, blocks):
      body = client.get(f"/documents/{H(1)}").json()
      assert client.get("/node/info").json()["chain_valid"] is True
      assert _verify(body)
      proofs.append((body["record"], body["merkle_proof"], body["merkle_root"]))
  assert proofs[0] == proofs[1]  # renaming changes no signature, hash or proof


def test_node_info_reports_the_institution(node_env: NodeEnv) -> None:  # CN-TC-MI.12
  write_issuers(node_env, [issuer_entry("issuer1", node_env.issuer_key, name="Institution A")])
  for client, _ in _serve(node_env, pbft_chain(node_env, 1)):
    body = client.get("/node/info").json()
    assert len(body) == 15
    assert (body["issuer_id"], body["issuer_name"]) == ("issuer1", "Institution A")
