# Implementation Plan — Decentralized Document Verification System

**Project:** Дипломна робота — «Децентралізована система верифікації документів на основі власної реалізації блокчейн-технології»
**Source documents:** [PRD v1.9 (Epics 1–5 architecture-approved at v1.3; Epic 6 under review)](PRD.md); Use Cases: [NFR & Operations (Epic 6)](use-cases/nfr_operations_use_cases.md), [Blockchain Core](use-cases/blockchain_core_use_cases.md), [Consensus & Network](use-cases/consensus_network_use_cases.md), [Web Interface](use-cases/web_interface_use_cases.md), [Attack Resistance Testing](use-cases/attack_resistance_testing_use_cases.md); QA Test Cases: [Blockchain Core](qa/blockchain_core_test_cases.md), [Consensus & Network](qa/consensus_network_test_cases.md), [Web Interface](qa/web_interface_test_cases.md), [Attack Resistance Testing](qa/attack_resistance_testing_test_cases.md), [NFR & Operations (Epic 6)](qa/nfr_operations_test_cases.md)
**Created:** 2026-09-07
**Audience:** the thesis author, writing all code by hand, solo, over a multi-month timeline.

---

## 0. How to read this plan

This is a **personal roadmap**, not an agent execution script. Slices are sized as **one solid work chunk each (roughly 1–2 weeks of part-time solo thesis work)**, not as agent-sized PRs. Each slice is still:

- independently testable and independently committable (1 slice = 1 commit or a small commit series),
- traced to the use cases and QA test cases it closes,
- ordered so that no slice depends on work from a later slice,
- flagged where an architecture or security review pass is worth doing before writing the code.

**Wave assignment is deliberately NOT performed.** Waves exist to let parallel agents own disjoint file sets; here a single human executes strictly sequentially. Section 5 lists the few places where slices *could* be reordered or interleaved if you want variety, but the default is: top to bottom.

### ID prefix convention (important — IDs collide across documents)

The four use-case files and the four QA files each restart numbering at `UC-1` / `TC-1.1`. This plan disambiguates with an epic prefix:

| Prefix | Use cases file | Test cases file |
|---|---|---|
| `E2-UC-…` / `BC-TC-…` | `use-cases/blockchain_core_use_cases.md` | `qa/blockchain_core_test_cases.md` |
| `E3-UC-…` / `CN-TC-…` | `use-cases/consensus_network_use_cases.md` | `qa/consensus_network_test_cases.md` |
| `E4-UC-…` / `WI-TC-…` | `use-cases/web_interface_use_cases.md` | `qa/web_interface_test_cases.md` |
| `E5-UC-…` / `AT-TC-…` | `use-cases/attack_resistance_testing_use_cases.md` | `qa/attack_resistance_testing_test_cases.md` |
| `E6-UC-…` / `NF-TC-…` | `use-cases/nfr_operations_use_cases.md` | `qa/nfr_operations_test_cases.md` (385 test cases) |

### TDD discipline per slice

For every code slice: write the listed test cases as **failing tests first**, then implement until green, then commit. `Verify:` gives the exact command; `Done when:` gives the boolean that must hold.

### Tooling assumptions (established in Slice 1 / Slice 20 / Slice 24)

- Python 3.11+, `pytest`, `ruff` (lint), `mypy` (types), `cryptography`, `fastapi`, `uvicorn`, `websockets`, `pydantic` v2.
- Frontend: React + TypeScript + Vite, `vitest` + React Testing Library.
- Analysis: `matplotlib` (primary) and/or `plotly`, `pandas`.
- Deployment: Docker + docker compose v2 (`docker compose`, not `docker-compose`).
- Commands are written to run from the repository root on Windows PowerShell **and** POSIX shells.

---

## 1. Prerequisites verified

| Prerequisite | Status |
|---|---|
| **PRD** — `docs/PRD.md` | Present (v1.9). Epics 1–5 architecture-approved at v1.3; Epic 6 (NFR/operations, §6) added in v1.5–v1.9 and under architecture re-review. Covers 6 epics: §1 research, §2 blockchain core, §3 consensus & network, §4 React UI, §5 attack resistance, §6 NFR & operations. |
| **Use cases** | Present, 5 files. `blockchain_core_use_cases.md` — 9 top-level UCs (UC-1…UC-9); `consensus_network_use_cases.md` — 17 UCs (UC-1…UC-17; UC-15…17 added for forwarding and `ChainState`); `web_interface_use_cases.md` — 9 UCs; `attack_resistance_testing_use_cases.md` — 8 UCs; `nfr_operations_use_cases.md` — 30 UCs (E6-UC-1…30). **73 top-level scenarios** plus alternative/error/edge sub-flows. |
| **QA test cases** | Present, 5 files. `blockchain_core_test_cases.md` — 108 TCs; `consensus_network_test_cases.md` — 189 TCs (includes CN-TC-15/16/17 = 74 new cases for forwarding, the `forward_record` channel and `ChainState`); `web_interface_test_cases.md` — 48 TCs; `attack_resistance_testing_test_cases.md` — 51 TCs; `nfr_operations_test_cases.md` (Epic 6) — 385 TCs (NF-TC, new file). **≈781 test cases total.** |
| **Architecture review** | **PASS.** PRD v1.2 passed the second review round with 5 sentence-level polish items; v1.3 applies them and is marked "FINAL, architecture-approved" with no further review round required. Security-priority list carried into this plan's `Pre-review` flags. **Epic 6:** architecture review rounds 1–3 returned FAIL; the resolutions are recorded in the Epic 6 header, and the current verdict is not recorded here (see Epic 6 Review notes, item 7). |
| **Existing source code** | **None.** The repository currently contains only `README.md`, `.gitignore`, and `docs/`. Every file path in this plan is therefore new; `[new]` is stated explicitly and no phantom existing paths are referenced. |

---

## 2. Target repository layout

Created incrementally by the slices below; listed here once so the plan's file paths are coherent.

```
pyproject.toml                    # Slice 1
src/blockchain_core/              # Epic 2 — pure library, NEVER imports src/node
  canonical.py  hashing.py  keys.py  signing.py
  document_record.py  merkle.py  block.py  genesis.py
  chain.py  validation.py
  storage/chain_store.py  storage/key_store.py
src/node/                         # Epic 3 — FastAPI node; may import blockchain_core
  main.py  config.py  errors.py  schemas.py
  registries.py  key_resolver.py  validity_cache.py  mempool.py  sync.py  metrics.py
  validation_gateway.py  chain_state.py  forwarding.py   # single FR-25 entry point (15), ChainState (16a), RecordForwarder (13/17b)
  api/{peers,chain,documents,node_info,metrics}.py
  peers/registry.py
  network/{connection_manager,ws_blocks,ws_pbft}.py
  consensus/{base,pow}.py
  consensus/pbft/{messages,engine,view_change,forward}.py
config/{validators.json,issuers.json,node.env.example}
docker/node.Dockerfile  docker/attacker.Dockerfile  docker-compose.yml
tests/core/…  tests/node/…  tests/vectors/canonical_vectors.json
web/                              # Epic 4 — React SPA
  src/api/client.ts  src/lib/{hash,merkle}.ts
  src/components/ConsensusModeBadge.tsx
  src/pages/{IssuePage,VerifyPage,ChainVisualizationPage}.tsx
  src/hooks/useBlockStream.ts
  src/__tests__/…
attacks/                          # Epic 5 — separate artifacts, own image
  attacker_node/{__init__,overrides}.py
  harness/{recorder,trust_anchor,resolver}.py
  scenarios/{sybil_pow,sybil_pbft,tamper_store,inject_block}.py
  analysis/{thresholds,charts}.py
results/attack_runs.csv  results/charts/
docs/research/epic1_blockchain_comparison.md
docs/results/findings.md
src/node/validation_gateway.py   # Epic 3, Slice 15 (single FR-25 validation entry point; Slice 30 wraps it for blocks_rejected_total)
src/node/chain_state.py    # Epic 3, Slice 16a (single owner + lock; Slice 33b adds the snapshot copy)
src/node/forwarding.py     # Epic 3, Slice 13 (RecordForwarder) + 17b (WS implementation); Slice 32a verifies it uses the tls.py client factory
src/node/consensus/pbft/forward.py   # Epic 3, Slice 17b (primary-side handler; Slice 31b adds the IssuerRegistry check)
# Epic 6 (Slices 30–35b)
src/node/{rate_limit,tls,snapshot_task}.py   # node-side (31a, 32a, 33b)
src/blockchain_core/storage/snapshot.py                  # pure, no node imports (33b)
benchmarks/{__init__,record,targets,fixtures,run_metadata,bench_validate_chain,bench_batching,bench_pow_time,bench_load,bench_pbft_finalization,bench_e2e_throughput,bench_scale,bench_fault_tolerance,bench_recovery_sync,gen_scale_compose,check_headline}.py
benchmarks/load/{k6_verify,k6_submit}.js   # 35a
results/nfr_measurements.csv  docs/results/nfr_report.md
docker/{prometheus.yml,grafana/,certs/}  docker-compose.{bench,scale}.yml  .env.example
.github/workflows/ci.yml  docs/security/owasp_api_top10_checklist.md
tests/{infra,benchmarks,docs}/  tests/test_layering.py
```

`benchmarks/` may import `src/*`; `src/*` never imports `benchmarks/` or `attacks/`.

**Hard architectural constraint (from PRD FR-6 / E3-UC-14):** `src/blockchain_core/` must never import from `src/node/`. Keys, `expected_difficulty`, and `ValidatorSet` are always **injected parameters**. This is checked explicitly in Slice 11.

---

## 3. Deliverables and slices

### D1 (Deliverable, not a TDD slice): Epic 1 — Research of blockchain systems

- **Epic:** 1. **Depends on:** nothing. **Est.:** 1–2 weeks of reading and writing.
- **Use cases:** none (documentation-only epic). **PRD:** §1, FR-1…FR-5.
- **Files:** `docs/research/epic1_blockchain_comparison.md` `[new]`
- **Changes:** Write a thesis-ready chapter section covering: (a) blockchain construction principles — block structure, hash linking, Merkle trees, consensus, node roles; (b) Blockcerts analysis — data model, hashing/anchoring approach, revocation, verification flow; (c) at least one further system (EBSI / OpenCerts) — optional but encouraged; (d) a comparison table across the 5 PRD FR-3 dimensions (data model, hashing scheme, consensus, revocation, verification flow); (e) at least 3 design decisions for Epics 2–3 explicitly traced to a research finding (SHA-256 choice, PoW-vs-PBFT comparison choice, Merkle batching); (f) rationale for building from scratch instead of reusing Hyperledger/Ethereum. Cite sources.
- **Verify:** `Get-Content docs/research/epic1_blockchain_comparison.md | Select-String -Pattern "Blockcerts","Merkle","Comparison"` (POSIX: `grep -E "Blockcerts|Merkle|Comparison" docs/research/epic1_blockchain_comparison.md`)
- **Done when:** the file exists, contains a comparison table with ≥2 systems × 5 dimensions, and contains a clearly labelled subsection listing ≥3 design decisions each with an explicit back-reference to a research finding. No code is produced by this item.
- **Pre-review:** none.

---

### Slice 1: Project scaffold + canonical serialization spec and test vectors

- **Epic:** 2. **Depends on:** D1 (design justification only — can start in parallel). **Est.:** ~1 week.
- **Use cases:** E2-UC-2-EC3 (canonical reproducibility); PRD FR-4 (cross-cutting).
- **Test cases:** BC-TC-CS.1, CS.2, CS.3, CS.4, CS.5; BC-TC-2.13.
- **Files:**
  - `pyproject.toml` `[new]`, `.gitignore` (extend existing), `README.md` (extend existing — add a "Repository layout / how to run tests" section)
  - `src/blockchain_core/__init__.py` `[new]`, `src/blockchain_core/canonical.py` `[new]`, `src/blockchain_core/hashing.py` `[new]`
  - `tests/core/test_canonical.py` `[new]`, `tests/vectors/canonical_vectors.json` `[new]`
- **Changes:** Set up the Python package, pytest/ruff/mypy config, and test layout. `canonical.py`: one and only one encoder — JSON, keys sorted lexicographically, no insignificant whitespace, UTF-8, timestamps as integer epoch-ms (reject ISO strings and floats), hash/signature/public-key fields lowercase hex (reject or normalize uppercase). `hashing.py`: `sha256_hex(bytes)` and `sha256_of_canonical(obj)` wrappers so no call site ever calls `hashlib` directly. Freeze a set of input-struct → expected-canonical-bytes → expected-SHA-256 vectors in `tests/vectors/canonical_vectors.json` and treat them as immutable from this point on.
- **Verify:** `python -m pytest tests/core/test_canonical.py -v && python -m mypy src/blockchain_core && python -m ruff check src tests`
- **Done when:** every vector in `canonical_vectors.json` round-trips to its exact expected byte string and hash (BC-TC-CS.1); canonicalizing the same struct twice yields byte-identical output (BC-TC-CS.2); a struct with a float/ISO timestamp is rejected (BC-TC-CS.4); a struct with uppercase hex is rejected or lowercased (BC-TC-CS.5); `grep -rn "hashlib" src/` returns matches only inside `hashing.py` (BC-TC-CS.3).
- **Pre-review:** **architect** — the canonical spec and the `blockchain_core`/`node` package boundary are frozen here and everything else hashes against them.

---

### Slice 2: Key pairs, signature primitives, and signed DocumentRecords

- **Epic:** 2. **Depends on:** Slice 1. **Est.:** ~1–1.5 weeks.
- **Use cases:** E2-UC-1 (+A, B, E1–E3, EC1–EC3), E2-UC-6 (+A, E1–E4, EC1), E2-UC-9 (+A, B, E1–E3, EC1, EC2).
- **Test cases:** BC-TC-1.1…1.10, BC-TC-6.1…6.7, BC-TC-9.1…9.8.
- **Files:** `src/blockchain_core/keys.py` `[new]`, `src/blockchain_core/signing.py` `[new]`, `src/blockchain_core/document_record.py` `[new]`, `src/blockchain_core/storage/__init__.py` `[new]`, `src/blockchain_core/storage/key_store.py` `[new]`, `tests/core/test_keys.py` `[new]`, `tests/core/test_document_record.py` `[new]`
- **Changes:** `keys.py`: `IssuerKeyPair` and `NodeKeyPair` as two distinct types (never interchangeable), generated via `cryptography`, ECDSA P-256 default, RSA ≥2048 optional, RSA <2048 rejected. `key_store.py`: each key pair persisted to its **own** file; refuse to overwrite an existing key file without an explicit force flag; set restrictive file permissions best-effort. `signing.py`: `sign(payload_obj, private_key)` and `verify(payload_obj, signature, public_key)` operating on Slice 1's canonical bytes, with algorithm auto-dispatch from the public-key type and a handled `invalid` (never an exception) for malformed signature blobs. `document_record.py`: build `{document_hash, issuer_id, issued_at, metadata, signature, ipfs_cid?}`, validate `^[0-9a-f]{64}$` on the hash, accept raw bytes as an alternative input, sign with `IssuerKeyPair` only. No duplicate checking at this layer (BC-TC-1.8).
- **Verify:** `python -m pytest tests/core/test_keys.py tests/core/test_document_record.py -v`
- **Done when:** a record signed with an `IssuerKeyPair` verifies against its public key and fails after any single-byte change to signature, `document_hash`, `issuer_id`, `issued_at`, or `metadata` (BC-TC-6.3/6.4); verification with a different issuer's key returns `invalid` (BC-TC-6.5); a malformed signature blob returns `invalid` without raising (BC-TC-6.6); RSA-1024 generation is rejected (BC-TC-9.5); generating over an existing key file without a force flag leaves the file untouched (BC-TC-9.4); `NodeKeyPair` and `IssuerKeyPair` never share key material or a store file (BC-TC-9.3).
- **Pre-review:** **security** — key-store handling and signature verification are on the architecture review's security-priority list. Confirm private keys are never logged and never leave their store files.

---

### Slice 3: Merkle tree with domain separation + inclusion proofs

- **Epic:** 2. **Depends on:** Slice 1 (canonical bytes), Slice 2 (record bytes). **Est.:** ~1 week.
- **Use cases:** E2-UC-2 steps 3–4 (+A, B), E2-UC-5 (+A, E1–E3, EC1–EC3).
- **Test cases:** BC-TC-2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.11; BC-TC-5.1…5.8.
- **Files:** `src/blockchain_core/merkle.py` `[new]`, `tests/core/test_merkle.py` `[new]`
- **Changes:** RFC 6962-style construction: leaf = `H(0x00 || canonical_bytes(record))`, internal = `H(0x01 || left || right)`. Odd node at a level is **promoted unchanged** — never duplicated. `build_root(records)`, `build_proof(records, document_hash)` returning a sibling path that records left/right position and promotion steps, and `verify_proof(leaf_or_record, proof, claimed_root)`. N=1 degenerates to the leaf hash itself with an empty proof path.
- **Verify:** `python -m pytest tests/core/test_merkle.py -v`
- **Done when:** leaf and internal hashes match the exact domain-separated formulas byte-for-byte (BC-TC-2.2/2.3); a batch crafted to collide under naive last-leaf duplication produces a **different** root under this construction (BC-TC-2.5); every one of N generated proofs verifies against the root, and altering any single sibling hash makes verification fail (BC-TC-5.1/5.4); a proof from block A fails against block B's root (BC-TC-5.5); a proof for a promoted unpaired node still verifies (BC-TC-5.8); a several-hundred-leaf build completes well under O(n²) (BC-TC-2.11).
- **Pre-review:** **security** — collision resistance / CVE-2012-2459 class is the reason this construction was specified; verify the domain separation is applied at every level and that no code path duplicates the last leaf.

---

### Slice 4: Block structure — hashed preimage vs. attestations, and batch build

- **Epic:** 2. **Depends on:** Slices 1–3. **Est.:** ~1 week.
- **Use cases:** E2-UC-2 (primary, steps 5–7; E1, E2, E3, EC1–EC3).
- **Test cases:** BC-TC-2.1, 2.8, 2.9, 2.10, 2.12, 2.13.
- **Files:** `src/blockchain_core/block.py` `[new]`, `tests/core/test_block.py` `[new]`
- **Changes:** Define `Block` with three explicitly separated field groups: **hashed preimage** (`index`, `timestamp`, `previous_hash`, `merkle_root`, `proposer_id`, `algorithm` ∈ {`"pow"`,`"pbft"`,`"genesis"`}, `sealed_consensus`), **batch content** (`document_records` — stored but never hashed into `block_hash`; covered only via `merkle_root`), and **attestations** attached after hashing (`block_hash`, `proposer_signature`, PBFT-only `commit_signatures[]`). `build_candidate_block(records, previous_hash, index, proposer_id, algorithm, sealed_consensus)`: verify every record's signature first, reject the whole batch on any failure (naming the offending index), reject an empty batch, reject a batch containing the same `document_hash` twice, then compute `merkle_root` and `block_hash` over the canonical preimage only. `attach_proposer_signature(block, node_key)` as a separate post-hash step.
- **Verify:** `python -m pytest tests/core/test_block.py -v`
- **Done when:** mutating `document_records` without rebuilding leaves `block_hash` unchanged while `merkle_root` recomputation diverges — proving records are outside the preimage (BC-TC-2.1); an empty batch is rejected (BC-TC-2.8); a batch with one bad-signature record is rejected and the failing index is reported (BC-TC-2.9); a batch with a repeated `document_hash` is rejected outright, never deduplicated (BC-TC-2.10/2.12); building the same preimage twice yields an identical `block_hash` (BC-TC-2.13).
- **Pre-review:** **architect** — the preimage/attestation split is the schema decision every later epic depends on; confirm `proposer_id` is inside the preimage for both algorithms and that `sealed_consensus.primary_id` does not exist.

---

### Slice 5: Deterministic genesis + hash-chain append

- **Epic:** 2. **Depends on:** Slice 4. **Est.:** ~1 week.
- **Use cases:** E2-UC-3 (+A, E1, E2, EC1, EC2).
- **Test cases:** BC-TC-3.1…3.8.
- **Files:** `src/blockchain_core/genesis.py` `[new]`, `src/blockchain_core/chain.py` `[new]`, `tests/core/test_chain_append.py` `[new]`, `tests/core/test_genesis.py` `[new]`
- **Changes:** `genesis.py`: fixed constants `GENESIS_TIMESTAMP_MS`, `GENESIS_MERKLE_ROOT` (computed once at implementation time from zero leaves per the Slice 3 spec, then **hardcoded** — never recomputed per node), `previous_hash = "0"*64`, `algorithm = "genesis"` (reserved literal), empty `sealed_consensus`, sentinel `proposer_id = null` and `proposer_signature = null`. `chain.py`: an in-memory `Chain` that is **never empty** — genesis exists from construction; `append(block)` performs an atomic check-and-append verifying `previous_hash == hash(tip)` and `index == tip.index + 1`, rejecting stale-previous-hash, index skips, and index duplicates.
- **Verify:** `python -m pytest tests/core/test_genesis.py tests/core/test_chain_append.py -v`
- **Done when:** two independently constructed `Chain` objects, sharing only the config constants and with no communication, produce an identical genesis `block_hash` (BC-TC-3.7 — closes C-1); genesis carries `algorithm = "genesis"` and both sentinels (BC-TC-3.2); appending with a stale `previous_hash`, a skipped index, or a duplicate index is rejected (BC-TC-3.3/3.4/3.5); two concurrent appends for the same next index leave exactly one winner (BC-TC-3.6); a node built with a modified genesis constant produces a visibly different `block_hash` and is documented as unsupported (BC-TC-3.8).
- **Pre-review:** none.

---

### Slice 6: Chain validation — core checklist with injected key resolver

- **Epic:** 2. **Depends on:** Slice 5. **Est.:** ~1.5–2 weeks (the single most important slice in Epic 2).
- **Use cases:** E2-UC-4 primary steps a–f, Genesis exemption, UC-4-A, E1–E6, EC1–EC5.
- **Test cases:** BC-TC-4.1, 4.3, 4.4, 4.5, 4.11, 4.12, 4.13, 4.14, 4.15, 4.16, 4.17, 4.18, 4.19, 4.20, 4.21, 4.24, 4.25, 4.26, 4.27, 4.27b, 4.28.
- **Files:** `src/blockchain_core/validation.py` `[new]`, `tests/core/test_validation_core.py` `[new]`
- **Changes:** `validate_chain(blocks, *, resolve_node_key, resolve_issuer_key, expected_difficulty=None, validator_set=None) -> {valid, first_invalid_index, failure_type}`. Both resolvers are **time-aware callables** `(identity, at_timestamp) -> public_key | NOT_FOUND`, supplied by the caller — this function performs **no registry lookup and no network call**. Per non-genesis block, in order: recompute `block_hash` over the canonical preimage (`"hash"`); check `previous_hash` against the prior block's recomputed hash (`"link"`); recompute `merkle_root` (`"merkle"`); verify `proposer_signature` against `resolve_node_key(proposer_id, block.timestamp)` (`"signature"`); verify **every** `DocumentRecord.signature` against `resolve_issuer_key(record.issuer_id, block.timestamp)` (`"signature"` — the explicit v1.3 checklist step); verify non-decreasing timestamp and contiguous non-duplicate indices (`"structural"`). Genesis (`algorithm == "genesis"`) is exempt from the proposer checks and compared only against the frozen constants. A resolver returning NOT_FOUND fails closed as `"signature"`, never raises, never defaults to valid. A genuinely zero-length input is rejected as an invalid input state. Report the **earliest** failing index. Algorithm-specific checks are stubs raising `NotImplementedError` only if reached — they are implemented in Slice 7 and must be wired before Epic 3 uses this function.
- **Verify:** `python -m pytest tests/core/test_validation_core.py -v`
- **Done when:** a correct chain returns `{valid: true, first_invalid_index: null, failure_type: null}` (BC-TC-4.1); each of the five tamper classes returns its exact `failure_type` — `"hash"` (BC-TC-4.13), `"link"` (BC-TC-4.14), `"merkle"` (BC-TC-4.15), `"signature"` (BC-TC-4.4/4.20), `"structural"` for duplicate index, index gap, and decreasing timestamp (BC-TC-4.16/4.17/4.21); **tampering the tip block's `timestamp` with a self-consistently recomputed `block_hash` is caught with `failure_type = "signature"`** (BC-TC-4.18 — the M-1 closure); the same tamper at a middle block is also caught (BC-TC-4.19); a genesis-only chain validates (BC-TC-4.25) and a zero-block input is rejected (BC-TC-4.24); a resolver returning two different keys for the same `node_id` at two timestamps straddling a rotation validates both pre- and post-rotation blocks (BC-TC-4.3); an unknown identity fails closed (BC-TC-4.28); the earliest failing index is reported for both an early-block and a tip-block corruption (BC-TC-4.27/4.27b); a several-hundred-block chain validates in better than O(n²) (BC-TC-4.26).
- **Pre-review:** **security** + **architect** — signature verification and the injected-resolver contract are both on the security-priority list, and this function's signature is the Epic 3 → Epic 2 dependency boundary.

---

### Slice 7: Chain validation — PoW difficulty/target and PBFT commit-quorum checks

- **Epic:** 2. **Depends on:** Slice 6. **Est.:** ~1 week.
- **Use cases:** E2-UC-4 steps g, h; UC-4-E7, UC-4-E8.
- **Test cases:** BC-TC-4.2, 4.6, 4.7, 4.8, 4.9, 4.10, 4.22, 4.23.
- **Files:** `src/blockchain_core/validation.py` (extend), `tests/core/test_validation_consensus.py` `[new]`
- **Changes:** For `algorithm == "pow"`: interpret `block_hash` as an unsigned integer and require it to **numerically** satisfy the target derived from `sealed_consensus.difficulty` (not a leading-zero-character count), **and** require `sealed_consensus.difficulty == expected_difficulty` (injected) — otherwise `failure_type = "difficulty"`. For `algorithm == "pbft"`: require `commit_signatures[]` to contain ≥ `2f+1` signatures from **distinct** `ValidatorSet` members, each resolved via `resolve_node_key(node_id, block.timestamp)` and each validly signing the canonical preimage; repeated signers count once — otherwise `failure_type = "quorum"`. Both checks skip `algorithm == "genesis"` by definition. Document that this is the single checklist reused by proposal-time, sync-time, and cache-refresh callers.
- **Verify:** `python -m pytest tests/core/test_validation_consensus.py -v`
- **Done when:** a block whose hash has the right leading-zero *format* but fails the numeric target is rejected (BC-TC-4.6); a block that satisfies its own self-declared low difficulty but whose difficulty ≠ injected `expected_difficulty` is rejected with `"difficulty"` (BC-TC-4.7); a block failing its own declared target is rejected with `"difficulty"` (BC-TC-4.22); a PBFT block with <2f+1 distinct signers is rejected with `"quorum"` (BC-TC-4.8); padding with a repeated signer does not reach quorum (BC-TC-4.9); a valid PBFT chain validates (BC-TC-4.2).
- **Pre-review:** **security** — PBFT quorum counting and PoW difficulty enforcement are both explicitly on the security-priority list; an error here silently invalidates the whole Epic 5 comparison.

---

### Slice 8: Persistence — chain store, key stores, restart durability

- **Epic:** 2. **Depends on:** Slices 5–7. **Est.:** ~1 week.
- **Use cases:** E2-UC-8 (+A, E1–E5, EC1–EC3).
- **Test cases:** BC-TC-8.1…8.10.
- **Files:** `src/blockchain_core/storage/chain_store.py` `[new]`, `src/blockchain_core/storage/key_store.py` (extend), `tests/core/test_persistence.py` `[new]`
- **Changes:** Three independent logical stores: chain, `IssuerKeyPair`, `NodeKeyPair`. Chain store as JSON first with the interface shaped so a SQLite backend can be dropped in behind the same contract. On load: deserialize, then run Slice 6/7 validation before the node resumes. Fresh start with no chain file → initialize with the deterministic genesis block. Corrupt/truncated chain file → fail startup with a specific error, never proceed partially. Missing issuer key file → fail fast with an "issuer key material unavailable" error; missing node key file → fail fast with a **distinctly worded** "node key material unavailable" error; never silently regenerate either. Loaded-but-invalid chain → surface the validation result and refuse to extend the chain. Document the single-writer/file-locking requirement.
- **Verify:** `python -m pytest tests/core/test_persistence.py -v`
- **Done when:** save → reload produces a chain that validates and keys that sign/verify identically to before (BC-TC-8.1); the same test passes against both storage backends behind one contract (BC-TC-8.2); a fresh node with no chain file starts at genesis (BC-TC-8.3); a truncated file fails startup with a specific error (BC-TC-8.4); missing issuer vs. missing node key produce two distinct error messages (BC-TC-8.5/8.7); a chain tampered while the process was down is reported invalid at startup with its failing index and `failure_type` (BC-TC-8.6); reloading a PoW chain under a changed `expected_difficulty` fails with `"difficulty"` and this is documented as by-design (BC-TC-8.10); key files are not world-readable (BC-TC-8.9).
- **Pre-review:** **security** — persistence and key-store handling are on the security-priority list.

---

### Slice 9: Tamper-detection composite suite (Epic 2 acceptance gate)

- **Epic:** 2. **Depends on:** Slices 6–8. **Est.:** ~1 week. Mostly tests; this slice is the evidence base for the thesis's core tamper-evidence claim.
- **Use cases:** E2-UC-7 (+A, B, E1/EC1, EC2).
- **Test cases:** BC-TC-7.1…7.10.
- **Files:** `tests/core/test_tamper_detection.py` `[new]`, `docs/research/epic1_blockchain_comparison.md` (extend — add a short "implemented guarantees vs. surveyed systems" paragraph once the guarantees are proven)
- **Changes:** End-to-end scenarios operating on a persisted chain file: mutate a record's metadata; mutate a block preimage field; mutate `previous_hash`; mutate a middle block **and** recompute its own `block_hash`; mutate the tip block and recompute its `block_hash`; mutate and re-sign with an attacker-owned key. Each scenario reloads from disk and asserts the layer that catches it. Add a short table in the test module docstring mapping scenario → detecting layer → `failure_type`, to be lifted into the thesis text.
- **Verify:** `python -m pytest tests/core/test_tamper_detection.py -v`
- **Done when:** the middle-block sophisticated tamper is caught via `"link"` (BC-TC-7.6); the **tip-block** sophisticated tamper is caught **exclusively** via `proposer_signature` with `"signature"` (BC-TC-7.7 — the central M-1 test); a record-field-only tamper is caught independently by the `IssuerKeyPair` signature (BC-TC-7.8); a tamper re-signed with the attacker's own key still fails against the known public key (BC-TC-7.9); the timestamp-only tip tamper with recomputed hash is caught with `"signature"` (BC-TC-7.10). **Epic 2 is done when this slice is green.**
- **Pre-review:** none (it consumes already-reviewed code) — but re-read the Epic 2 acceptance criteria list in PRD §2 and tick every box before moving on.

---

### Slice 10: Node skeleton — config, registries, error envelope, validation, CORS, mode selection

- **Epic:** 3. **Depends on:** Slice 9 (Epic 2 complete). **Est.:** ~1 week.
- **Use cases:** E3-UC-1-C, E3-UC-1-D, E3-UC-11 (+E1, E2, EC1), E3-UC-14-E2; cross-cutting FR-19 error envelope + Pydantic validation + CORS.
- **Test cases:** CN-TC-1.3, 1.5, 1.6, 11.1, 11.2, 11.3, 14.6, EV.1, EV.2, EV.3, EV.4.
- **Files:** `src/node/__init__.py` `[new]`, `src/node/main.py` `[new]`, `src/node/config.py` `[new]`, `src/node/errors.py` `[new]`, `src/node/schemas.py` `[new]`, `src/node/registries.py` `[new]`, `config/validators.json` `[new]`, `config/issuers.json` `[new]`, `config/node.env.example` `[new]`, `tests/node/test_config.py` `[new]`, `tests/node/test_error_envelope.py` `[new]`
- **Changes:** FastAPI app factory. `config.py`: `NODE_ID`, `CONSENSUS_MODE` (`pow`|`pbft`, fail-fast on an unrecognized value, one documented default-or-fail-fast policy for a missing value), `EXPECTED_DIFFICULTY`, key-store paths, seed peers, CORS origins (config-driven, not hardcoded), max page size, metadata byte cap. `registries.py`: load static `ValidatorSet` (`node_id`, `node_public_key`, nullable `retired_at`, network-wide `n`/`f` with `n ≥ 3f+1`) and network-wide `IssuerRegistry` (`issuer_id → public_key`); never mutated at runtime; never derived from peers; both logged at boot; missing/malformed config → fail fast. `errors.py`: one exception handler emitting `{"error": {"code", "message", "details"}}` for every error path. `schemas.py`: shared Pydantic types including the `^[0-9a-f]{64}$` hash constraint and the metadata size cap.
- **Verify:** `python -m pytest tests/node/test_config.py tests/node/test_error_envelope.py -v`
- **Done when:** boot logs contain the loaded `ValidatorSet` (`n`, `f`) and `IssuerRegistry` `issuer_id` (CN-TC-1.3/1.5); a malformed or missing registry file causes fail-fast startup (CN-TC-14.6); an invalid `CONSENSUS_MODE` fails startup with an explicit error rather than defaulting (CN-TC-11.2); every error response on every registered route matches the exact envelope shape (CN-TC-EV.1); a non-`^[0-9a-f]{64}$` hash and an over-cap metadata value are both rejected as validation errors (CN-TC-EV.2/EV.3); CORS allows the configured frontend origin and is changeable via config alone (CN-TC-EV.4).
- **Pre-review:** **architect** — registry shapes and config surface are consumed by every later Epic 3 slice.

---

### Slice 11: Time-aware key resolver, validity cache, and `GET /node/info`

- **Epic:** 3. **Depends on:** Slice 10. **Est.:** ~1 week.
- **Use cases:** E3-UC-14 (+A, E1, E2, EC1, EC2), E3-UC-12 (+A, E1, EC1–EC3).
- **Test cases:** CN-TC-14.1…14.8, CN-TC-12.1…12.8, CN-TC-1.4.
- **Files:** `src/node/key_resolver.py` `[new]`, `src/node/validity_cache.py` `[new]`, `src/node/api/__init__.py` `[new]`, `src/node/api/node_info.py` `[new]`, `tests/node/test_key_resolver.py` `[new]`, `tests/node/test_node_info.py` `[new]`
- **Changes:** `key_resolver.py`: build one combined resolver object from `ValidatorSet` (including `retired_at` entries) + `IssuerRegistry`, exposing `resolve_node_key(node_id, at_timestamp)` and `resolve_issuer_key(issuer_id, at_timestamp)`, each selecting the key active at that timestamp and returning an explicit NOT_FOUND (never `None`-as-valid, never an exception) for unknown identities. Rebuildable on config reload without retroactively invalidating in-flight validations. `validity_cache.py`: holds `{chain_valid, first_invalid_index, quorum_status, tip_index}`, initialized at boot and updated **incrementally on append/replace events only** — no periodic revalidation, no per-request full revalidation. `api/node_info.py`: `GET /node/info` returning `{node_id, algorithm, n, f, node_public_key, tip_index, chain_valid, first_invalid_index, quorum_status}` read from the cache.
- **Verify:** `python -m pytest tests/node/test_key_resolver.py tests/node/test_node_info.py -v`
- **Done when:** `resolve_node_key(node_id, t)` returns the **old** key for `t ≤ retired_at` and the **new** key for `t >` rotation, for the same `node_id` (CN-TC-14.7 — the central time-aware test); a retired entry is excluded from active `n`/`f` counting but stays resolvable (CN-TC-14.7); an unknown identity returns NOT_FOUND and the calling validation reports `"signature"` (CN-TC-14.5); `GET /node/info` returns all nine fields with correct values (CN-TC-12.1) and works on a genesis-only node with `chain_valid = true` (CN-TC-12.3); an invalid chain yields HTTP 200 with `chain_valid = false` plus `first_invalid_index` (CN-TC-12.4); measured `GET /node/info` latency on a several-hundred-block chain is within noise of the latency on a 2-block chain (CN-TC-12.7); a static check confirms `blockchain_core` contains no import of `src.node` and performs no registry lookup (CN-TC-14.3).
- **Pre-review:** **security** — the resolver is the trust anchor for every signature check in the system.

---

### Slice 12: Peer registry REST (`/peers`) and paginated `GET /chain`

- **Epic:** 3. **Depends on:** Slice 11. **Est.:** ~1 week.
- **Use cases:** E3-UC-1 (+A, E1–E3, EC1, EC2), E3-UC-2 (+E1), E3-UC-3-D, E3-UC-3-E4.
- **Test cases:** CN-TC-1.1, 1.2, 1.7…1.11, 2.1, 2.2, 3.6, 3.10, EV.5.
- **Files:** `src/node/peers/__init__.py` `[new]`, `src/node/peers/registry.py` `[new]`, `src/node/api/peers.py` `[new]`, `src/node/api/chain.py` `[new]`, `tests/node/test_peers.py` `[new]`, `tests/node/test_chain_api.py` `[new]`
- **Changes:** `PeerInfo` registry (`node_id`, `host`, `port`, `public_key` = the peer's `NodeKeyPair` public key, `last_seen`) — dynamic, gossip-populated, **structurally disconnected from `ValidatorSet`**. `POST /peers/register` merges/updates on re-registration rather than duplicating, rejects self-registration, rejects malformed payloads via the envelope, and returns the receiver's current peer list. `GET /peers` returns `PeerInfo` only (never `ValidatorSet`), empty list on a fresh node. Seed-peer registration at startup retries with backoff instead of crashing. `GET /chain?from=&to=` returns a bounded range with a server-enforced max page size and never an unbounded dump — including when called with no parameters.
- **Verify:** `python -m pytest tests/node/test_peers.py tests/node/test_chain_api.py -v`
- **Done when:** mutual registration leaves both nodes aware of each other and A merges B's list (CN-TC-1.1); re-registering the same `node_id` updates `last_seen`/`host`/`port` with no duplicate entry (CN-TC-1.8); self-registration is ignored (CN-TC-1.10); an unreachable seed peer triggers backoff retries, not a crash (CN-TC-1.7); flooding thousands of registrations neither crashes the node nor changes any quorum-related value (CN-TC-1.11 — asserted directly against `GET /node/info`'s `n`/`f`); `GET /chain` with no parameters on a chain longer than the max page size returns exactly the capped page (CN-TC-EV.5); an over-max requested range is truncated or rejected (CN-TC-3.10).
- **Pre-review:** **security** — peer registration is the Sybil attack surface Epic 5 targets; confirm registration can never touch `ValidatorSet` and that unbounded `PeerInfo` growth degrades only connectivity.

---

### Slice 13: `POST /documents` (server-side issuer signing, duplicate policy, mempool, `RecordForwarder` contract) and `GET /documents/{hash}`

- **Epic:** 3. **Depends on:** Slice 12. **Est.:** ~1.5 weeks (at the threshold — fallback: split the forwarder contract into "Slice 13b: `RecordForwarder` + HTTP mapping" carrying CN-TC-15.x and NF-TC-30.4/30.11/30.17; 17b would then depend on 13b).
- **Use cases:** E3-UC-4 (+A, E1–E6, EC1, EC2); E3-UC-13 (+A, E1, E2, EC1, EC2); E3-UC-15 (primary, A1–A4, E1–E6, EC1–EC4, FR-22 (x) side effects); moved Epic 6 flows covered via CN-TC-15.x: E6-UC-4-A9, E6-UC-4-E8, E6-UC-4-EC8 and the HTTP halves of E6-UC-4-A4/A5/E7/EC7; E6-UC-30-A3, E6-UC-30-E7, E6-UC-30-EC5 (`FORWARD_ACK_TIMEOUT_MS` boot validation is Epic 3-owned per Epic 6 FR-23).
- **Test cases:** CN-TC-4.1…4.13, CN-TC-13.1…13.6, CN-TC-15.1…15.27; NF-TC-30.4, 30.11, 30.17 (same assertions as CN-TC-15.15…15.17 — implemented once, tagged with both IDs).
- **Files:** `src/node/mempool.py` `[new]`, `src/node/forwarding.py` `[new]` (`RecordForwarder` protocol + stub, pending-request table keyed by `request_id`, injected `is_primary()` seam), `src/node/api/documents.py` `[new]`, `src/node/config.py` (extend — `FORWARD_ACK_TIMEOUT_MS`), `tests/node/test_documents_submit.py` `[new]`, `tests/node/test_documents_lookup.py` `[new]`, `tests/node/test_forward_mapping.py` `[new]`
- **Changes:** `POST /documents` accepts **only** `{hash, metadata}` — a body containing `signature` (or any pre-signed record shape) is a 400 validation error. Order of operations is fixed: validate shape/hash pattern/metadata cap → acquire a per-hash (or global) submission lock → reject `409 Conflict` if the hash is in **any finalized block OR the current pending batch/mempool** → assemble `{document_hash, issuer_id (from IssuerRegistry), issued_at (now, epoch-ms), metadata}` → sign server-side with the node's `IssuerKeyPair` → queue → release lock → return an accepted/queued acknowledgement. Under PBFT, a non-primary node signs with **its own** configured issuer identity and forwards the **already-signed** record to the primary as a `forward_record` message through a **`RecordForwarder` protocol** defined here in `src/node/forwarding.py` `[new]` (interface + stub implementation; the real WS channel, authentication and primary-side acceptance are built in Slice 17b); the node waits for the primary's synchronous reply (request id, timeout) and maps it to HTTP. The submission lock is per-hash, or is released **before** awaiting the primary's reply, so a slow forward never serialises all submissions. `FORWARD_ACK_TIMEOUT_MS` (default 2000, ≥1) is validated at boot here. Mapping — `accepted` → normal ack, `duplicate` → 409, `not_primary`/view change/timeout (`FORWARD_ACK_TIMEOUT_MS`, default 2000) → retryable 503 with `Retry-After`, `unregistered_issuer` → 403, `invalid_record` → 422, `not_validator`/`auth_failed` → 502 (all via the envelope). The proposer never re-signs or reassigns `issuer_id`. Until Slice 17b lands, the `RecordForwarder` is a stub and only the local-queue path runs for real. `GET /documents/{hash}` returns `{issuer_id, issued_at, block_index, merkle_proof}` on hit and HTTP 404 via the envelope on miss, with the path parameter validated before any chain search. The `is_primary()` seam returns a tri-state `PrimaryStatus` (`self` | `other(node_id)` | `none` — view change or no established primary) so the view-change row of the mapping (CN-TC-15.6: 503 + `Retry-After`, no local queuing) is testable against the stub before Slice 18 exists. The forwarder keeps one pending-request entry per in-flight `request_id`, removed on reply or timeout; replies with an unknown `request_id` are dropped.
- **Verify:** `python -m pytest tests/node/test_documents_submit.py tests/node/test_documents_lookup.py tests/node/test_forward_mapping.py -v`
- **Done when:** a valid submission produces a server-signed record whose signature verifies against the configured issuer public key, with no client involvement (CN-TC-4.1); a body containing `signature` is rejected 400 (CN-TC-4.4); a hash already finalized returns 409 and assembles/signs nothing (CN-TC-4.10); a hash already **pending in the mempool** also returns 409 (CN-TC-4.11 — the v1.3 broadening); two concurrent submissions of the same hash yield exactly one acceptance and one 409 (CN-TC-4.13); a malformed hash or over-cap metadata is rejected before the duplicate check (CN-TC-4.8/4.9); lookup returns 200 with a Merkle proof that verifies against the block's stored root (CN-TC-13.1) and a never-issued hash returns 404 via the envelope (CN-TC-13.2); a parameterised test against a stub `RecordForwarder` maps each of the 7 reply codes to its HTTP status (accepted → ack, duplicate → 409, not_primary → 503 + `Retry-After`, unregistered_issuer → 403, invalid_record → 422, not_validator/auth_failed → 502) and maps a timeout (`FORWARD_ACK_TIMEOUT_MS`) and a connection failure to 503 with `Retry-After`; a slow stub reply does not block an unrelated submission (lock released before the await); `FORWARD_ACK_TIMEOUT_MS < 1` fails startup; a reply code outside the closed enum is treated as a defect and mapped to 502; a non-primary never places a forwarded record in its own mempool. One parameterised test asserts every row of CN-TC-15.2…15.12 and fails when an outcome without a table row is added; a reply with an unknown `request_id` is dropped and the pending request is unaffected (CN-TC-15.25); a hash already finalized, or pending in the node's own mempool (seeded while it was primary), returns 409 without calling the forwarder (CN-TC-15.26); for every forwarder outcome including `accepted` the non-primary's mempool size is unchanged and the pending-request table is empty after reply/timeout (CN-TC-15.27); `FORWARD_ACK_TIMEOUT_MS` ∈ {`0`, `-1`, `abc`, empty} exits non-zero naming the key under both `CONSENSUS_MODE=pow` and `pbft`, while `1` and the default are accepted and the effective value is logged (CN-TC-15.15…15.17, NF-TC-30.4/30.11/30.17).
- **Pre-review:** **security** — server-side issuer signing, the unsigned-submission contract, the duplicate-hash lock and the lock-release-before-await rule.

---

### Slice 14: PoW consensus engine + consensus metrics endpoint

- **Epic:** 3. **Depends on:** Slice 13. **Est.:** ~1 week.
- **Use cases:** E3-UC-5 (+A, E1, E2, EC1–EC3), E3-UC-9 (+A, E1, EC1, EC2).
- **Test cases:** CN-TC-5.1…5.7, CN-TC-9.1…9.5.
- **Files:** `src/node/consensus/__init__.py` `[new]`, `src/node/consensus/base.py` `[new]`, `src/node/consensus/pow.py` `[new]`, `src/node/metrics.py` `[new]`, `src/node/api/metrics.py` `[new]`, `tests/node/test_pow.py` `[new]`, `tests/node/test_metrics.py` `[new]`
- **Changes:** `base.py`: a small engine interface (`on_submission`, `on_inbound_block`, `start`, `stop`) both algorithms implement, so `CONSENSUS_MODE` selects one implementation. `pow.py`: an **interruptible** async mining loop varying `sealed_consensus.nonce` inside the preimage until the hash meets the configured target; on success attach `proposer_signature`, append locally, update the validity cache, and hand the block to the broadcast layer (wired in Slice 15). Abandon the loop and re-queue unincluded records when a valid competing block for the same height arrives. `metrics.py` + `GET /metrics/consensus`: `ConsensusMetric` rows (`block_index`, `algorithm`, `proposed_at`, `finalized_at`, `attempts_or_rounds`, PoW `hash_rate`), excluding in-flight rounds, empty list on a fresh node, no overflow/truncation on large attempt counts.
- **Verify:** `python -m pytest tests/node/test_pow.py tests/node/test_metrics.py -v`
- **Done when:** a mined block's hash satisfies the configured target, carries a valid `proposer_signature`, and passes Slice 7 validation (CN-TC-5.1); raising the configured difficulty with no code change measurably increases time-to-finalize as reported by `GET /metrics/consensus` (CN-TC-5.2); a competing valid block arriving mid-mining aborts the loop within one poll interval and re-queues the pending batch (CN-TC-5.3/5.7); the metrics endpoint returns per-block finalization time plus a per-node `hash_rate` sample (CN-TC-9.1) and an empty list on a fresh node (CN-TC-9.3).
- **Pre-review:** none.

---

### Slice 15: WebSocket layer — `PeerConnectionManager`, block broadcast, inbound authentication

- **Epic:** 3. **Depends on:** Slice 14. **Est.:** ~1.5 weeks.
- **Use cases:** E3-UC-7 (+A, E1, E2, EC1, EC2), E3-UC-8 (+E1–E4, EC1, EC2), E3-UC-6-F.
- **Test cases:** CN-TC-7.1…7.6, CN-TC-8.1…8.7, CN-TC-6.6.
- **Files:** `src/node/network/__init__.py` `[new]`, `src/node/network/connection_manager.py` `[new]`, `src/node/network/ws_blocks.py` `[new]`, `src/node/validation_gateway.py` `[new]`, `tests/node/test_connection_manager.py` `[new]`, `tests/node/test_block_broadcast.py` `[new]`
- **Changes:** `PeerConnectionManager`: each node is simultaneously a WS **server** (accepting inbound) and a WS **client** (maintaining outbound connections to every `PeerInfo` peer **and** every `ValidatorSet` member); fan-out uses whichever direction is established; reconnect with capped exponential backoff; per-peer health (`up`/`reconnecting`/`down`) exposed for metrics and `GET /node/info`. `ws_blocks.py`: `WS /ws/blocks` push on finalization; on receipt, run the **single** Slice 6/7 validation checklist with the Slice 11 resolver before doing anything else. That single FR-25 validation entry point is the module `src/node/validation_gateway.py` `[new]`; the sync path (Slice 16b), the PoW broadcast path and the PBFT path all call it, and Slice 30 wraps it once for `blocks_rejected_total`. Rejection rules: no/empty `proposer_signature` → reject; signature from a key not in `PeerInfo`/`ValidatorSet` → reject; valid signature but broken link/merkle → reject with the right `failure_type`; conflicting block at an already-finalized index → reject, first-finalized wins, and log an equivocation event if the sender is a validator; stale replay → reject. A rejected block is never appended and **never re-broadcast**. Duplicate delivery of an already-appended block is a no-op. A block that does not extend the local tip falls back to chain sync (implemented next slice — until then, log and skip).
- **Verify:** `python -m pytest tests/node/test_connection_manager.py tests/node/test_block_broadcast.py -v`
- **Done when:** a block broadcast by one node is fast-appended by peers connected in **either** direction (CN-TC-7.1/6.6); a downed connection reconnects with capped backoff and per-peer health is visible via `GET /node/info` (CN-TC-7.2); an unsigned block, a block signed by an unknown key, and a block with a broken link are each rejected **and not re-broadcast** (CN-TC-8.2/8.3/8.4, CN-TC-7.3); a duplicate arrival is a no-op (CN-TC-7.5); simultaneous high fan-out produces no state corruption in the append path (CN-TC-7.6). A static check finds exactly one validation entry point (`validation_gateway.py`) and no caller bypasses it.
- **Pre-review:** **security** — inbound block/proposal authentication is on the security-priority list; confirm there is exactly one validation entry point and no "trusted peer" shortcut.

---

### Slice 16a: `ChainState` — single chain owner, one asyncio lock, retrofit of append paths

- **Epic:** 3. **Depends on:** Slice 15. **Est.:** ~1 week.
- **Use cases:** E3-UC-17 (primary, postconditions, A1, A2, A3, E1, E2, EC1, EC2, EC3, EC4). E3-UC-17 side effects (round abandonment on replace) are Slice 16b (PoW) and Slice 17 (PBFT).
- **Test cases:** CN-TC-17.1, 17.2, 17.4…17.14.
- **Files:** `src/node/chain_state.py` `[new]`, `src/node/consensus/pow.py` (extend — append through `ChainState`), `src/node/network/ws_blocks.py` (extend), `src/node/validity_cache.py` (extend — updated from `ChainState` append/replace events), `src/node/api/chain.py` (extend — consistent read view), `src/node/api/documents.py` (extend — duplicate check and lookup read through `ChainState`), `tests/node/test_chain_state_concurrency.py` `[new]`, `tests/node/test_chain_state_static.py` `[new]`
- **Changes:** `ChainState` is the only code that mutates the in-memory chain. It owns exactly one `asyncio.Lock` that serialises `append(block)` and `replace(new_chain, validate)`, both implemented as context-managed critical sections (the lock is never leaked on exceptions). `replace` takes the incoming chain plus a validation callable (the single FR-25 checklist); on validation failure the local chain is untouched. Both operations persist through the Slice 8 store and update the validity cache inside the critical section. Readers get a consistent snapshot view (tuple of frozen `Block` objects), never a half-installed chain. Blocks handed out are frozen (`dataclasses.replace` for derived blocks), which is the contract the Slice 33b snapshot copy builds on. Slices 14/15 append paths are retrofitted to call `ChainState`. A static test scans `src/node/**` for chain-list mutation (append/insert/extend/item assignment/deletion/rebinding) outside `chain_state.py` and counts chain locks (positive-control fixture must fail). No snapshot operation exists in this slice.
- **Verify:** `python -m pytest tests/node/test_chain_state_concurrency.py tests/node/test_chain_state_static.py -v`
- **Done when:** an append issued while `replace` holds the lock runs afterwards against the new tip (appended if it extends it, else rejected) (CN-TC-17.1); across both orderings and ≥100 seeded interleavings the final chain passes the Epic 2 checklist, no append is lost or interleaved, and the persisted chain and validity cache equal the in-memory chain (CN-TC-17.2, 17.4, 17.10); two same-height blocks → exactly one appended (CN-TC-17.5); a `GET /node/info` cache refresh during a replace never observes a mixed chain (CN-TC-17.6); a replace that fails validation leaves the chain byte-identical and a queued append proceeds (CN-TC-17.7); an exception injected in `append` or `replace` releases the lock and a subsequent append completes within 1 s (CN-TC-17.8, 17.9); the static check fails on the positive-control module and passes on the real tree, and finds exactly one chain lock (CN-TC-17.11, 17.12); mutating a returned block raises or leaves the live chain unchanged (CN-TC-17.13); no snapshot API or second lock exists (CN-TC-17.14).
- **Pre-review:** **architect** — `ChainState` API (append/replace/read view), frozen-block contract, lock scope including persistence and cache update.

---

### Slice 16b: Chain synchronization and fork resolution

- **Epic:** 3. **Depends on:** Slice 16a. **Est.:** ~1.5 weeks.
- **Use cases:** E3-UC-3 (+A, B, D, E1–E4, EC1–EC3); E3-UC-17 side effects (PoW mining abandoned/restarted on replace).
- **Test cases:** CN-TC-3.1…3.5, 3.7, 3.8, 3.9, 3.11, 3.12, 3.13, 3.14; CN-TC-12.8; CN-TC-17.3 (PoW half — the PBFT half is Slice 17).
- **Files:** `src/node/sync.py` `[new]`, `src/node/validity_cache.py` (extend — `quorum_status` value `byzantine_event_detected`; Slice 18 adds `view_change_in_progress` and `crash_fault_quorum_loss`), `src/node/consensus/pow.py` (extend — abandon/restart on `ChainState` replace event), `tests/node/test_chain_sync.py` `[new]`, `tests/node/test_fork_resolution.py` `[new]`
- **Changes:** Periodic/on-demand `GET /chain` from peers (paginated for long histories). Classify the incoming chain: **strict non-diverging extension** → validate incrementally from the local tip; **diverges before the local tip** → run **full validation from genesis** over the entire incoming chain, never incremental. Both modes use the identical Slice 6/7 checklist with the Slice 11 resolver — including PBFT `commit_signatures` quorum verification. Adoption rule: PoW longest-valid-chain; PBFT highest latest-finalized-height. Tie-break: **PoW only**, lowest tip `block_hash` as an unsigned integer — order-independent, never "first observed". **PBFT same-height differing finalized blocks must never be tie-broken**: log a safety-violation event and set `quorum_status = byzantine_event_detected` (no tie-break). On adoption, call `ChainState.replace(new_chain, validate)` (Slice 16a), which persists and updates the validity cache inside the critical section. An in-progress PoW mining round is cleanly abandoned and restarted against the newly adopted chain (the PBFT-round half of this rule is Slice 17).
- **Verify:** `python -m pytest tests/node/test_chain_sync.py tests/node/test_fork_resolution.py tests/node/test_chain_state_concurrency.py -v`
- **Done when:** a strict extension takes the incremental path and a divergent chain provably takes the **full-from-genesis** path (assert via an instrumented call counter — CN-TC-3.1/3.2, closes M-14); the checklist executed during sync is byte-for-byte the same function used at proposal time and cache refresh (CN-TC-3.3, CN-TC-12.8); two equal-length PoW chains resolve to the lowest tip hash **regardless of arrival order** (CN-TC-3.11); two differently-finalized PBFT blocks at the same height are **not** silently resolved and instead surface as a Byzantine event in `quorum_status` (CN-TC-3.12); an invalid peer chain is rejected wholesale with the local chain retained and the peer flagged (CN-TC-3.7); timeouts, truncated JSON, and long paginated catch-ups all fail or complete gracefully without hanging (CN-TC-3.8/3.9/3.14). A sync replace during PoW mining abandons the loop and restarts mining on the adopted tip, and the validity cache reflects the new chain (CN-TC-17.3, PoW half); adoption goes exclusively through `ChainState.replace` (the CN-TC-17.11 static check still passes).
- **Pre-review:** **security** — fork-adoption rule (unchanged rationale).

---

### Slice 17: PBFT three-phase protocol — pre-prepare / prepare / commit (17a)

- **Epic:** 3. **Depends on:** Slice 16b. **Est.:** ~2 weeks (largest single slice; flagged above 1.5 weeks and accepted — splitting the phases would leave an untestable half). The `forward_record` channel is **not** part of this slice — it is Slice 17b, placed after Slice 18 because its `not_primary` / view-change cases need view-change.
- **Use cases:** E3-UC-6 primary (+A, B, F), quorum-scope note, E3-UC-6-E3, EC1, EC3.
- **Test cases:** CN-TC-6.1, 6.2, 6.3, 6.4, 6.5, 6.9, 6.14; CN-TC-17.3 (PBFT half).
- **Files:** `src/node/consensus/pbft/__init__.py` `[new]`, `src/node/consensus/pbft/messages.py` `[new]`, `src/node/consensus/pbft/engine.py` `[new]`, `src/node/network/ws_pbft.py` `[new]`, `tests/node/test_pbft_rounds.py` `[new]`
- **Changes:** `messages.py`: `pre-prepare` / `prepare` / `commit` payloads keyed by `(view, seq, block_hash)`, each signed with the sender's `NodeKeyPair` and verified on receipt. `engine.py`: primary proposes a candidate block over `WS /ws/pbft` via `PeerConnectionManager`; replicas validate the candidate with the standard checklist before sending `prepare`; quorum is counted **exclusively over the static `ValidatorSet`**, never over `PeerInfo`; the primary's own `pre-prepare` counts as its implicit `prepare` vote (implemented and commented explicitly at the counting site); on 2f+1 matching commits the block is finalized, `commit_signatures[]` is attached as an attestation **after** hashing, the block is appended, the validity cache and metrics (round counts) are updated, and the block is broadcast. Message handling is idempotent under duplicate/out-of-order delivery; commits arriving without a preceding prepare-quorum are rejected on phase ordering. `commit_signatures[]` are attached to the block by constructing a new immutable `Block` (frozen blocks; `dataclasses.replace`), consistent with the Slice 16a `ChainState` decision.
- **Verify:** `python -m pytest tests/node/test_pbft_rounds.py -v`
- **Done when:** a full round on n=4/f=1 finalizes the identical block on every correct member, and the resulting block passes Slice 7's `commit_signatures` quorum check (CN-TC-6.1); registering many extra `PeerInfo` peers leaves the 2f+1 threshold and the round outcome unchanged (CN-TC-6.2 — the central C-4 test); the primary reaches quorum for its own proposal **without** sending itself a `prepare` (CN-TC-6.3); stopping exactly 1 of 4 members still finalizes and is reported as normal operation, not a fault (CN-TC-6.5); an out-of-sequence `commit` is rejected (CN-TC-6.9); duplicated/reordered messages do not double-count votes (CN-TC-6.14); a `ChainState.replace` during an in-progress PBFT round abandons the round and restarts it against the adopted chain (CN-TC-17.3, PBFT half); finalized blocks are appended only via `ChainState.append` and the CN-TC-17.11/17.12 static checks still pass.
- **Pre-review:** **security** + **architect** — PBFT quorum logic is the top item on the security-priority list; review the counting rule, the distinct-signer requirement, and the message-authentication path before implementing.

---

### Slice 18: PBFT view-change, equivocation detection, crash-vs-Byzantine reporting

- **Epic:** 3. **Depends on:** Slice 17. **Est.:** ~1.5 weeks.
- **Use cases:** E3-UC-6-D (simplified view-change), E3-UC-6-E1, E2, E4, E5; E3-UC-6-EC2; E3-UC-12-EC1; crash-vs-Byzantine semantics (E3-UC-6-E5 / E3-UC-6-E2).
- **Test cases:** CN-TC-6.7, 6.8, 6.10, 6.11, 6.12, 6.13; CN-TC-12.5; CN-TC-8.5.
- **Files:** `src/node/consensus/pbft/view_change.py` `[new]`, `src/node/consensus/pbft/engine.py` (extend), `src/node/validity_cache.py` (extend — `quorum_status` states), `tests/node/test_pbft_view_change.py` `[new]`, `tests/node/test_fault_classification.py` `[new]`
- **Changes:** Deterministic round-robin view-change `primary = view_number mod n` over the `ValidatorSet`, triggered by a configurable round timeout or by a primary proposing an invalid block. Explicitly **no** state-transfer, checkpoint, or watermark protocol — say so in a code comment at the implementation site and in the thesis text. Equivocation handling: count at most one vote per `node_id` per `(view, seq)`; a second, conflicting vote is discarded and logged as a **Byzantine/equivocation** event. `quorum_status` gains `view_change_in_progress` and `crash_fault_quorum_loss` (insufficient responsive replicas), alongside `healthy` and the `byzantine_event_detected` value introduced in Slice 16b (reused, not redefined) — the states are never conflated. A view-change storm must converge or persistently report the condition rather than looping silently.
- **Verify:** `python -m pytest tests/node/test_pbft_view_change.py tests/node/test_fault_classification.py -v`
- **Done when:** an invalid proposal from the primary yields no `prepare` votes and triggers a view change (CN-TC-6.7); a validator equivocating to different peers is deduplicated, cannot advance quorum, and is logged as a Byzantine event **distinct from** any crash report (CN-TC-6.8, CN-TC-8.5); stopping 2 of 4 members stalls finalization and reports **crash-fault** quorum loss with no wrong block ever finalized (CN-TC-6.11); a round timeout advances the view via `view_number mod n` (CN-TC-6.10/6.12); repeated primary failures converge or report persistently, never loop silently (CN-TC-6.13); `GET /node/info` during a view change reports the in-progress state rather than a binary healthy/lost (CN-TC-12.5).
- **Pre-review:** **security** — view-change and equivocation handling are both on the security-priority list, and Epic 5's PBFT scenarios measure exactly this code.

---

### Slice 17b: `forward_record` channel on `WS /ws/pbft` (non-primary → primary intake)

- **Epic:** 3. **Depends on:** Slices 13 (`RecordForwarder`, mapping), 16a (`ChainState` duplicate check), 17 (PBFT messages + `WS /ws/pbft`), 18 (view change for `not_primary`). **Est.:** ~1–1.5 weeks.
- **Use cases:** E3-UC-16 (primary + message contract, A1–A5, E1–E8, E9 pairs 1a/1b, 1b/2, 2/3, 3/5, 5/6, 6/7, EC1–EC5, FR-22 (x) side effects, PoW mode scope); moved Epic 6 flows covered via CN-TC-16.x: E6-UC-4-A4, A5, A6, A8, A10, E2, E3, E7, EC5, EC7 (channel halves).
- **Test cases:** CN-TC-16.1…16.23, CN-TC-16.25…16.33. CN-TC-16.15 is asserted here with the pre-Epic-6 expectation (`invalid_record`) and updated by Slice 31b; CN-TC-16.24 and the proposed CN-TC-16.34 are owned by Slice 31b.
- **Files:** `src/node/consensus/pbft/forward.py` `[new]`, `src/node/network/ws_pbft.py` (extend), `src/node/forwarding.py` (extend — real WS `RecordForwarder`), `src/node/mempool.py` (extend — atomic check-and-queue), `src/node/main.py` (extend — wires the real forwarder and engine-backed `is_primary()`), `tests/node/test_forward_record.py` `[new]`
- **Changes:** A non-primary sends the already-signed record to the primary over `WS /ws/pbft` with a `request_id` and awaits one synchronous reply within `FORWARD_ACK_TIMEOUT_MS`. The primary-side handler checks, **in this order**: sender authentication (`auth_failed`), sender in `ValidatorSet` (`not_validator`), current primary (`not_primary`, including view-change-in-flight), record shape (`invalid_record`), `IssuerRegistry` (`unregistered_issuer` — added by Slice 31b; until Slice 31b an unknown issuer yields `invalid_record` via resolver miss (CN-TC-16.15, pre-Epic-6 expectation)), signature (`invalid_record`), then duplicate against mempool and finalized blocks (`duplicate`), else queue (`accepted`). Late replies after a timeout are discarded by `request_id`. Reply enum is closed: `accepted | duplicate | not_primary | not_validator | unregistered_issuer | invalid_record | auth_failed`. Two non-primaries forwarding the same hash yield exactly one `accepted`. The duplicate check reads finalized blocks through `ChainState`; mempool check-and-queue is one atomic step shared with the primary's local `POST /documents` path. A PoW-mode node exposes no `forward_record` handler; such a message is rejected/ignored with no state change.
- **Verify:** `python -m pytest tests/node/test_forward_record.py tests/node/test_forward_mapping.py -v`
- **Done when:** a record submitted to non-primary N2 is accepted by the primary and finalized exactly once, with N2's `issuer_id`/`signature`, and exactly one `forward_record_reply` per `request_id` is sent before finalization (CN-TC-16.1, 16.2, 16.29); concurrent forwards of one hash from N2 and N3 (both orders) and a concurrent primary-local submit yield exactly one `accepted`, the rest `duplicate`, and one mempool entry (CN-TC-16.4, 16.8, 16.30); a forward during a view change gets `not_primary` → 503 + `Retry-After`, and the client retry after election is accepted with the hash in exactly one block (CN-TC-16.5, 16.6, 16.7, 16.12); missing/invalid sender signature → `auth_failed` (502) and a `PeerInfo`-only sender → `not_validator` (502) (CN-TC-16.9…16.11); malformed record → `invalid_record` (422) and bad record signature → `invalid_record` (CN-TC-16.13, 16.14); unknown issuer → `invalid_record` (CN-TC-16.15, pre-Epic-6); finalized or pending hash → `duplicate` (CN-TC-16.16, 16.17); late or never-issued `request_id` reply discarded (CN-TC-16.18); a corpus + fuzz run produces only the 7 enum codes (CN-TC-16.19); adjacent-pair tests 1a/1b, 1b/2, 2/3, 3/5, 5/6, 6/7 pass (CN-TC-16.20…16.23, 16.25, 16.26); after every non-`accepted` code a fresh valid submission of the same hash succeeds and the channel stays open (CN-TC-16.27, 16.28); `sender_id` never equals the receiver's `node_id` (CN-TC-16.31); N2's mempool never changes (CN-TC-16.32); a PoW-mode node ignores `forward_record` with no state change (CN-TC-16.33).
- **Pre-review:** **security** + **architect** — sender authentication and handler check order.

---

### Slice 19: Docker image and multi-node docker-compose network (Epic 3 acceptance gate)

- **Epic:** 3. **Depends on:** Slice 17b (and transitively 18). **Est.:** ~1 week.
- **Use cases:** E3-UC-10 (+A, E1, E2, EC1), E3-UC-11-EC1.
- **Test cases:** CN-TC-10.1…10.5, CN-TC-11.4, CN-TC-1.6.
- **Files:** `docker/node.Dockerfile` `[new]`, `docker-compose.yml` `[new]`, `config/validators.json` (extend — the 4-node demo set), `config/issuers.json` (extend — the single shared demo issuer), `tests/node/test_compose_smoke.py` `[new]`, `README.md` (extend — how to run the network)
- **Changes:** One honest-node image. Compose file defining ≥4 node services on a shared Docker network, each with a distinct host port, its own key-store volume, seed-peer wiring, and env-driven `CONSENSUS_MODE`/`EXPECTED_DIFFICULTY`. Warn loudly at boot when the configured node count violates `n ≥ 3f+1` for the intended `f`. Detect and reject fundamentally incompatible messages from a mismatched-mode peer instead of corrupting local state. A smoke test script that brings the network up, submits a document, and asserts convergence.
- **Verify:** `docker compose up -d --build; python -m pytest tests/node/test_compose_smoke.py -v; docker compose down -v`
- **Done when:** `docker compose up` starts ≥4 nodes, each logging its `ValidatorSet` (`n`, `f`) and shared `IssuerRegistry` `issuer_id`, each reachable on a distinct port, converging to full peer awareness (CN-TC-10.1, CN-TC-1.6); a document submitted to one node appears in a finalized block on **all** other nodes in **both** PoW and PBFT modes (Epic 3 acceptance criterion); one crash-looping container does not hang the rest (CN-TC-10.4); an `n < 3f+1` configuration warns at startup (CN-TC-10.5); a mixed pow/pbft cluster rejects incompatible messages without crashing (CN-TC-11.4). **Epic 3 is done when this slice is green** — re-check every PRD §3 acceptance box here.
- **Pre-review:** **architect** — container topology and volume/key placement affect Epic 5's attacker-image boundary.

---

### Slice 20: React app scaffold, API client, node selector, consensus-mode badge

- **Epic:** 4. **Depends on:** Slice 19. **Est.:** ~1 week.
- **Use cases:** E4-UC-9 (+E1, EC1, EC2); node-selection plumbing for E4-UC-8.
- **Test cases:** WI-TC-9.1…9.5.
- **Files:** `web/package.json` `[new]`, `web/vite.config.ts` `[new]`, `web/src/main.tsx` `[new]`, `web/src/App.tsx` `[new]`, `web/src/api/client.ts` `[new]`, `web/src/api/types.ts` `[new]`, `web/src/state/nodeSelection.ts` `[new]`, `web/src/components/ConsensusModeBadge.tsx` `[new]`, `web/src/__tests__/ConsensusModeBadge.test.tsx` `[new]`
- **Changes:** Vite + React + TypeScript app with routing for Issue / Verify / Chain pages. `client.ts`: typed wrappers for `POST /documents`, `GET /documents/{hash}`, `GET /chain`, `GET /node/info`, `GET /metrics/consensus`, plus a `WS /ws/blocks` subscriber; it must decode the `{"error": {...}}` envelope and expose `status` so callers can distinguish 400 / 404 / 409 / network failure. Node selection stored in app state (base URL per node, configurable list). `ConsensusModeBadge` sources `algorithm` from **`GET /node/info`**, never from `GET /metrics/consensus`.
- **Verify:** `npm --prefix web ci; npm --prefix web run test; npm --prefix web run build`
- **Done when:** the badge renders "PoW"/"PBFT" from `GET /node/info` (WI-TC-9.1); it shows an explicit "unknown" state when the endpoint is unreachable rather than a stale label (WI-TC-9.3); switching between nodes with different modes updates the badge independently with no cached carry-over (WI-TC-9.4); a freshly started genesis-only node still shows its configured algorithm immediately (WI-TC-9.5).
- **Pre-review:** **architect** — freeze the API client's error-discrimination contract (404 vs. 409 vs. network) here; every later UI slice depends on it.

---

### Slice 21: Issue page — client-side hashing, unsigned submission, 409 handling, confirmation tracking

- **Epic:** 4. **Depends on:** Slice 20. **Est.:** ~1.5 weeks.
- **Use cases:** E4-UC-1 (+A, B, E1–E4, EC1, EC2), E4-UC-2 (+E1, E2, EC1), E4-UC-3 (+A, E1, E2, EC1).
- **Test cases:** WI-TC-1.1…1.10, WI-TC-2.1…2.4, WI-TC-3.1…3.5.
- **Files:** `web/src/lib/hash.ts` `[new]`, `web/src/pages/IssuePage.tsx` `[new]`, `web/src/hooks/useBlockStream.ts` `[new]`, `web/src/__tests__/IssuePage.test.tsx` `[new]`, `web/src/__tests__/hash.test.ts` `[new]`
- **Changes:** `hash.ts`: SHA-256 over a file via the **Web Crypto API** with streaming/chunked reads so the UI thread never blocks; the raw file is never uploaded. Issue page: file-picker **and** drag-and-drop entry points sharing one downstream flow; a pasted-hash alternative with trim+lowercase normalization and `^[0-9a-f]{64}$` client validation; metadata fields (recipient identifier, document title). Submit an **unsigned** `{hash, metadata}` body — the browser must never construct a signature or hold key material. Error mapping: 409 → a distinct, explicit duplicate-submission message (never a silent no-op, never an auto-retry, never merged with the network-error state); other API rejections → surface the node's reported reason. `useBlockStream`: subscribe to `WS /ws/blocks`, fall back to polling `GET /chain` when the socket is unavailable or drops, show an explicit "still pending / possible network issue" state after a timeout, and clean up safely on unmount.
- **Verify:** `npm --prefix web run test -- IssuePage hash`
- **Done when:** submitting a file issues exactly one `POST /documents` whose body contains only `hash` and `metadata` and no signature field, with no request carrying the file bytes (WI-TC-1.1); a 409 renders a duplicate-specific error distinct from the network-error state (WI-TC-1.7/1.8/1.10, WI-TC-2.3); an empty form is blocked client-side with no request sent (WI-TC-1.4); a 0-byte file still hashes and submits (WI-TC-1.9); a pasted uppercase/whitespace hash is normalized before submission (WI-TC-2.4); confirmation shows block index and hash on the WS path and on the polling fallback (WI-TC-3.1/3.2/3.4); a timeout yields an explicit pending state rather than an endless spinner (WI-TC-3.3); unmounting mid-wait does not crash (WI-TC-3.5).
- **Pre-review:** **security** — confirm end-to-end that no private-key material or signature can originate in the browser (a hard PRD constraint).

---

### Slice 22: Verify page — lookup, found/not-found/invalid states, Merkle proof result

- **Epic:** 4. **Depends on:** Slice 21. **Est.:** ~1 week.
- **Use cases:** E4-UC-4 (+A, E1, E2, EC1, EC2), E4-UC-5 (+E1), E4-UC-6 (+A, B, E1, EC1).
- **Test cases:** WI-TC-4.1…4.6, WI-TC-5.1…5.3, WI-TC-6.1…6.5.
- **Files:** `web/src/lib/merkle.ts` `[new]`, `web/src/pages/VerifyPage.tsx` `[new]`, `web/src/__tests__/VerifyPage.test.tsx` `[new]`, `web/src/__tests__/merkle.test.ts` `[new]`
- **Changes:** File-upload and pasted-hash entry points sharing one downstream query/render path. `GET /documents/{hash}`: HTTP 404 maps to an explicit **"not found"**, an unreachable API maps to a **separate** error/retry state, and the two must never be visually or semantically merged. `merkle.ts`: a browser-side re-implementation of the domain-separated proof verification from Slice 3 (leaf `H(0x00||…)`, internal `H(0x01||left||right)`, unpaired promotion) validated against fixtures generated from the Python implementation, so the "valid" badge is cryptographically grounded rather than a trust-the-server flag. Missing/incomplete proof data → "unable to verify proof", never a default "valid".
- **Verify:** `npm --prefix web run test -- VerifyPage merkle`
- **Done when:** an unmodified issued document renders "valid" with correct issuer, timestamp, and block index (WI-TC-4.1/5.1); a never-issued hash renders "not found" and an unreachable API renders a distinct error state (WI-TC-4.5/4.3); **a document whose on-chain record was tampered with renders an explicit "invalid" — never "valid" and never "not found"** (WI-TC-4.6/6.5, the central end-to-end tamper test); missing proof data renders "unable to verify proof" (WI-TC-6.4); the browser-side proof verification agrees with the Python implementation on every shared fixture, including single-leaf and promoted-node cases (WI-TC-6.2).
- **Pre-review:** none.

---

### Slice 23: Chain visualization page, node selector, live refresh (Epic 4 acceptance gate)

- **Epic:** 4. **Depends on:** Slice 22. **Est.:** ~1–1.5 weeks.
- **Use cases:** E4-UC-7 (+A, E1, EC1–EC3), E4-UC-8 (+E1, EC1).
- **Test cases:** WI-TC-7.1…7.7, WI-TC-8.1…8.3.
- **Files:** `web/src/pages/ChainVisualizationPage.tsx` `[new]`, `web/src/components/BlockCard.tsx` `[new]`, `web/src/components/NodeSelector.tsx` `[new]`, `web/src/__tests__/ChainVisualizationPage.test.tsx` `[new]`
- **Changes:** Fetch `GET /chain` (paginated) plus `GET /node/info` from the selected node; render a connected chain diagram with index, timestamp, and document count per block. Validity indicators come **strictly** from `chain_valid`/`first_invalid_index` — the block at `first_invalid_index` is flagged and everything before it is shown valid. Node selector re-fetches and re-renders without a full page reload and updates the badge. Live auto-refresh on `WS /ws/blocks`. Long chains stay responsive via pagination or virtualization. An unreachable node shows an explicit error rather than silently displaying stale data.
- **Verify:** `npm --prefix web run test -- ChainVisualizationPage; npm --prefix web run build`
- **Done when:** ≥5 sequential blocks render correctly and a block corrupted in the backing store is flagged invalid while the rest still render (WI-TC-7.6 — the live tamper demo, and the PRD §4 acceptance criterion); a genesis-only chain renders through the normal path with no empty-state special case (WI-TC-7.5); switching nodes re-renders without a page reload and never merges two nodes' chains when they fork (WI-TC-8.1/8.3); an unreachable node/selection shows a scoped explicit error (WI-TC-7.4/8.2); a 100+ block chain remains responsive (WI-TC-7.7). **Epic 4 is done when this slice is green.**
- **Pre-review:** none.

---

### Slice 24: Attacker component/image scaffold + attack-run results recorder

- **Epic:** 5. **Depends on:** Slice 19 (network) — can be started before or alongside Epic 4. **Est.:** ~1 week.
- **Use cases:** E5-UC-1-A (separate attacker image), E5-UC-6 (+E1, EC1).
- **Test cases:** AT-TC-1.3, AT-TC-6.1, 6.2, 6.3.
- **Files:** `attacks/__init__.py` `[new]`, `attacks/attacker_node/__init__.py` `[new]`, `attacks/attacker_node/overrides.py` `[new]`, `attacks/harness/__init__.py` `[new]`, `attacks/harness/recorder.py` `[new]`, `docker/attacker.Dockerfile` `[new]`, `docker-compose.yml` (extend — an `attacker` service profile), `results/attack_runs.csv` `[new]`, `tests/attacks/test_recorder.py` `[new]`, `tests/attacks/test_attacker_separation.py` `[new]`
- **Changes:** A **separate** attacker image with its own Dockerfile and compose service that **imports** `src/node`'s consensus engine as a library and subclasses/patches the message-handling and mining hooks from the outside. The honest-node image must contain **zero** attacker-mode flags, env conditionals, or hooks. `recorder.py`: append-only rows with `attack_type`, `consensus_mode`, `attacker_hash_power_share` (PoW) **and** `attacker_validator_seat_fraction` (PBFT) as **separate columns** — never one generic "fraction" — plus `failure_class` (byzantine|crash|n/a), `hash_rate_sample` (PoW), `outcome` (detected|blocked|succeeded|inconclusive), `time_to_detection`. A failed write raises a clear error and never silently drops a run.
- **Verify:** `python -m pytest tests/attacks/test_recorder.py tests/attacks/test_attacker_separation.py -v; docker build -f docker/attacker.Dockerfile .`
- **Done when:** a repository scan finds no attacker-mode conditional, flag, or hook anywhere under `src/node/` and the attacker behavior exists only under `attacks/` + `docker/attacker.Dockerfile` (AT-TC-1.3 — the M-13 closure); the attacker image builds and joins the compose network as its own service; a completed run appends exactly one row with the two metric columns kept separate (AT-TC-6.1); re-running the same parameters appends a second row rather than overwriting (AT-TC-6.3); a write failure surfaces an explicit error (AT-TC-6.2).
- **Pre-review:** **architect** — the honest-node/attacker separation boundary is an explicit PRD acceptance criterion (M-13) and is easy to violate accidentally.

---

### Slice 25: Sybil attack against PoW — hash-power-share measurement and sweep

- **Epic:** 5. **Depends on:** Slice 24. **Est.:** ~1–1.5 weeks.
- **Use cases:** E5-UC-1 (+B, E1, E2, EC1, EC2).
- **Test cases:** AT-TC-1.1, 1.2, 1.4, 1.5, 1.6, 1.7, 1.8.
- **Files:** `attacks/scenarios/sybil_pow.py` `[new]`, `attacks/attacker_node/overrides.py` (extend — mining-bias and proposal-flooding behavior), `tests/attacks/test_sybil_pow.py` `[new]`, `docs/results/` `[new dir]`
- **Changes:** Spin up N attacker containers at a configurable per-container mining effort against the honest network's **shared** `expected_difficulty`. Measure the attacker's **hash-power share** from per-container `hash_rate` samples via `GET /metrics/consensus` — never node count. Record fork / stall / attacker-block-finalized outcomes. Include a negative sub-scenario in which the attacker mines at a self-chosen lower declared difficulty. Sweep the share (linear or binary search) to bracket the disruption threshold. Infrastructure failures (attackers cannot join; honest network dies of resource exhaustion) are recorded as **inconclusive**, never as "attack failed".
- **Verify:** `python -m pytest tests/attacks/test_sybil_pow.py -v` then a real run: `python -m attacks.scenarios.sybil_pow --sweep --mode pow`
- **Done when:** an attacker block declaring an artificially low difficulty is rejected with `failure_type = "difficulty"` and never counts as a win (AT-TC-1.2 — the FR-24 cross-check); every recorded PoW row carries a measured hash-power share and a `hash_rate_sample`, and no row records a raw node-count fraction (AT-TC-1.1, PRD §5 acceptance criterion); the 0-share control run records "no disruption" (AT-TC-1.7); a run at/above hash-power majority records disruption (AT-TC-1.8); infra failures are recorded as inconclusive (AT-TC-1.5/1.6); the sweep produces at least one successful and one unsuccessful run for PoW (PRD §5 acceptance criterion).
- **Pre-review:** **security** — this scenario deliberately exercises the Sybil surface; confirm it runs against a disposable network only.

---

### Slice 26: Sybil attack against PBFT — seat fraction, Byzantine vs. crash variants, PeerInfo negative control

- **Epic:** 5. **Depends on:** Slice 25. **Est.:** ~1.5 weeks.
- **Use cases:** E5-UC-2 (+A, B, C, E1, EC1, EC2).
- **Test cases:** AT-TC-2.1…2.8.
- **Files:** `attacks/scenarios/sybil_pbft.py` `[new]`, `attacks/attacker_node/overrides.py` (extend — equivocating and silent variants), `tests/attacks/test_sybil_pbft.py` `[new]`
- **Changes:** Controlled-experiment redeployment placing N attacker containers into N of the n boot-time `ValidatorSet` seats. Two clearly separated variants: **UC-2-B Byzantine equivocation** (conflicting `prepare`/`commit` to different honest peers — a safety test) and **UC-2-C crash/silent** (stop responding — a liveness test). Outcome classification is read from `GET /node/info`'s `quorum_status`, not inferred. Include the boundary point `f = floor((n-1)/3)` and an explicitly labelled over-limit point (e.g., 2 attacker seats on n=4) recorded as an intentional boundary test, not a vulnerability. Include the **negative control**: mass `POST /peers/register` with zero `ValidatorSet` seats.
- **Verify:** `python -m pytest tests/attacks/test_sybil_pbft.py -v` then `python -m attacks.scenarios.sybil_pbft --sweep`
- **Done when:** mass `PeerInfo`-only registration leaves the quorum threshold and every consensus outcome unchanged (AT-TC-2.8 — the central C-4 negative control); at/below the theoretical boundary the Byzantine variant finalizes **no** wrong block (AT-TC-2.4/2.7); the crash variant at/below f keeps finalizing and above f stalls with a **crash/liveness** label never conflated with a Byzantine finding (AT-TC-2.5); every recorded PBFT row carries a `ValidatorSet` seat fraction and a `failure_class` (AT-TC-2.2); the over-limit run is labelled a boundary test point (AT-TC-2.6); the sweep produces at least one successful and one unsuccessful run for PBFT (PRD §5 acceptance criterion).
- **Pre-review:** **security** — directly targets the quorum/equivocation logic from Slices 17–18.

---

### Slice 27: Backdating/tampering — direct chain-store mutation with out-of-band trust anchor

- **Epic:** 5. **Depends on:** Slice 24 (recorder), Slice 9 (validation guarantees). **Est.:** ~1–1.5 weeks.
- **Use cases:** E5-UC-4 (+A, B, E1, E2, EC1, EC2).
- **Test cases:** AT-TC-4.1…4.11.
- **Files:** `attacks/harness/trust_anchor.py` `[new]`, `attacks/harness/resolver.py` `[new]`, `attacks/scenarios/tamper_store.py` `[new]`, `config/trust_anchor.example.json` `[new]`, `tests/attacks/test_tamper_store.py` `[new]`
- **Changes:** `trust_anchor.py` reads a **separately stored, read-only** trusted `IssuerKeyPair`/`NodeKeyPair` public-key file kept **outside** the attacked node's key-store directory. `resolver.py` builds a key resolver from that anchor and injects it into Epic 2's `validate_chain` — this is the exact seam that makes the test resistant to an attacker who swaps both the data and the node's local keys. The harness must never fall back to the attacked node's local key-store. Scenarios: metadata-only mutation; block-preimage mutation; mutation with the block's own `block_hash` recomputed at any position; content re-signed with an attacker key; multiple simultaneous tamper points. Re-validation is triggered by a node restart or by an append/sync event — **there is no periodic validation cycle to wait for**. Every scenario also confirms end-to-end through `GET /documents/{hash}` and `GET /node/info`, with no dependency on the Epic 4 UI.
- **Verify:** `python -m pytest tests/attacks/test_tamper_store.py -v` then `python -m attacks.scenarios.tamper_store --target <disposable-node>`
- **Done when:** validation using the out-of-band resolver reports invalid at the correct index with the expected `failure_type` for every scenario (AT-TC-4.3); a preimage-field tamper with recomputed `block_hash` at **any** position is caught via `proposer_signature` (AT-TC-4.7 — the M-1 closure, and a critical finding if it is not); content re-signed with an attacker key is rejected against the out-of-band issuer key (AT-TC-4.8); a code-level assertion proves the harness never reads the attacked node's local key-store (AT-TC-4.9 — the M-2 regression guard); detection is identical for a near-genesis block and the tip (AT-TC-4.10); with multiple tamper points, the earliest failing index is reported and a follow-up scan reveals the rest (AT-TC-4.11); `GET /node/info` reports `chain_valid = false` with the right `first_invalid_index` after a restart or sync event (AT-TC-4.2/4.4).
- **Pre-review:** **security** — the out-of-band trust-anchor requirement (M-2) is precisely the kind of thing that silently degrades into "read the local key file"; review before implementing.

---

### Slice 28: Backdating/tampering — mid-chain block injection (offline and online paths)

- **Epic:** 5. **Depends on:** Slice 27. **Est.:** ~1 week.
- **Use cases:** E5-UC-5 (+A, B, E1, EC1).
- **Test cases:** AT-TC-5.1…5.7.
- **Files:** `attacks/scenarios/inject_block.py` `[new]`, `tests/attacks/test_inject_block.py` `[new]`
- **Changes:** Construct a forged block carrying a falsified, chronologically earlier timestamp positioned to appear mid-chain. **Offline path:** write it directly into the store file and restart/reload the node. **Online path:** broadcast it / propose it via PBFT against a live honest node. Also attempt the full renumber-and-shift variant to demonstrate the cascading re-sign requirement, and confirm honest peers holding the pre-injection chain reject the rewritten fork through **full from-genesis revalidation** (Slice 16's divergence path).
- **Verify:** `python -m pytest tests/attacks/test_inject_block.py -v` then `python -m attacks.scenarios.inject_block --mode offline` and `--mode online`
- **Done when:** the offline injection is rejected at reload with `failure_type` of `"structural"` or `"link"` (AT-TC-5.2/5.4); the online injection is rejected immediately on `proposer_signature` verification and is **not re-broadcast** (AT-TC-5.3/5.5); a fully hash-consistent injection with a chronologically earlier timestamp is rejected by the monotonicity check with `"structural"` (AT-TC-5.7 — a critical finding if it is not); the renumber-and-shift variant is shown to require re-signing every downstream block, and honest peers reject the rewritten chain via full revalidation (AT-TC-5.6); every run appends a recorder row.
- **Pre-review:** **security** — exercises the chain-sync fork-adoption path from the security-priority list.

---

### Slice 29: Threshold aggregation and comparison charts

- **Epic:** 5. **Depends on:** Slices 25–28 (need recorded runs). **Est.:** ~1 week.
- **Use cases:** E5-UC-3 (+E1, EC1), E5-UC-7 (+A, E1, EC1).
- **Test cases:** AT-TC-3.1, 3.2, 3.3, AT-TC-7.1…7.6.
- **Files:** `attacks/analysis/__init__.py` `[new]`, `attacks/analysis/thresholds.py` `[new]`, `attacks/analysis/charts.py` `[new]`, `results/charts/` `[new dir]`, `tests/attacks/test_thresholds.py` `[new]`, `tests/attacks/test_charts.py` `[new]`
- **Changes:** `thresholds.py`: aggregate recorded runs per consensus mode and compute the minimum disruptive attacker fraction on the **algorithm-appropriate axis** — PoW hash-power share, PBFT `ValidatorSet` seat fraction — computed and reported independently, never merged; emit an explicit "no threshold found within the tested range" marker when applicable. `charts.py`: (a) a PoW-vs-PBFT block-finalization-latency chart across difficulties/network sizes sourced from `GET /metrics/consensus`; (b) a Sybil-resistance chart rendered as **two separate panels** with different x-axes. Export static images sized for the thesis document. Regeneration from stored data must be deterministic; a dataset missing rows for a chart must produce an explicit "cannot generate chart X because Y" message, never a misleading empty plot.
- **Verify:** `python -m pytest tests/attacks/test_thresholds.py tests/attacks/test_charts.py -v; python -m attacks.analysis.charts --out results/charts`
- **Done when:** the Sybil chart is emitted as two panels with distinct x-axis labels ("attacker hash-power share" and "attacker ValidatorSet seat fraction") and **no** shared node-count axis exists anywhere in the output (AT-TC-7.2 — the M-8 closure); ≥2 chart image files exist under `results/charts/` (PRD §5 acceptance criterion); running the script twice on unchanged data produces identical output (AT-TC-7.6/7.4); a dataset with no PBFT rows produces a named, explicit error instead of an empty chart (AT-TC-7.5); each mode's threshold (or its explicit "not found" marker) is reported on its own axis (AT-TC-3.1/3.2).
- **Pre-review:** none.

---

## Epic 6 — Non-functional requirements and operations (added 2026-10-28)

Closes the gap between Chapter 1 §1.5 (Core Features + NFR matrix, Table 1.5) and this plan: Prometheus/Grafana, API hardening, TLS 1.3, container/CI hardening, snapshots, and every measurable NFR target. **Documentation:** PRD §6 (Epic 6, FR-1…FR-23), use cases `use-cases/nfr_operations_use_cases.md` (`E6-UC-…`) and QA cases `qa/nfr_operations_test_cases.md` (`NF-TC-…`, 385 test cases). Architecture reviews rounds 1–3 returned FAIL; the decisions below are the resolutions and are binding for Slices 13, 16a/16b, 17, 17b and 30–35b. The earlier Slices 16, 31, 32, 33 and 35 are split into 16a/16b, 31a/31b, 32a/32b, 33a/33b and 35a/35b; Slice 34 is listed first and runs right after Slice 14.

- **`forward_record` is built in Epic 3, not Epic 6.** Non-primary → primary forwarding of pre-signed records is a typed `forward_record` message on `WS /ws/pbft` (request id, synchronous ack with timeout, closed reply enum `accepted | duplicate | not_primary | not_validator | unregistered_issuer | invalid_record | auth_failed`, mapped to HTTP for the original `POST /documents`). **Slice 13** owns the `RecordForwarder` interface (stub, tri-state `is_primary()` seam), the HTTP mapping and a parameterised mapping test; **Slice 17b** (after view-change Slice 18) builds the real WS channel, sender authentication, record validation, dedupe, `not_primary` and late-reply discard; **Slice 31b** adds only the `IssuerRegistry` check and the `unregistered_issuer` reply. The primary's rejection is a WS reply code, not an HTTP status; the forwarding non-primary maps it to 403 on the original request. Public `POST /documents` still rejects any `signature` body with 400. In PoW mode there is no intake channel: the evidence is block-level rejection by the Epic 2 signature check when the issuer cannot be resolved.
- **`ChainState` (single owner + one asyncio lock for append/replace/snapshot) is introduced in Slice 16a** (before sync/replace in 16b, so both operations exist behind one lock) and used by Slices 14/15 (retrofitted), 16b, 17 and 17b; Slice 33b only adds the snapshot copy (frozen blocks) under that lock. The append-during-replace concurrency tests live in Slice 16a (CN-TC-17.x).
- **Key/cert volumes are one per service** (or compose `volume.subpath`); each container mounts only its own key material plus the CA certificate read-only; the dev-CA private key never lives in a runtime volume; a test proves the attacker container cannot read any `node*` key file.
- **NFR-P3 statistic is frozen as p95** (Table 1.5 gives none). NFR-P2 latency for non-primary-received requests includes the forward round-trip and is reported separately from primary-received.
- **TLS = server authentication + confidentiality only (no mTLS).** Node identity stays at the application layer (NodeKeyPair signatures). The cert generator issues certs for node names (n = 4…10) **and** attacker service names; Epic 5 findings state attackers hold CA-signed certs (insider model).
- **Headline NFR-S1/P1/P2 are measured in PBFT mode.** PoW S1 is structurally capped at block_interval × 256 (≈25.6 rec/s at 10 s) and is reported with that arithmetic.
- **Measurement protocol is frozen before any headline run** (statistics, intervals, fixtures, load model); early runs are indicative and labelled non-headline; every headline row is re-run at the final hardened commit.
- **Single `ChainState` owner** with one asyncio lock for append/replace/snapshot; snapshots copy the in-memory block list under the lock, never the chain-store file.

### Slice 34: NFR measurement — core level (harness, P5, S1 batching, P4)

- **Epic:** 6. **Depends on:** Slice 9 (core), Slice 11 (real time-aware resolver), Slice 14 (PoW). **Est.:** ~1–1.5 weeks. Rows produced here are indicative (`headline=false`) unless produced at the final hardened commit; every headline P4/P5/S1-batching row is re-run in Slice 35b.
- **Use cases:** E6-UC-15 (primary, A1, E1–E4, EC1–EC6); E6-UC-16 (primary, A1, A2, E1–E5, EC1–EC4); E6-UC-17 (primary, A1, E1, E2, EC1–EC3); E6-UC-18 (primary, A1, A2, E1–E4, EC1–EC3); E6-UC-28-A1, E4, E6, EC2 (harness-level rules).
- **Test cases:** NF-TC-15.1…15.12, NF-TC-16.1…16.12, NF-TC-17.1…17.7, NF-TC-18.1…18.10, NF-TC-28.2, 28.8, 28.10, 28.12.
- **Files:** `benchmarks/__init__.py` `[new]`, `benchmarks/record.py` `[new]` (nine-column CSV writer, git/machine metadata, `-dirty` handling, headline demotion), `benchmarks/targets.py` `[new]` (Table 1.5 target constants + `HEADLINE_IDS` list used by 35b), `benchmarks/fixtures.py` `[new]` (seeded 10 000-block PoW fixture, PBFT supplementary fixture, on-disk cache with tip-hash check), `benchmarks/bench_validate_chain.py` `[new]`, `benchmarks/bench_batching.py` `[new]`, `benchmarks/bench_pow_time.py` `[new]`, `tests/benchmarks/test_record.py` `[new]`, `tests/benchmarks/test_bench_core.py` `[new]`, `tests/benchmarks/test_bench_smoke.py` `[new]`, `tests/test_layering.py` `[new]` (`src/*` never imports `benchmarks/` or `attacks/`), `results/nfr_measurements.csv` (created on first run)
- **Changes:** The fixture composition is fixed in PRD §6 FR-17 before any run (records per block, algorithm, signature scheme); a deterministic synthetic chain of 10 000 blocks is cached on disk and **loading/deserialization is outside the timed region**. Time `validate_chain` with the **real time-aware resolver** (`benchmarks/` may import `src/*`; `src/*` never imports `benchmarks/` or `attacks/`); median of 5 runs, hardware + commit hash in every CSV row. Measure records/s for 256-record blocks including signature verification and Merkle construction. NFR-P4: calibrate `EXPECTED_DIFFICULTY` on ≥100 blocks for a mean of 10 s (single miner in-process vs compose network is stated per row), then measure ≥30 blocks and report mean and spread; recalibration needs a fresh chain. If a target is missed, the row records the miss — do not tune the threshold; optimise and re-measure. CSV header is exactly `nfr_id,value,target,pass_fail,mode,achieved_rps,headline,machine,commit`; `mode ∈ {pow,pbft,core}`; a row missing any column is refused; `commit` = `git rev-parse HEAD` or the explicit `unknown` marker, `-dirty` rows can never be `headline=true`; writing a new headline row for an NFR ID demotes the older one; only the 10 000-block P5 row and the PBFT-mode S1 row are headline-eligible for their IDs; pass/fail is computed from `targets.py` constants; smoke runs write to a temporary CSV.
- **Verify:** `python -m pytest tests/benchmarks tests/test_layering.py -v; python -m benchmarks.bench_validate_chain --blocks 10000; python -m benchmarks.bench_batching; python -m benchmarks.bench_pow_time --calibrate 100 --measure 30`
- **Done when:** all listed NF-TC tests pass (harness tests use injected clocks and small fixtures; numeric results are not asserted); `results/nfr_measurements.csv` has the exact nine-column header and contains rows for NFR-P5 (10 000 blocks, median of 5, target 5 s), the labelled PBFT-fixture P5 supplementary row (`mode=pbft`, never headline), NFR-S1 batching (256-record batches, target 50 rec/s) and NFR-P4 (single-miner in-process, ≥100 calibration + ≥30 measured blocks, mean and spread), each with all nine columns populated (`achieved_rps` empty); editing any target constant fails NF-TC-15.8; the smoke test runs a 100-block chain in the normal pytest run and writes only to a temp CSV (NF-TC-15.2); the layering test fails on a fixture `src/` module importing `benchmarks` (NF-TC-15.6).
- **Pre-review:** **architect (light)** — P5 fixture composition, resolver choice, P4 calibration, headline eligibility rules.

---

### Slice 30: Prometheus metrics export + Prometheus/Grafana stack

- **Epic:** 6. **Depends on:** Slice 14 (metrics source), Slice 19 (network; transitively 17b/18 for the PBFT rejection path). **Est.:** ~1 week.
- **Use cases:** E6-UC-1 (primary, A1–A3, E1, E2, E4, E5, EC1–EC5; E3 → Slice 31a); E6-UC-2 (primary over plain http, A2, E1, E3, E4, E5, EC1–EC3; https part of primary + A3 + E2 → Slice 32b; A1 → Slice 35b).
- **Test cases:** NF-TC-1.1…1.6, 1.8…1.14; NF-TC-2.1 (http variant), 2.3, 2.5, 2.7…2.12.
- **Files:** `src/node/metrics.py` (extend — dedicated `CollectorRegistry`, series, buckets), `src/node/api/metrics.py` (extend — `GET /metrics`), the single FR-25 validation entry-point module named in Slice 15 (extend — the one `blocks_rejected_total` wrapper; see gap G5), `docker/prometheus.yml` `[new]`, `docker/grafana/provisioning/datasources/prometheus.yml` `[new]`, `docker/grafana/provisioning/dashboards/dashboards.yml` `[new]`, `docker/grafana/dashboards/node_overview.json` `[new]`, `docker-compose.yml` (extend — `prometheus`, `grafana`, `127.0.0.1` port binds), `.env.example` `[new]`, `.gitignore` (extend — `.env`), `pyproject.toml` (extend — `prometheus_client`), `tests/node/test_prometheus_export.py` `[new]`, `tests/infra/test_compose_static.py` `[new]`, `tests/infra/test_monitoring_stack.py` `[new]` (`@pytest.mark.docker`)
- **Changes:** Use `prometheus_client` with a **dedicated `CollectorRegistry`** (the default registry adds `python_gc`/`process_*` series with extra labels). Gauges/histograms: `chain_height`, `peer_connections{state}` (from `PeerConnectionManager` health), `consensus_finalization_seconds{algorithm}` histogram with explicit buckets that include `le="2"` and extend to ≥120 s (so PoW is not all `+Inf`), `mempool_size`, `blocks_rejected_total{failure_type}`. The histogram is observed in the **same call** that writes the `ConsensusMetric` row, so `/metrics` and `/metrics/consensus` cannot disagree; `blocks_rejected_total` is incremented from one wrapper around the single validation entry point. Prometheus scrapes all nodes over http in this slice; Slice 32b switches the scrape to https with `tls_config`; host ports for Prometheus (9090) and Grafana (3000) bind to `127.0.0.1`; Grafana admin password comes from an uncommitted `.env`. `/metrics` is unauthenticated (recorded in OWASP API8/API9). No new data is collected that is not already in Slices 14–18. Grafana admin password has no default: compose fails if `.env` or the key is missing.
- **Verify:** `python -m pytest tests/node/test_prometheus_export.py tests/infra/test_compose_static.py -v; docker compose up -d --build; python -m pytest tests/infra/test_monitoring_stack.py -m docker -v; docker compose down -v`
- **Done when:** `GET /metrics` returns 200 `text/plain; version=0.0.4` with the five series; after one finalized block `chain_height` +1 and the histogram `_count` +1 and equal to the `GET /metrics/consensus` row count (NF-TC-1.1, 1.8); a signature-rejected block increments `blocks_rejected_total{failure_type="signature"}` exactly once on each of the sync, PoW-broadcast and PBFT paths, with exactly one increment site (NF-TC-1.4); the body contains no key material, signature, metadata or document hash, and no `python_*`/`process_*` series; label names ⊆ {`state`,`algorithm`,`failure_type`,`le`} (NF-TC-1.5, 1.6); buckets include `le="2"` and a finite bucket ≥ 120 (NF-TC-1.9); `GET http://127.0.0.1:9090/api/v1/targets` lists ≥4 node targets with `health="up"` (NF-TC-2.1, http); the Grafana HTTP API returns the provisioned dashboard (200) with no manual step, and a datasource query for `chain_height` returns series for ≥2 distinct `instance` labels (NF-TC-2.1, 2.7); compose refuses to start without the `.env` password (NF-TC-2.8); the static check fails on a Prometheus/Grafana port mapping without `127.0.0.1:` (NF-TC-2.9); `.env` is untracked and `.env.example` holds no real password (NF-TC-2.12).
- **Pre-review:** **architect (light)** — dedicated registry, bucket boundaries, single increment site, port binding; confirm `/metrics` leaks nothing.

---

### Slice 31a: Per-IP rate limiting, SPA status handling, rate-limit config fail-fast

- **Epic:** 6. **Depends on:** Slices 13, 15, 17b (503 codes from forwarding), 22 (SPA client), 30 (`GET /metrics` route, Prometheus scrape rate). **Est.:** ~1–1.5 weeks.
- **Use cases:** E6-UC-3 (primary, A1–A6, E1–E6, E8, EC1–EC12; E7 docs part → 31b); E6-UC-1-E3; E6-UC-29-A1, A2, A5, A6, A7, E1, E2, EC1, EC2, EC4, EC5; E6-UC-30 (primary, A2 rate-limit defaults, E1, E2 exemption flag, E5, E6, E8 matrix introduced, EC1, EC3, EC4).
- **Test cases:** NF-TC-3.1…3.13, 3.15…3.27; NF-TC-1.7; NF-TC-29.2, 29.3, 29.6…29.10, 29.15, 29.16, 29.18, 29.19; NF-TC-30.1, 30.3 (rate-limit + `FORWARD_ACK_TIMEOUT_MS` defaults; completed in 33b), 30.5, 30.6 (`RATE_LIMIT_EXEMPT_VALIDATORS` half), 30.9, 30.10, 30.12 (rows for rate-limit keys + `FORWARD_ACK_TIMEOUT_MS`), 30.13, 30.15, 30.16.
- **Files:** `src/node/rate_limit.py` `[new]`, `src/node/errors.py` (extend — shared envelope builder usable outside handlers), `src/node/main.py` (extend — middleware order, programmatic single-worker uvicorn with `proxy_headers=False`), `src/node/config.py` (extend — `RATE_LIMIT_PER_MIN`, `RATE_LIMIT_EXEMPT_VALIDATORS`, `RATE_LIMIT_MAX_TRACKED_IPS`, validation before any listener/task), `pyproject.toml` (extend — pin uvicorn/websockets), `web/src/api/client.ts` (extend — 429/503 + `Retry-After` as retry guidance, 403/422/502 as node errors, 409 "already submitted", no auto-resubmit), `tests/node/test_rate_limit.py` `[new]`, `tests/node/test_rate_limit_live.py` `[new]` (real uvicorn: XFF, WS denial, workers), `tests/node/test_config_failfast.py` `[new]` (parametrised key matrix), `web/src/__tests__/client429.test.ts` `[new]`, `web/src/__tests__/clientIssueErrors.test.ts` `[new]`
- **Changes:** Per-client-IP limiter (100 req/min, configurable) implemented as **pure ASGI middleware** covering `http` and `websocket` scopes (Starlette `BaseHTTPMiddleware` never sees WS upgrades); algorithm = exact sliding log `deque(maxlen=limit)` per IP plus an LRU-capped tracked-IP map (memory = cap × limit, documented). 429 is built through the shared envelope function with `Retry-After`; `CORSMiddleware` is outermost and `Retry-After` is in `Access-Control-Expose-Headers`. WS pre-upgrade denial uses the ASGI denial-response extension if the pinned uvicorn/ws backend supports it, else close-before-accept (documented fallback). uvicorn runs with `proxy_headers=False` so `X-Forwarded-For` cannot alter the client IP; one worker only. Exemption (default off) is built only from static `ValidatorSet` config — **never from `PeerInfo`** (peer registration is unauthenticated). Fail-fast boot validation (FR-23) covers `RATE_LIMIT_*` keys. IPv4-mapped IPv6 addresses are normalised to IPv4 for keying and exemption. A parametrised fail-fast matrix enumerates every node config key; a key with no matrix row fails the test, so Slices 32a and 33b must add their rows. SPA: no new pages or components; existing Issue/Verify error displays render the new error kinds; one consolidated message for several concurrent 429s; auto-retry timer capped, manual retry always available.
- **Verify:** `python -m pytest tests/node/test_rate_limit.py tests/node/test_rate_limit_live.py tests/node/test_config_failfast.py -v; npm --prefix web run test -- client429 clientIssueErrors`
- **Done when:** with an injected clock the 101st request in 60 s from IP X returns 429 in the shared envelope with an integer `Retry-After` in [1, 60], IP Y (ASGI scope injection) is not limited, X succeeds again after the window, and the rejected `POST /documents` leaves no pending record (NF-TC-3.1, 3.7, 3.8, 3.16, 3.21); 150 concurrent requests from one IP → exactly 100 processed, 50 × 429 (NF-TC-3.19); 10 000 distinct IPs plus one more keep memory within cap × limit and the node keeps serving (NF-TC-3.17, 3.18); against a real uvicorn server rotating `X-Forwarded-For`/`X-Real-IP`/`Forwarded` does not avoid the 429 (NF-TC-3.9); the 101st WS upgrade is denied before the handler runs, with the mechanism matching the pinned uvicorn (NF-TC-3.4, 3.13); 429 from the allowed origin carries `Access-Control-Allow-Origin` and exposes `Retry-After`, and `CORSMiddleware` is outermost (NF-TC-3.6, 3.24); a `POST /peers/register` peer with the flag `true` is still limited and nobody is exempt by default (NF-TC-3.12, 3.22); >1 worker is rejected (NF-TC-3.15); 429 on `GET /metrics` above the limit while the default scrape stays far below it (NF-TC-1.7, 3.27); invalid `RATE_LIMIT_*` values exit non-zero naming the key before any port opens (NF-TC-3.11, 30.5, 30.9, 30.15); vitest: 429/503 show "retry after N seconds" with no retry before N, 403/422/502 show node errors, 409 shows "already submitted", none renders as a verification result, and no background resubmission happens (NF-TC-3.5, 3.10, 29.2, 29.3, 29.6…29.10, 29.15, 29.16, 29.19).
- **Pre-review:** **security** + **architect** — middleware order vs CORS/envelope, WS denial mechanism, `proxy_headers=False`, exemption source.

---

### Slice 31b: Unregistered-issuer rejection, OWASP API Top 10 checklist, no-PII guard

- **Epic:** 6. **Depends on:** Slices 17b (channel), 30 (`blocks_rejected_total` for the PoW test), 31a (rate-limit evidence cited by the checklist; NF-TC-4.4). **Est.:** ~1 week.
- **Use cases:** E6-UC-4 (primary, A1, A2, A3, A7, E1, E4, E5, E6, EC1–EC4, EC6 — OWASP half); E6-UC-5 (primary, A1, A2, E1–E4, EC2, EC3, EC5; EC1 → 32a, EC4 → 33a); E6-UC-6 (primary, A1, A2, E1, E2, EC1, EC2); E6-UC-3-E7; E3-UC-16-E5 (post-Epic-6 expectation); E3-UC-16-E9 pairs 3/4 and 4/5.
- **Test cases:** NF-TC-4.1…4.14 (4.14 OWASP half; report half = NF-TC-27.9 in 35b), NF-TC-5.1…5.7, 5.9, 5.10, 5.12, NF-TC-6.1…6.7, NF-TC-3.14; CN-TC-16.15 (updated expectation `unregistered_issuer`), CN-TC-16.24, CN-TC-16.34 *(proposed — gap G1)*.
- **Files:** `src/node/consensus/pbft/forward.py` (extend — check 4 `IssuerRegistry` exact-match lookup between shape and signature), `tests/node/test_issuer_auth.py` `[new]` (PBFT + PoW), `tests/node/test_forward_record.py` (extend — CN-TC-16.15 update, 16.24, 16.34), `tests/core/test_no_pii.py` `[new]`, `docs/security/owasp_api_top10_checklist.md` `[new]`, `tests/docs/test_owasp_checklist.py` `[new]`
- **Changes:** WS message flooding after upgrade is an accepted risk in OWASP API4. Unregistered issuer: a pre-signed record arriving as `forward_record` on `/ws/pbft` whose `issuer_id` is not in `IssuerRegistry` is rejected by the primary with reply code `unregistered_issuer`, not queued; public `POST /documents` keeps rejecting `signature` bodies with 400. In PoW mode (no intake channel) the same evidence is block-level rejection by the Epic 2 signature check when the resolver cannot find the issuer; `test_issuer_auth.py` covers both modes. The OWASP API Security Top 10 (2023) checklist maps each item to the control that addresses it or a stated "not applicable / accepted risk" with reason. `test_no_pii.py` asserts the block/record schemas contain only `document_hash`, `signature`, `issuer_id`, `issued_at`, metadata (size-capped), and fails if a new field is added without being listed. `issuer_id` comparison is exact (no case folding or trimming). The checklist is created with rows citing only controls that already exist; Slice 32a extends API8 (`INSECURE_DEV_MODE`), Slice 33a extends API1/API5 (per-service key isolation). The docs test parses the table, requires exactly API1:2023…API10:2023, rejects empty/"TBD" cells, resolves every cited test file/FR/endpoint (dangling references fail), checks the mandatory records (API4 WS flooding, API8/API9 `/metrics` + `127.0.0.1`, WS denial mechanism + pinned uvicorn version), compares the API9 inventory with the app's route list, and requires SEC3 and SEC4 as separate rows with SEC4 stating both modes. The no-PII guard walks nested models and includes the metadata cap constant.
- **Verify:** `python -m pytest tests/node/test_issuer_auth.py tests/node/test_forward_record.py tests/core/test_no_pii.py tests/docs/test_owasp_checklist.py -v`
- **Done when:** a forward with an unregistered `issuer_id` gets `unregistered_issuer`, `mempool_size` is unchanged and the original `POST /documents` returns 403 (NF-TC-4.6, CN-TC-16.15); a registered issuer is accepted identically via primary and non-primary (NF-TC-4.1, 4.3); a malformed record with an unregistered issuer gets `invalid_record` and a registry spy records zero calls (NF-TC-4.7, CN-TC-16.24); unregistered issuer + bad signature gets `unregistered_issuer` (CN-TC-16.34); registered issuer + bad signature gets `invalid_record` → 422 (NF-TC-4.8); case/whitespace variants are rejected (NF-TC-4.10); a reject leaves no lock or mempool entry, and the channel stays open over repeats (NF-TC-4.11, 4.12); the result is identical with the exemption flag `true`/`false` (NF-TC-4.4); in PoW mode a block whose record issuer is unresolvable is rejected with `failure_type="signature"` on both the broadcast and sync paths, the tip is unchanged and `blocks_rejected_total{failure_type="signature"}` +1 per path (NF-TC-4.5); pre-signed bodies to public routes return 400 (NF-TC-4.2, 4.9); the checklist docs test passes on the real file and fails on fixtures with a missing row, a blank/TBD cell, a dangling reference, a missing mandatory record, a merged SEC3/SEC4 row, or an unlisted route (NF-TC-5.1…5.7, 5.9, 5.10, 5.12, 3.14, 4.14); the no-PII guard passes on the current schema and fails when `owner_name` is added to the record, the block, or a nested consensus sub-model, or when the cap is removed (NF-TC-6.1…6.7).
- **Pre-review:** **security** — check-4 placement in the handler order; PoW evidence path.

---

### Slice 32a: TLS 1.3 backend — `tls.py`, dev CA generator, outbound verification, insecure mode

- **Epic:** 6. **Depends on:** Slices 19, 31a (programmatic uvicorn start, fail-fast matrix), 31b (OWASP checklist exists). **Est.:** ~1–1.5 weeks.
- **Use cases:** E6-UC-7 (primary, A1, A2, A5, E1–E7, EC1, EC2, EC5, EC6); E6-UC-8 (A1, A3, E1–E7, EC1, EC3, EC4); E6-UC-9 (primary, A1, E1–E3, EC1, EC2, EC4); E6-UC-30-A1, E2 (`INSECURE_DEV_MODE` half), E4, E8 (TLS rows), EC2; E6-UC-5-EC1.
- **Test cases:** NF-TC-7.1…7.3, 7.6…7.15, 7.18, 7.19; NF-TC-8.2, 8.4…8.11, 8.15, 8.17, 8.18; NF-TC-9.1…9.7, 9.9; NF-TC-30.2, 30.6 (`INSECURE_DEV_MODE` half), 30.8, 30.12 (TLS rows), 30.14; NF-TC-5.8.
- **Files:** `docker/certs/gen_dev_certs.py` `[new]`, `src/node/tls.py` `[new]`, `src/node/main.py` (extend — calls the `tls.py` server `minimum_version` hook after `config.load()`), `src/node/config.py` (extend — `TLS_CERT`, `TLS_KEY`, `TLS_CA`, `INSECURE_DEV_MODE`), `src/node/network/connection_manager.py`, `src/node/sync.py`, `src/node/peers/registry.py`, `src/node/forwarding.py` (extend or verify — all outbound clients via the `tls.py` factory; gap G6), `.gitignore` (extend — generated keys), `docs/security/owasp_api_top10_checklist.md` (extend — API8 row), `tests/node/test_tls.py` `[new]` (live listeners), `tests/node/test_tls_static.py` `[new]`, `tests/node/test_insecure_mode.py` `[new]`, `tests/node/test_cert_generator.py` `[new]`, `tests/node/test_config_failfast.py` (extend — TLS rows)
- **Changes:** TLS provides confidentiality and **server** authentication only (no client certificates; node identity stays at the application layer via `NodeKeyPair` signatures). uvicorn is started programmatically and `config.ssl.minimum_version = TLSv1_3` is set after `config.load()` (`ssl_version`/`ssl_ciphers` cannot enforce TLS 1.3-only). Outbound clients (`websockets.connect(..., ssl=ctx)`, `httpx.AsyncClient(verify=ctx)`) verify against the dev CA — no `verify=False`. Plain-HTTP mode only via `INSECURE_DEV_MODE=true` with a loud boot warning. A static check asserts that no module under `src/node/**` other than `tls.py` builds an `SSLContext` or HTTP client (`attacks/`, `benchmarks/` and tests are exempt); the server-side `minimum_version` hook lives in `tls.py` and is called from `main.py`. Invalid `TLS_*` values fail startup (FR-23). Document that the dev CA is prototype-only. The generator takes `--nodes N` (4…10) and `--attackers NAMES`, emits SANs for compose service names and `localhost`, writes keys with mode `0600`, and supports fresh-CA and reuse modes. Only the literal `true` enables insecure mode. Error messages name the key and the constraint, never key contents. Multi-node TLS convergence is tested in-process (4 programmatic uvicorn nodes on temp certs); the compose rollout is Slice 32b.
- **Verify:** `python -m pytest tests/node/test_tls.py tests/node/test_tls_static.py tests/node/test_insecure_mode.py tests/node/test_cert_generator.py tests/node/test_config_failfast.py -v`
- **Done when:** against a live node started through `main.py`, a client with `maximum_version=TLSv1_2` (and TLS 1.1/1.0) is refused, and TLS 1.3 without a client certificate succeeds with a chain to the dev CA (NF-TC-7.1, 7.7, 7.8, 7.18); a non-programmatic start fails the live-listener test (NF-TC-7.19); plain HTTP to the TLS port yields no HTTP response, and with the flag unset no plain listener exists and outbound `ws://` is refused (NF-TC-7.9, 7.10, 9.1, 9.3, 9.4); an in-process 4-node network converges over `wss://` in PoW and in PBFT including `forward_record` (NF-TC-7.2, 7.3); outbound clients reject self-signed, foreign-CA, SAN-mismatch, raw-IP, expired and new-CA certificates (NF-TC-7.12…7.15, 8.5, 8.11, 8.17); a CA-signed attacker-named cert completes TLS but is denied at the application layer (`not_validator`) (NF-TC-7.6, 8.6, 8.15); static checks fail on positive-control fixtures and pass on the tree: SSLContext/HTTP/WS clients only in `tls.py` under `src/node/**`, and no `verify=False`/`CERT_NONE`/`check_hostname=False`/`http://`/`ws://` literals outside the insecure branch, no `ssl_version`/`ssl_ciphers` (NF-TC-7.11, 8.9, 8.10, 9.9); generator output for n = 4, 7, 10 + attacker names has exactly those names and non-colliding files (NF-TC-8.2, 8.4); `git ls-files` lists no `*.key`/private `*.pem` and the tracked-fake-key control fails (NF-TC-8.8); `INSECURE_DEV_MODE=true` boots plain with exactly one warning, and `yes`/`1`/`True `/empty never enable it (NF-TC-9.2, 9.5, 9.7, 30.2, 30.6); each `TLS_*` missing/unreadable/unparseable/mismatched exits non-zero naming the key without printing key bytes (NF-TC-8.7, 30.8, 30.14); a mixed insecure node is partitioned (NF-TC-9.6); the OWASP API8 row cites `INSECURE_DEV_MODE`, `proxy_headers=False`, single worker and XFF (NF-TC-5.8); dev CA documented as prototype-only (NF-TC-8.18).
- **Pre-review:** **security** + **architect** — no-mTLS decision, uvicorn `minimum_version` mechanism, single client factory, no downgrade path.

---

### Slice 32b: TLS rollout in compose — per-service key/cert volumes, Prometheus https, attacker, SPA https

- **Epic:** 6. **Depends on:** Slices 22 (SPA), 24 (attacker image), 30 (Prometheus), 31a (`client.ts` status handling), 32a. **Est.:** ~1 week.
- **Use cases:** E6-UC-2 (primary https part, A3, E2); E6-UC-7-A3, A4, EC3; E6-UC-8 (primary, A2, E8, E9, E10); E6-UC-9-EC3; E6-UC-10-E4, E6, E7; E6-UC-29 (primary — HTTPS part, A3, A4, E3, E4, E6).
- **Test cases:** NF-TC-2.1 (https re-assertion), 2.4, 2.6; NF-TC-7.4, 7.5, 7.16; NF-TC-8.1, 8.3, 8.12, 8.13, 8.14; NF-TC-9.8; NF-TC-10.7, 10.9, 10.10; NF-TC-29.1 (HTTPS part), 29.4, 29.5, 29.11, 29.12, 29.14.
- **Files:** `docker-compose.yml` (extend — one-shot cert/key init service as sole holder of `ca.key`, one named key/cert volume or `subpath` per service, CA cert `:ro`, `https`/`wss` URLs), `docker/node.Dockerfile` (extend — cert mount points), `docker/attacker.Dockerfile` (extend — trusts dev CA, own cert volume), `docker/prometheus.yml` (extend — `scheme: https`, `tls_config.ca_file`, `server_name`), `attacks/harness/` (extend — the modules that open HTTP/WS clients trust `TLS_CA`), `web/src/api/client.ts` (extend — configurable `https://` base URL, TLS/connection errors surfaced as connection problems), `tests/node/test_compose_smoke.py` (extend — TLS on, both modes), `tests/infra/test_compose_static.py` (extend — key-volume, `ca.key`, bind-mount, `INSECURE_DEV_MODE`, `insecure_skip_verify` rules), `tests/infra/test_key_isolation.py` `[new]` (`@pytest.mark.docker`), `web/src/__tests__/clientHttps.test.ts` `[new]`
- **Changes:** Init service runs `gen_dev_certs.py` once and copies each service's key + cert into that service's own volume plus the CA certificate. `ca.key` stays only in the init volume / operator host. Each service mounts only its own volume plus the CA cert read-only; there are no bind mounts for keys/certs. Prometheus scrapes https with CA + `server_name`; Grafana→Prometheus stays plain HTTP inside compose (documented out of scope). The attacker container gets its own CA-signed cert (insider model). Ownership/UID/mode hardening of these volumes is Slice 33a.
- **Verify:** `python -m pytest tests/infra/test_compose_static.py -v; npm --prefix web run test -- clientHttps; docker compose up -d --build; python -m pytest tests/node/test_compose_smoke.py tests/infra/test_key_isolation.py tests/infra/test_monitoring_stack.py -m docker -v; docker compose down -v`
- **Done when:** the Slice 19 smoke test passes with TLS on in PoW and PBFT, and the Epic 5 harness runs against the TLS network (NF-TC-7.16, 8.3); Prometheus shows ≥4 node targets `up` over https, while removing the CA or using a wrong `server_name` yields `up=0` with a TLS error (NF-TC-2.1, 2.6, 7.5); the SPA issues and verifies a document over HTTPS against the compose network, and vitest shows a base-URL switch with no code change, while `http://` against a TLS-only node and an untrusted CA render as connection errors, never verification results (NF-TC-7.4, 29.1, 29.4, 29.11, 29.12); from inside the attacker container every `node*` key (Node/Issuer/TLS) and `ca.key` read fails, node1 sees no foreign key, and writing to the CA cert mount fails (NF-TC-8.14, 10.9, 29.5); compose static checks fail on fixtures with `ca.key` in any runtime container, a keys volume shared without distinct `subpath`, a writable CA mount, a key bind mount, a committed `INSECURE_DEV_MODE=true`, or `insecure_skip_verify` outside insecure config — and pass on the committed files (NF-TC-8.12, 8.13, 9.8, 10.7, 10.10, 29.14, 2.4, 2.6); the init service output matches NF-TC-8.1.
- **Pre-review:** **security** — per-service key isolation, `ca.key` placement, attacker cert scope.

---

### Slice 33a: Container hardening (non-root, read-only) + CI baseline (ruff, mypy, coverage, Trivy)

- **Epic:** 6. **Depends on:** Slices 19, 24, 31b (no-PII guard in CI), 32a (static TLS checks in CI), 32b (per-service volumes to harden), 34 (bench smoke in CI). **Est.:** ~1–1.5 weeks.
- **Use cases:** E6-UC-10 (primary, A1, A2, E1, E2, E3, E5, EC1, EC2, EC4, EC5); E6-UC-8-EC2; E6-UC-13 (primary, A1–A3, E1–E4, EC1–EC3); E6-UC-14 (primary, A1, A2, E1–E4, EC1–EC3); E6-UC-29-E5 (and the non-root clause of E6-UC-29 primary); E6-UC-5-EC4.
- **Test cases:** NF-TC-10.1…10.6, 10.8, 10.11, 10.12, 10.14, 10.15; NF-TC-8.16; NF-TC-13.1…13.11; NF-TC-14.1…14.10; NF-TC-29.13; NF-TC-5.11.
- **Files:** `docker/node.Dockerfile` (extend — non-root `USER`, digest-pinned `FROM`, chowned volume dirs, `PYTHONDONTWRITEBYTECODE=1`), `docker/attacker.Dockerfile` (extend likewise), `docker-compose.yml` (extend — `read_only: true`, tmpfs `/tmp`, init-service chown/mode step), `docker/certs/gen_dev_certs.py` (extend — delivery sets owner UID and `0600`, never overwrites existing keys), `.github/workflows/ci.yml` `[new]`, `pyproject.toml` (extend — `pytest-cov`, coverage config, `docker` marker), `tests/node/test_container_user.py` `[new]` (`@pytest.mark.docker`), `tests/infra/test_compose_static.py` (extend — read-only/tmpfs rules), `tests/infra/test_ci_config.py` `[new]`, `tests/test_layering.py` (extend — forbid `prometheus_client`/`uvicorn`/`httpx` in `blockchain_core`), `docs/security/owasp_api_top10_checklist.md` (extend — API1/API5 rows), `README.md` (extend — root→non-root volume migration)
- **Changes:** Node image runs as an unprivileged UID; chain, snapshot, key and cert volumes are **named volumes** (Docker Desktop bind mounts from Windows are root-owned and give no rename/fsync guarantees) owned by the node UID via the one-shot init service introduced in Slice 32b (this slice owns the UID/`chown`/mode step, not the per-service volume layout). CI jobs: `ruff`, `mypy`, `pytest --cov=src/blockchain_core --cov-fail-under=80`, frontend `vitest` + build, `trivy image` on the node image failing on any CRITICAL (vulnerability DB cached, base image pinned by digest; a CRITICAL with no upstream fix blocks CI until the base image is re-pinned — accepted risk). Trivy gates only the node image. Forbid `prometheus_client`/`uvicorn`/`httpx` in `blockchain_core` via the static import check (`tests/test_layering.py`). CI has two jobs: `quality` (ruff, mypy, `pytest -m "not docker" --cov=src/blockchain_core --cov-fail-under=80`, vitest + build) and `image` (build node image from the digest-pinned base, restore the Trivy DB cache, `trivy image --severity CRITICAL --exit-code 1`, then `pytest -m docker` for container-user and key-isolation tests). No `.trivyignore`, no `--ignore-unfixed`. No gate needs secrets.
- **Verify:** `python -m pytest tests/infra/test_ci_config.py tests/test_layering.py -v; python -m pytest -m "not docker" --cov=src/blockchain_core --cov-fail-under=80; docker compose up -d --build; python -m pytest tests/node/test_container_user.py -m docker -v; trivy image --severity CRITICAL --exit-code 1 <node-image>; docker compose down -v`
- **Done when:** `docker compose exec node1 id -u` and `docker compose exec attacker id -u` print non-zero, and the test fails on a root control image (NF-TC-10.1, 10.2, 10.4, 29.13); `touch /app/x` fails with a read-only error and no `.pyc` is created; only the named volumes and `/tmp` are writable, and `/tmp` is not persisted across restart (NF-TC-10.8, 10.11, 10.15); key files are `0600` owned by the node UID, or skipped with a recorded reason on non-POSIX filesystems (NF-TC-8.16, 10.3, 10.6); a root-owned persistence volume makes the node exit with a permission error (NF-TC-10.5); re-running init changes no ownership, overwrites no key and never copies `ca.key` (NF-TC-10.14); `test_ci_config.py` asserts the workflow contains every gate (coverage scoped to `src/blockchain_core`, `--cov-fail-under=80`, bench smoke, static checks, Trivy CRITICAL exit-code 1 on the node image only, digest-pinned `FROM`, no ignore options) and fails on fixtures violating each (NF-TC-13.1…13.4, 13.10, 14.1, 14.3, 14.5, 14.7, 14.10); each negative case (79.9 % coverage, ruff violation, mypy error, failing test, CRITICAL fixture image, DB download failure) is demonstrated once on a throwaway branch with a red run and 80.0 % on a green run, with run links recorded in the commit/PR notes (NF-TC-13.5…13.9, 14.4, 14.6, 14.8, 14.9); a fork-PR run executes all gates without secrets (NF-TC-13.11); CI is green on the branch head with Trivy 0 CRITICAL (NF-TC-14.1, 14.2); OWASP API1/API5 rows cite the insider model and per-service key isolation (NF-TC-5.11).
- **Pre-review:** **security** + **architect** — key permissions under a non-root UID, Trivy policy, docker-marked CI job split.

---

### Slice 33b: Periodic chain snapshots — copy under `ChainState` lock, atomic write, restore

- **Epic:** 6. **Depends on:** Slices 8 (store/serializer), 16a (`ChainState`, frozen blocks), 16b (sync for restore-then-sync), 33a (named, non-root snapshot volume). **Est.:** ~1 week.
- **Use cases:** E6-UC-11 (primary, A1–A3, E1–E7 (E7 = Epic 6 three-way extension), EC1–EC6); E6-UC-12 (primary, A1–A3, E1–E7, EC1–EC5); E6-UC-10-EC3; E6-UC-30-E3, E8 (snapshot rows — matrix complete), A2 (all defaults complete).
- **Test cases:** NF-TC-11.1…11.17, NF-TC-12.1…12.16, NF-TC-10.13, NF-TC-30.7, NF-TC-30.3 (completed), NF-TC-30.12 (completed).
- **Files:** `src/node/chain_state.py` (extend — `snapshot_copy()` under the existing lock, no new lock), `src/blockchain_core/storage/snapshot.py` `[new]` (pure; block list + destination; reuses the Slice 8 serializer), `src/node/snapshot_task.py` `[new]`, `src/node/main.py` (extend — start the task only after `ChainState` init), `src/node/config.py` (extend — `SNAPSHOT_INTERVAL_MIN`, `SNAPSHOT_DIR`, `SNAPSHOT_KEEP`), `docker-compose.yml` (extend — snapshot named volume per node), `tests/core/test_snapshot.py` `[new]`, `tests/node/test_snapshot_task.py` `[new]`, `tests/node/test_snapshot_restore.py` `[new]`, `tests/node/test_config_failfast.py` (extend — snapshot rows), `tests/test_layering.py` (extend — `snapshot.py` imports), `README.md` (extend — restore procedure for a stopped node)
- **Changes:** Invalid `SNAPSHOT_*` values fail startup (FR-23). The snapshot task takes `ChainState`'s lock **only to copy the in-memory block list**, releases it, then writes off the event loop (`asyncio.to_thread`) — it never copies the chain-store file, so keys are excluded by construction and P3 is not stalled. Snapshot format = chain-store format, so restore is "copy into the chain-store path, then normal Slice 8 load + validation". Atomic write: temp file in `SNAPSHOT_DIR` with a prefix retention ignores, fsync file, `os.replace`, directory fsync on POSIX only, unique names by height + counter, Windows `PermissionError` ⇒ retry next cycle; crashes are simulated by fault injection in the write function. Retains newest `SNAPSHOT_KEEP`. Extend the Slice 11 static import check to cover `snapshot.py`. Restore = copy into the chain-store path of a stopped node, then the normal Slice 8 load + FR-6 validation; there is no snapshot-specific loader.
- **Verify:** `python -m pytest tests/core/test_snapshot.py tests/node/test_snapshot_task.py tests/node/test_snapshot_restore.py tests/node/test_config_failfast.py tests/test_layering.py -v`
- **Done when:** a timer tick produces a uniquely named snapshot that loads and passes FR-6 and contains no key file names or key marker bytes, and the chain-store file is never opened (NF-TC-11.1, 12.1, 12.7); the lock is held only for the copy — a heartbeat keeps ticking and a concurrent append is not blocked (NF-TC-11.8); append during serialisation → snapshot is exactly blocks 0..H; append + replace + snapshot together → the live chain is valid and the snapshot is wholly old or wholly new (NF-TC-11.7, 11.11, 11.15, 12.11); mutating a live block after the copy does not change the snapshot, and the shallow-copy control fails (NF-TC-11.10); `SNAPSHOT_KEEP=3` over 5 cycles leaves 3, `KEEP=1` never leaves zero, and temp files are never counted, pruned or loaded (NF-TC-11.3, 11.12, 12.12, 12.13); fault injection between write and `os.replace` leaves the previous snapshot byte-identical, and the next cycle succeeds (NF-TC-12.5); `PermissionError` on replace and an unwritable/full dir skip the cycle without crashing (NF-TC-11.6, 11.9, 12.9); dir fsync only on POSIX (NF-TC-12.10); a tampered snapshot fails with `hash`/`merkle` and a truncated one with a structural error, neither adopted (NF-TC-12.6, 12.8); a PBFT snapshot validates `commit_signatures` (NF-TC-12.3); restore at 900 on a 1 000-block network reaches the tip via paginated `GET /chain` (NF-TC-12.2); invalid `SNAPSHOT_*` values exit non-zero naming the key, and the full fail-fast matrix has a row for every config key (NF-TC-11.5, 30.7, 30.12, 30.3); `snapshot.py` imports no node config/`asyncio`/`prometheus_client`, and `snapshot_task.py` defines no lock of its own (NF-TC-11.4, 11.17, 12.4); a snapshot succeeds on the non-root named volume in compose (NF-TC-10.13).
- **Pre-review:** **architect** + **security** — lock scope and off-loop I/O, restore path, key exclusion by construction.

---

### Slice 35a: NFR measurement — load campaigns (P1, P2, P3, S1 end-to-end) and load-generator validity

- **Epic:** 6. **Depends on:** Slices 17b (forward round-trip), 30 (histogram cross-check), 31a (limiter + bench override), 32b (TLS network, dev CA for k6), 34 (harness/CSV). **Est.:** ~1.5 weeks (at the threshold). Rows here may be indicative; headline rows are re-run in 35b.
- **Use cases:** E6-UC-19 (primary, A1–A3, E1–E6, EC1–EC3); E6-UC-20 (primary, A1, A2, E1–E3, EC1–EC3); E6-UC-21 (primary, A1–A3, E1–E6, EC1–EC4); E6-UC-22 (primary, A1, E1–E4, EC1–EC4); E6-UC-23 (primary, A1, E1–E3, EC1–EC3); E6-UC-7-EC4.
- **Test cases:** NF-TC-19.1…19.13, NF-TC-20.1…20.9, NF-TC-21.1…21.14, NF-TC-22.1…22.10, NF-TC-23.1…23.8, NF-TC-7.17.
- **Files:** `benchmarks/load/k6_verify.js` `[new]`, `benchmarks/load/k6_submit.js` `[new]` (`constant-arrival-rate`), `docker-compose.bench.yml` `[new]` (`k6` service with own `cpuset`, CA cert `:ro`, `RATE_LIMIT_PER_MIN=100000`), `benchmarks/run_metadata.py` `[new]` (TLS on, metrics on, limit value, cpuset, executor, node set), `benchmarks/bench_load.py` `[new]` (k6 summary → rows; invalid-run rules: any 429, error rate, achieved RPS below target, reused hash, closed-loop script), `benchmarks/bench_pbft_finalization.py` `[new]`, `benchmarks/bench_e2e_throughput.py` `[new]`, `tests/benchmarks/test_load_harness.py` `[new]`, `tests/benchmarks/test_pbft_finalization.py` `[new]`, `tests/infra/test_bench_compose_static.py` `[new]`
- **Changes:** Configuration fixed by the thesis: n = 4, f = 1, one host, docker-compose. The protocol (consensus mode per NFR, P3 statistic and interval, load model, rate-limit override, R2 definition) is frozen **before** any headline run. Headline P1/P2/S1 are in **PBFT** mode; PoW rows are optional and annotated (4 miners share host CPU; S1 capped at block_interval × 256). (1) `GET /documents/{hash}` at 200 RPS (open-loop arrival rate, achieved RPS recorded) on one node for ≥60 s with `RATE_LIMIT_PER_MIN` raised via the bench override (limiter stays in the measured path) — record p50/p95/p99. (2) `POST /documents` at 50 RPS, measure acceptance latency up to queueing; report primary-received, non-primary-received (includes the `forward_record` round-trip) and overall rows; record that forwarding travels over WS `forward_record`, so the per-IP HTTP limit is not hit by forwarded requests. (3) PBFT finalization time (pre-prepare → local commit quorum, all correct nodes) from `GET /metrics/consensus` over ≥100 blocks. Preflight aborts when the effective limit is below the offered rate or `RATE_LIMIT_EXEMPT_VALIDATORS=true`. P2 always writes three rows (primary-received, non-primary-received including the `forward_record` round-trip, overall) with traffic shares; an empty group is `n/a`, never omitted. P3 = p95 of pre-prepare → local commit quorum over all correct nodes, ≥100 blocks under S1 load, with JSON/Prometheus counts cross-checked. PoW S1 row carries 256 / 10 s = 25.6 rec/s and "mode limit, not a target change". Static check: k6 is the only load tool.
- **Verify:** `python -m pytest tests/benchmarks/test_load_harness.py tests/benchmarks/test_pbft_finalization.py tests/infra/test_bench_compose_static.py -v; docker compose -f docker-compose.yml -f docker-compose.bench.yml up -d --build; docker compose -f docker-compose.yml -f docker-compose.bench.yml run --rm k6 run /scripts/k6_verify.js; docker compose -f docker-compose.yml -f docker-compose.bench.yml run --rm k6 run /scripts/k6_submit.js; python -m benchmarks.bench_pbft_finalization --blocks 100; python -m benchmarks.bench_e2e_throughput --mode pbft; docker compose -f docker-compose.yml -f docker-compose.bench.yml down -v`
- **Done when:** harness tests with stubbed k6 summaries pass — an injected 429 invalidates the run, a closed-loop script and a non-k6 tool are rejected, achieved RPS below target is flagged, a P2 write without the role split is refused, and a P3 verdict is computed from p95 only (NF-TC-19.5…19.9, 20.5…20.9, 21.6…21.10, 22.6, 22.7); bench-compose static checks pass (100 000 only in the override, default compose untouched, k6 `cpuset` set, CA `:ro`, no node keys/`ca.key`) (NF-TC-19.2, 19.10, 19.11); `results/nfr_measurements.csv` contains one complete run each for P1 (`mode=pbft`, p50/p95/p99, `achieved_rps`), P2 (three rows), P3 (p95, batch size, sample count, view changes), S1 end-to-end PBFT, and the annotated PoW S1 row, all nine columns populated; every run has a metadata file recording TLS on, metrics on, limit value, cpuset and executor (NF-TC-7.17, 19.1, 19.12).
- **Pre-review:** **architect** — freeze the measurement protocol (statistics, intervals, load model, invalid-run rules) before the first run.

---

### Slice 35b: NFR measurement — scale, fault tolerance, recovery, final headline re-run, NFR report (**Epic 6 gate**)

- **Epic:** 6. **Depends on:** Slices 33a, 33b (snapshot-restore supplementary R2 row), 35a (and transitively all of 30–34). **Est.:** ~1.5 weeks of work plus unattended run time.
- **Use cases:** E6-UC-24 (primary, A1, A2, E1–E3, EC1–EC4); E6-UC-25 (primary, A1, E1–E3, EC1–EC3); E6-UC-26 (primary, A1, A2, E1–E4, EC1–EC3); E6-UC-27 (primary, A1–A3, E1–E5, EC1–EC3); E6-UC-28 (primary, A2, A3, E1, E2, E3, E5, EC1, EC3); E6-UC-2-A1; E6-UC-4-EC6 (report half).
- **Test cases:** NF-TC-24.1…24.10, NF-TC-25.1…25.8, NF-TC-26.1…26.10, NF-TC-27.1…27.12, NF-TC-28.1, 28.3…28.7, 28.9, 28.11, 28.13, NF-TC-2.2.
- **Files:** `benchmarks/gen_scale_compose.py` `[new]` (n = 4…10: compose, `validators.json`, cert names, Prometheus targets), `docker-compose.scale.yml` `[new]` (generated, committed for n = 10), `benchmarks/bench_scale.py` `[new]`, `benchmarks/bench_fault_tolerance.py` `[new]`, `benchmarks/bench_recovery_sync.py` `[new]`, `benchmarks/check_headline.py` `[new]` (headline consistency against `targets.HEADLINE_IDS` and the final commit), `docs/results/nfr_report.md` `[new]`, `tests/benchmarks/test_scale_config.py` `[new]`, `tests/benchmarks/test_recovery_harness.py` `[new]`, `tests/docs/test_nfr_report.py` `[new]`, `results/nfr_measurements.csv` (headline rows appended)
- **Changes:** (4) Start the same stack with n = 4, 7, 10 (config only, no code change) and confirm a document submitted to node 1 is finalized on all nodes in both modes. (5) Stop a node after 1 000 blocks (PBFT mode or a pre-generated fixture chain — 1 000 PoW blocks at 10 s is ~2.8 h), restart it, and time convergence to the network tip. (6) Re-run the f-fault check for each n (kill ⌊(n−1)/3⌋ nodes, still finalizes). `nfr_report.md` lists every NFR from Table 1.5 with target, measured value, pass/fail, and a note on any miss and its cause — a missed target is reported honestly and discussed in Chapter 3, not hidden. Then a final headline re-run at the hardened commit on a clean tree: P1, P2 (×3), P3, P4, P5, S1 (batching + end-to-end), S2, R1, R2 with `headline=true`, while earlier rows are demoted. `check_headline.py` rejects headline rows from another commit, from a `-dirty` tree, or from runs whose metadata lacks TLS/metrics/limiter; it also rejects a non-eligible headline row (PBFT-fixture P5, PoW S1) and a missing ID. The report docs test counts the 19 IDs, verifies each value equals the latest headline CSV row and commit, and checks the annotations, caveats and SEC3/SEC4 statements.
- **Verify:** `python -m pytest tests/benchmarks/test_scale_config.py tests/benchmarks/test_recovery_harness.py -v; python -m benchmarks.bench_scale --sizes 4 7 10 --modes pow pbft; python -m benchmarks.bench_fault_tolerance --sizes 4 7 10; python -m benchmarks.bench_recovery_sync --blocks 1000; python -m benchmarks.check_headline --final-commit HEAD; python -m pytest tests/docs/test_nfr_report.py -v`
- **Done when:** generated configs for n = 4, 7, 10 are internally consistent (names, ports, SANs, n/f = 4/1, 7/2, 10/3, Prometheus targets) without starting containers, and a forced collision fails clearly (NF-TC-24.6, 24.7, 24.10); S2 rows exist for each n × mode with a document finalized on every node and the diff limited to generated config (NF-TC-24.1…24.5); R1 rows exist for each n with ⌊(n−1)/3⌋ nodes stopped, including a stopped-primary case, and the negative control with one more node stopped does not finalize and produces no conflicting block (NF-TC-25.1…25.4); the R2 row records the approach, block gap and convergence time vs 30 s, plus the supplementary snapshot row (NF-TC-26.1…26.3); Prometheus scrapes all generated targets at n = 7 and 10 (NF-TC-2.2); `check_headline.py` exits 0 — every ID in `HEADLINE_IDS` has exactly one `headline=true` row at the final clean commit with TLS/metrics/limiter on — and exits non-zero on fixtures with a stale commit, a `-dirty` tree, a disabled control, an ineligible headline row or a missing ID (NF-TC-28.1, 28.3…28.7, 28.9, 28.11, 28.13); `tests/docs/test_nfr_report.py` passes: all 19 IDs present with an unchanged target, a measured value equal to the latest headline row, pass/fail and evidence, misses with cause notes, SEC3 mode-independent, SEC4 stating PBFT + PoW evidence, caveats (single host, TLS on, metrics on, raised limit, achieved RPS), and it fails on the 18-ID, missing-evidence and headline=false-citation fixtures (NF-TC-27.1…27.12).
- **Pre-review:** **architect** — headline-consistency rules and the report template, before the final re-run.

---

## Review notes

Conflicts and open points found while merging the tech-lead review (planner text preferred where the two conflicted):

1. **Epic 6 header decisions superseded by the planner:** `ChainState` is now introduced in Slice 16a (was "Slice 16"), the snapshot copy is added in Slice 33b (was "Slice 33"), the `IssuerRegistry` check and `unregistered_issuer` reply are Slice 31b (was "Slice 31"). All other binding decisions are unchanged.
2. **Volume ownership (gap G7):** the old Slice 32 and Slice 33 both claimed the init service and per-service key/cert volumes. Resolved as 32b owns the volumes, init service and isolation tests; 33a owns UID/`chown`/`0600`, read-only root and tmpfs. The 33a Changes sentence was reworded accordingly instead of copied verbatim.
3. **Slice 34 position:** Slice 34 is listed before Slice 30 in section 3 and section 5 (number unchanged) because 33a needs it (bench smoke in CI). Its dependencies are now 9, 11, 14 (old plan: 9, 14).
4. **Headline eligibility wording:** Slice 34 says only the 10 000-block P5 row and the PBFT-mode S1 row are headline-eligible, while its own S1 batching row is a core-level measurement (`mode=core`) and Slice 35b lists "S1 (batching + end-to-end)" as headline. The planner text is kept verbatim; the architect should confirm which S1 rows carry `headline=true`.
5. **Slice 13 fallback split:** the planner mentions an optional "Slice 13b" (forwarder contract) if Slice 13 overruns. It is not added to section 5; if used, 17b would depend on 13b.
6. **Estimates above the 1.5 week threshold:** Slice 17 (~2 weeks, accepted, not split). At the threshold: 13, 16b, 35a, 35b.
7. **Architect verdict for Epic 6 (gap G16):** rounds 1-3 returned FAIL; the planner could not verify a later verdict, so none is recorded in section 1. The orchestrator must record it.
8. **Gaps owned by other files (not edited here):** G1/CN-TC-16.34 (owned by Slice 31b), G2 (E6-UC-15-EC5 column names), G10 (NF-TC-2.1 split into http/https), G11 (NF-TC-29.1 split), G14 (CN-TC-15.26 fixture wording). The plan references the resulting IDs as the planner does; NF-TC-2.1 and NF-TC-29.1 are cited in two slices each until QA splits them.
9. **Slice 15 addition (gap G5):** the single FR-25 validation entry point is named `src/node/validation_gateway.py` `[new]` in Slice 15; the planner proposed the name as an example, so the architect may adjust it.
10. **Old Epic 5 sentence:** the old Slice 32 sentence that Epic 5 findings must state that attackers hold CA-signed certificates now lives in D2 (NF-TC-29.17) instead of Slice 32a.

---

### D2 (Deliverable, not a TDD slice): Epic 5 written findings summary

- **Epic:** 5. **Depends on:** Slice 29, Slice 32b (insider-model statement), and Slice 35b if the NFR results are to be cited in the same chapter. **Est.:** ~1 week of writing.
- **Use cases:** E5-UC-8 (+E1, EC1). **Test cases:** AT-TC-8.1…8.5; NF-TC-29.17.
- **Files:** `docs/results/findings.md` `[new]`, `README.md` (extend — link the results and how to reproduce them)
- **Changes:** A thesis-ready results chapter mapping attack type → outcome → consensus mode for every completed scenario; an explicit cross-reference of D1's theoretical expectations against the measured results, including any contradiction discussed rather than smoothed over; an explicit statement that PoW's hash-power-share metric and PBFT's seat-fraction metric are measured on **different axes and are not comparable node-for-node**; crash-fault (liveness) and Byzantine-fault (safety) findings reported as **distinct classes**; an explicit statement of any under-tested mode rather than overstated confidence. Embed the Slice 29 charts.
- **Verify:** `grep -E "hash-power share|ValidatorSet seat fraction|not directly comparable|crash|Byzantine" docs/results/findings.md`
- **Done when:** the file exists, contains the attack-type → outcome → mode mapping for every scenario run, contains the verbatim non-comparability statement, reports crash and Byzantine findings under separate headings, references both generated charts (AT-TC-8.1…8.5), and states that attackers hold CA-signed certificates and that TLS admission of attackers is not under test (NF-TC-29.17). **Epic 5 — and the project — is done when this exists and every PRD acceptance box in §§1–5 is ticked.**
- **Pre-review:** none.

---

## 4. Acceptance criteria (project-level "done")

- [ ] `docs/research/epic1_blockchain_comparison.md` contains a ≥2-system × 5-dimension comparison table and ≥3 design decisions traced to research findings (PRD §1).
- [ ] Two independently started nodes compute an identical genesis `block_hash` from shared constants alone (PRD §2, C-1).
- [ ] N document hashes in one block produce one Merkle root and N independently verifiable inclusion proofs (PRD §2).
- [ ] Tampering any block field, at any position including the tip, is detected with the correct `failure_type` and the correct first-failing index; tip-block tampering with a recomputed `block_hash` is caught by `proposer_signature` (PRD §2, M-1).
- [ ] Chain state, `IssuerKeyPair`, and `NodeKeyPair` survive a restart and reload to an identical, verifiable state (PRD §2).
- [ ] A PoW block whose declared difficulty ≠ the network's `expected_difficulty` is rejected with `"difficulty"`; a PBFT block below 2f+1 distinct commit signatures is rejected with `"quorum"` — on the proposal path, the sync path, and the `GET /node/info` cache path identically (PRD §2/§3, FR-24/FR-25).
- [ ] A ≥4-node docker compose network starts, logs `ValidatorSet`/`IssuerRegistry` per node, and propagates a document submitted to one node to all others, in **both** PoW and PBFT modes (PRD §3).
- [ ] Under PBFT n=4: stopping 1 node keeps finalizing; stopping 2 reports **crash-fault** quorum loss; an equivocating validator is reported as a **Byzantine** event — the two are never conflated (PRD §3, M-9).
- [ ] Registering arbitrarily many `PeerInfo` peers never changes the PBFT quorum threshold (PRD §3, C-4).
- [ ] A divergent incoming chain triggers full from-genesis revalidation, not incremental (PRD §3, M-14).
- [ ] Every REST error uses the `{"error": {code, message, details}}` envelope; hash fields are validated against `^[0-9a-f]{64}$`; oversized metadata is rejected; `GET /chain` is always bounded (PRD §3, M-11/FR-18).
- [ ] `GET /node/info` returns all nine fields and its latency does not scale with chain length (PRD §3, FR-26).
- [ ] The UI can issue a document (unsigned submission, node-side signing) and show it confirmed with a block index on both networks; can verify an unmodified document as valid; shows an altered document as **invalid** (not "not found"); renders ≥5 blocks and flags a corrupted block; switches nodes without a page reload (PRD §4).
- [ ] The browser never generates, holds, or transmits issuer private-key material or a signature (PRD §4, hard constraint).
- [ ] ≥1 successful and ≥1 unsuccessful Sybil run recorded per consensus mode, on the correct per-algorithm metric axis (PRD §5).
- [ ] The attacker component is a separate build artifact with zero attacker-mode conditionals in the honest-node image (PRD §5, M-13).
- [ ] Tamper detection is verified against a separately stored, out-of-band trusted public key, never the attacked node's key-store (PRD §5, M-2).
- [ ] ≥2 comparison charts exist, with PoW and PBFT Sybil thresholds on **separate panels** (PRD §5, M-8).
- [ ] `docs/results/findings.md` exists with the non-comparability statement and distinct crash/Byzantine reporting (PRD §5).
- [ ] Every node exposes Prometheus metrics (chain height, connections, consensus time) and the compose stack includes working Prometheus + Grafana (Slices 30, 32b, Chapter 1 §1.5.2).
- [ ] Rate limit 100 req/min/IP, typed `unregistered_issuer` reply on `forward_record` (PBFT) / block-level rejection (PoW), OWASP API Top 10 checklist filled, and no-PII schema guard green (Slices 31a, 31b; NFR-SEC3/SEC4/C1).
- [ ] REST and WebSocket traffic requires TLS 1.3; TLS 1.2 is refused (Slices 32a, 32b; NFR-SEC2).
- [ ] Node containers run as non-root, snapshots run every 60 min, CI is green with core coverage ≥80 % and Trivy 0 CRITICAL (Slices 33a, 33b; NFR-I1/I2/I3/M1).
- [ ] `docs/results/nfr_report.md` reports a measured pass/fail for NFR-P1…P5, S1, S2, R1, R2 against Table 1.5 targets, honestly including any misses (Slices 34, 35a, 35b).

---

## 5. Dependency order and optional interleaving

| # | Slice | Hard dependencies |
|---|---|---|
| D1 | Epic 1 research | — |
| 1 | Scaffold + canonical serialization | — (informed by D1) |
| 2 | Keys, signatures, DocumentRecord | 1 |
| 3 | Merkle tree + proofs | 1, 2 |
| 4 | Block structure + batch build | 3 |
| 5 | Genesis + chain append | 4 |
| 6 | Chain validation — core checklist | 5 |
| 7 | Chain validation — PoW/PBFT checks | 6 |
| 8 | Persistence | 7 |
| 9 | Tamper-detection suite (**Epic 2 gate**) | 8 |
| 10 | Node skeleton, config, registries, envelope | 9 |
| 11 | Key resolver, validity cache, `/node/info` | 10 |
| 12 | Peers REST + paginated `/chain` | 11 |
| 13 | `/documents` submit + lookup + `RecordForwarder` contract | 12 |
| 14 | PoW engine + metrics | 13 |
| 15 | WebSocket layer + inbound authentication (names the single FR-25 validation entry point `validation_gateway.py`) | 14 |
| 16a | `ChainState` — single owner, one lock, retrofit of append paths | 15 |
| 16b | Chain sync + fork resolution | 16a |
| 17 | PBFT three-phase protocol | 16b |
| 18 | PBFT view-change + fault classification | 17 |
| 17b | `forward_record` channel (non-primary → primary) | 13, 16a, 17, 18 |
| 19 | docker compose network (**Epic 3 gate**) | 17b |
| 20 | React scaffold + badge | 19 |
| 21 | Issue page | 20 |
| 22 | Verify page | 21 |
| 23 | Chain visualization (**Epic 4 gate**) | 22 |
| 24 | Attacker image + results recorder | 19 |
| 25 | Sybil vs. PoW | 24 |
| 26 | Sybil vs. PBFT | 25 |
| 27 | Tampering — store mutation | 24 (+9) |
| 28 | Tampering — block injection | 27 |
| 29 | Thresholds + charts | 25, 26, 27, 28 |
| 34 | NFR measurement — core level (harness, P5, S1 batching, P4); listed before 30 because 33a needs its bench smoke in CI | 9, 11, 14 |
| 30 | Prometheus export + Prometheus/Grafana | 14, 19 |
| 31a | Rate limit, SPA status handling, rate-limit config fail-fast | 13, 15, 17b, 22, 30 |
| 31b | Unregistered-issuer reject, OWASP checklist, no-PII | 17b, 30, 31a |
| 32a | TLS 1.3 backend (`tls.py`, dev CA, outbound verification, insecure mode) | 19, 31a, 31b |
| 32b | TLS rollout in compose (per-service volumes, Prometheus https, attacker, SPA https) | 22, 24, 30, 31a, 32a |
| 33a | Non-root/read-only containers + CI (ruff, mypy, coverage, Trivy) | 19, 24, 31b, 32a, 32b, 34 |
| 33b | Periodic snapshots + restore | 8, 16a, 16b, 33a |
| 35a | NFR load campaigns (P1, P2, P3, S1 e2e) | 17b, 30, 31a, 32b, 34 |
| 35b | Scale/fault/recovery + headline re-run + `nfr_report.md` (**Epic 6 gate**) | 33a, 33b, 35a |
| D2 | Findings summary | 29, 32b (35b optional) |

Dependency check: the Kahn order 12 → 13 → 14 → 15 → 16a → 16b → 17 → 18 → 17b → 19 → (20–29) → 34 → 30 → 31a → 31b → 32a → 32b → 33a → 33b → 35a → 35b → D2 has no back-edges; every slice depends only on slices above it in the table. Slice 34 depends only on 9, 11 and 14, so it can be started right after Slice 14 (indicative, non-headline rows).

### NFR traceability (Chapter 1, Table 1.5 → plan)

| NFR | Implemented in | Measured / evidenced in |
|---|---|---|
| P1, P2 | Slices 13, 17b (forward round-trip), 31a | Slice 35a (headline re-run in 35b) |
| P3 | Slice 17 | Slices 35a, 35b |
| P4 | Slice 14 | Slice 34 (headline re-run in 35b) |
| P5 | Slice 6 | Slice 34 (headline re-run in 35b) |
| S1 | Slices 4, 13 | Slices 34, 35a (headline re-run in 35b) |
| S2 | Slices 10, 19 | Slice 35b |
| SEC1 | Slices 1–2 | Slice 9 |
| SEC2 | Slices 32a, 32b | Slices 32a, 32b |
| SEC3 | Slices 13, 31a | Slice 31a |
| SEC4 | Slices 10, 31b | Slice 31b (+ Slice 30 for the PoW rejection counter) |
| C1 | Slice 4 | Slice 31b (`test_no_pii.py`) |
| R1 | Slices 16a–18 | Slices 26, 35b |
| R2 | Slices 16a, 16b | Slice 35b |
| R3 | Slices 9, 25–28 | Slices 25–28 |
| I1 | Slices 19, 32b, 33a | Slice 33a |
| I2 | Slice 33a | Slice 33a (CI) |
| I3 | Slices 8, 33b | Slice 33b |
| M1 | Slices 1, 33a | Slice 33a (CI) |

**Optional interleaving (solo, for variety or to unblock writing):**

- D1 can be written at any time before the thesis text is finalized; only its *design justifications* need to precede Slices 1–7 conceptually.
- Slices 24–28 (Epic 5) depend on Slice 19, **not** on Epic 4. If you want attack results early for the thesis, run Epic 5 before Epic 4.
- Slice 27 (store tampering) only needs Slices 9 + 24; it can be done immediately after the network exists, well before the Sybil work.
- Slice 20 (React scaffold) can be started as soon as Slice 11 exists if you want the badge and node selector working against a single node before the full network.

---

## 6. Files created or changed

**Existing files extended:** `README.md`, `.gitignore` (Slices 1, 30, 32a), `docker-compose.yml` (created in Slice 19, extended in Slices 24, 30, 32b, 33a, 33b; `docker-compose.bench.yml` and `docker-compose.scale.yml` are separate overrides in 35a/35b), `docs/research/epic1_blockchain_comparison.md` (created in D1, extended in Slice 9).

**Epic 6 extensions of files created by earlier slices:** `src/node/{metrics,errors,main,config,sync,mempool,forwarding,validity_cache,chain_state}.py`, `src/node/api/{metrics,documents}.py`, `src/node/network/{ws_pbft,connection_manager}.py`, `src/node/consensus/{pow,pbft/engine}.py` and `src/node/validity_cache.py` (via `ChainState`, introduced in Slice 16a; `src/node/validation_gateway.py`, introduced in Slice 15, is wrapped by Slice 30), `src/node/peers/registry.py`, `web/src/api/client.ts`, `docker/node.Dockerfile`, `docker/attacker.Dockerfile`, `docker/prometheus.yml`, `docker/certs/gen_dev_certs.py`, `tests/node/test_compose_smoke.py`, `tests/node/test_forward_record.py`, `attacks/harness/*`, `pyproject.toml`, `README.md`; new top-level: `.env.example` (Grafana password, never committed with real values), cert/key init service, `tests/benchmarks/`, `tests/infra/`, `tests/docs/`, `tests/test_layering.py`, `benchmarks/` (incl. `targets.py`, `fixtures.py`, `check_headline.py`).

**All other paths listed in section 2 are new**, created by the slice that first names them. `src/blockchain_core/` and `tests/` currently exist locally as untracked work-in-progress for Slices 1+; no `src/node/` code exists yet.

---

## 7. Risk assessment

| Risk | Impact | Where it bites | Mitigation in this plan |
|---|---|---|---|
| **Canonical serialization drift** | Two nodes compute different hashes for the same data; the whole network silently fails to converge. | Slices 1, 4, 6; every Epic 3 node. | One encoder module, frozen test vectors, and BC-TC-CS.3 asserting no duplicate encoding logic exists. Never edit the vectors after Slice 1. |
| **Cryptographic key handling** | Private keys leaked into logs, into the browser, or regenerated silently, destroying issuer identity continuity. | Slices 2, 8, 13, 21. | Separate stores per key type; fail-fast on missing key files; server-side-only issuer signing; a hard "no key material in the browser" check in Slice 21. **Security pre-review on all four.** |
| **PBFT quorum/equivocation logic error** | Safety violation — a wrong block finalizes; and the thesis's central PoW-vs-PBFT comparison becomes invalid. | Slices 17, 18; measured in 26. | Quorum counted only over the static `ValidatorSet`; one vote per `node_id` per `(view, seq)`; distinct-signer requirement enforced twice (engine + validation). **Security pre-review on both.** |
| **Sybil surface via peer registration** | An attacker inflates influence by registering peers. | Slice 12; measured in 26. | Structural separation of `PeerInfo` from `ValidatorSet`, asserted by CN-TC-1.11 and AT-TC-2.8 as a negative control. |
| **Fork-adoption bug** | A node adopts a tampered chain, silently defeating every guarantee proven in Slice 9. | Slice 16b. | Full from-genesis revalidation on divergence (asserted with a call counter); PoW-only tie-break; PBFT same-height fork treated as a Byzantine event. **Security pre-review.** |
| **Trust-anchor shortcut in Epic 5** | Tamper tests read the attacked node's own key-store and produce false "valid"/"detected" results, invalidating the thesis evidence. | Slice 27. | Out-of-band anchor file + injected resolver, with AT-TC-4.9 as an explicit regression guard. **Security pre-review.** |
| **Attacker logic leaking into the honest node** | Violates PRD §5 acceptance (M-13) and contaminates every measurement. | Slice 24. | Separate image/Dockerfile/compose service; repo scan test (AT-TC-1.3). **Architect pre-review.** |
| **Difficulty change against an old chain** | Looks like a bug; actually by-design. | Slices 7, 8, 14, 25. | Documented in BC-TC-8.10; changing difficulty requires a fresh chain on every node. |
| **Scope creep from IPFS** | Time lost on an explicitly optional item. | Any. | IPFS is out of scope by PRD decision; `ipfs_cid` stays an optional, defaulted-absent field (BC-TC-1.3) and must never block an acceptance criterion. |
| **Data sensitivity** | Low. `DocumentRecord.metadata` should carry non-PII identifiers where possible and is size-capped server-side. No user authentication exists — a deliberate, documented prototype scope reduction (PRD §4 NFR). |
| **Persistence/schema changes** | Chain store format changes after data exists force a chain reset. | Slice 8. | Freeze the store contract in Slice 8 behind an interface; the demo network is disposable, so a reset is always acceptable. |
| **NFR targets missed on a single dev host** | p95 ≤200 ms @200 RPS, 1 000-block sync ≤30 s, or 10 000-block validation ≤5 s may fail on a laptop with 4–10 containers sharing cores. | Slices 34–35b. | Measure early (Slice 34 right after Slice 14, before hardening) so optimisation has time; record misses honestly in `nfr_report.md` rather than editing targets. |
| **TLS complicates the attack harness** | Attackers must hold CA-signed server certs or Epic 5 measures TLS admission instead of consensus resistance. | Slices 24, 32a, 32b. | Cert generator also issues attacker certs; Slice 32b re-runs the smoke test with TLS; findings state the insider threat model. |
| **Rate limiter distorts load tests** | The 100 req/min/IP limit would throttle the 200 RPS test; the host-side client is one bridge IP. | Slices 31a, 35a. | Benchmark override compose raises the limit (limiter stays in the measured path); per-IP acceptance tests use ASGI scope injection or multiple containers. |
| **NFR-S1 unreachable in PoW mode** | 256 records per ~10 s block ⇒ ≈25.6 rec/s < 50. | Slices 34, 35a, 35b. | Headline S1/P1/P2 measured in PBFT; PoW row reported with the arithmetic (a mode statement, not a target change). |
| **Post-hoc choice of measurement definition** | Picking the statistic after seeing results undermines the NFR evidence. | Slices 34, 35a, 35b. | Measurement protocol frozen in PRD §6 FR-17…19 and architect-reviewed before headline runs. |
| **Cross-slice artifacts drift** (OWASP checklist, fail-fast config matrix, compose static checks) | A row cites a control or test that does not exist yet, or a new key ships unvalidated. | 31a, 31b, 32a, 32b, 33a, 33b. | Each slice extends only its own rows. The dangling-reference check (NF-TC-5.5) runs from 31b. The fail-fast matrix fails on any config key without a row. |
| **Docker-dependent tests vs CI** | Stack, key-isolation and `id -u` tests are skipped silently, so I1/SEC2 evidence is unverified. | 30, 32b, 33a, 35b. | `@pytest.mark.docker`; a separate CI `image`/compose job runs them while static compose checks run everywhere. NF-TC-13.11 asserts no gate is skipped. |
| **`ChainState` retrofit regressions** | Slice 14/15 append paths break when moved behind the lock. | 16a. | 16a re-runs the Slice 14/15 suites in its Verify, and the single-owner static check (CN-TC-17.11/17.12) guards later slices. |
| **External calls** | None. No third-party services, no message broker (RabbitMQ explicitly rejected), no network access from `blockchain_core`. |

---

## 8. Dependencies

**Python (backend, Slices 1–19, 24–35b):** `cryptography`, `fastapi`, `uvicorn[standard]`, `pydantic` v2, `websockets`, `httpx` (client + test client), `pytest`, `pytest-asyncio`, `ruff`, `mypy`; `matplotlib`, `plotly`, `pandas` (Slice 29 only).

**Frontend (Slices 20–23):** `react`, `react-dom`, `react-router-dom`, `typescript`, `vite`, `vitest`, `@testing-library/react`, `@testing-library/user-event`. Hashing uses the browser-native **Web Crypto API** — no third-party hashing library.

**Epic 6 additions (Slices 30–35b):** `prometheus_client`, `pytest-cov`, `k6` (single load tool, run as a service in `docker-compose.bench.yml` with its own cpuset and the dev-CA cert mounted); infrastructure images `prom/prometheus`, `grafana/grafana`; tools `trivy`, `openssl`; GitHub Actions for CI.

**Infrastructure:** Docker Engine + `docker compose` v2 (≥4 node containers, up to 10 for Slice 35b, plus the attacker service, Prometheus and Grafana).

**Explicitly NOT dependencies:** RabbitMQ or any message broker (rejected by architecture review — a broker would invalidate the Sybil demonstration); IPFS (optional/deferred, must never block an acceptance criterion); Hyperledger/Ethereum or any existing blockchain framework (building from scratch is the thesis's premise).

---

## 9. Wave assignment

**Not performed — intentionally.** Wave assignment exists to let parallel agents own disjoint file sets within a wave. This plan is executed by one person sequentially, so slices carry no `Wave:` field; execution falls back to the dependency order in section 5. If this plan is ever handed to a parallel executor, waves must be assigned first, and note that Slices 6/7 (both edit `src/blockchain_core/validation.py`), 17/18 (both edit `src/node/consensus/pbft/engine.py`), 24/25/26 (all edit `attacks/attacker_node/overrides.py`), 30, 31a, 32a, 32b, 33a, 33b (all edit `docker-compose.yml` and/or `src/node/config.py`), 31a/32b (both edit `web/src/api/client.ts`), 16a/16b/17 (all touch `src/node/consensus/pow.py`, `src/node/validity_cache.py` or `chain_state.py`), 17b/31b (both edit `src/node/consensus/pbft/forward.py` and `tests/node/test_forward_record.py`) and 31a/32a/33b (all extend `tests/node/test_config_failfast.py`) share files and could never occupy the same wave.
