# Epic 1 — Research of Blockchain Systems: Construction Principles and Document-Verification Systems

**Deliverable:** D1 (PRD §1, FR-1…FR-5). **Status:** draft for the thesis text. **Companion text:** Chapter 1, §1.3 (`docs/1_analysis.md`), which surveys Blockcerts, OpenCerts and Hyperledger Indy/Aries in Ukrainian; this note adds the construction principles, the EBSI case, the explicit design-decision trace and the as-built guarantees. No code is produced by this deliverable.

---

## 1. Blockchain construction principles (FR-1)

### 1.1 Block structure

A block is a bundle of records plus a header that commits to them. In this project (Epic 2) a block has two parts: a **hashed preimage** (`index`, `timestamp`, `previous_hash`, `merkle_root`, and the consensus data sealed into the hash such as the PoW `nonce`/`difficulty`) and **attestations** that are attached *after* hashing (`proposer_signature`, PBFT `commit_signatures`). Splitting them is deliberate: a PBFT commit vote signs the block hash, so the votes cannot be inside the thing they sign.

### 1.2 Hash linking

Each block stores the hash of its predecessor. Changing any earlier block changes its hash, which breaks the `previous_hash` of the next block, so tampering is detectable by recomputation (Nakamoto, 2008). The hash function must be collision- and second-preimage-resistant; SHA-256 (FIPS 180-4) is the de-facto choice (Bitcoin, Ethereum's Merkle structures, Blockcerts). The weakness of pure hash linking is the **tip**: the last block has no successor, so nothing links to it and an attacker who recomputes its hash is not caught by linking alone. Section 4.2 shows how this project closes that gap with a signature.

### 1.3 Merkle trees

A Merkle tree (Merkle, 1987) hashes the records as leaves and hashes pairs upward to a single root. One root commits to N records, and an inclusion proof for one record is only O(log N) hashes. Blockcerts and OpenAttestation both batch many credentials under one root and anchor only that root; the same structure gives a verifier a compact proof without downloading the whole block. Leaves and inner nodes should be hashed under different prefixes (domain separation) so an inner node cannot be passed off as a leaf; this project uses a `0x00` leaf prefix and a `0x01` inner-node prefix.

### 1.4 Consensus

Consensus decides which block extends the chain when several nodes propose.

| Family | Idea | Fault model | Finality | Cost |
|---|---|---|---|---|
| Proof of Work | Find a nonce so the block hash is below a target; longest valid chain wins (Nakamoto, 2008) | Tolerates a minority of hash power; open membership | Probabilistic | Energy / compute; latency set by difficulty |
| PBFT | Pre-prepare / prepare / commit rounds among a known validator set; quorum of matching votes finalizes (Castro & Liskov, 1999) | n ≥ 3f + 1 Byzantine-tolerant, known membership | Deterministic, immediate | O(n²) messages per round |
| Proof of Authority / Stake (rotating validators) | Known or staked validators take turns | Depends on validator set and slashing/identity | Fast to deterministic | Low compute; trust in the validator list |

The thesis compares the first two **implemented by hand**. Their Sybil behaviour differs fundamentally: PoW weighs influence by hash power, PBFT by seats in a static validator set, so open peer registration is harmless to PBFT quorum and irrelevant to PoW weight (these are different axes and not directly comparable node-for-node).

### 1.5 Node roles

| Role | Responsibility |
|---|---|
| Issuer | Holds the key that signs `DocumentRecord`s; registered in the network-wide `IssuerRegistry` |
| Validator / proposer node | Holds a node key; proposes and signs blocks, votes in PBFT; member of the static `ValidatorSet` |
| Peer | Any connected node (`PeerInfo`), dynamic and gossip-populated; has **no** voting power |
| Verifier / client | Looks up a hash and checks the Merkle proof and signatures; holds no private key |

---

## 2. Survey of document-verification systems (FR-2)

Ukrainian-language engineering analysis with the comparison matrix is in Chapter 1 §1.3. The facts below are the English research basis.

### 2.1 Blockcerts

- **Data model:** credentials as JSON-LD aligned with W3C Verifiable Credentials; held by the recipient, no central database. A batch is hashed into a Merkle tree and the receipt carries the proof (`MerkleProof2017`, Chainpoint-compatible).
- **Hashing / anchoring:** only the Merkle root is written into a Bitcoin or Ethereum transaction. There is no own ledger.
- **Verification flow:** `cert-verifier-js` (1) recomputes the credential hash and checks it equals the receipt's `targetHash`; (2) checks the Merkle proof reaches the receipt's root; (3) checks that root against the anchoring transaction on the chain; (4) fetches the **issuer profile** over HTTPS, takes the issuer's public keys and cross-checks them against the transaction; (5) checks the revocation list and expiry.
- **Revocation:** a list of revoked assertions published by the issuer at a URL named in the credential; trust in the list is the issuer's hosting.
- **Weak points:** issuer-key trust rests on an HTTPS-hosted profile (a fabricated issuer profile is an attack surface discussed in arXiv:1910.04622); confirmation latency and fees are those of the base chain; the consensus is not tunable.

### 2.2 OpenCerts / OpenAttestation

- **Data model:** every field is salted and hashed; the field hashes form a Merkle tree whose root identifies the document (batch of documents shares a root).
- **Hashing / anchoring:** the root is issued through a `DocumentStore` smart contract on Ethereum or Polygon.
- **Verification flow:** verifier recomputes the root, checks the root is issued (and not revoked) in the contract, and checks issuer identity through a DNS-TXT record binding the contract address to a domain.
- **Revocation:** the contract can revoke a whole root or a single document inside a batch by its path.
- **Weak points:** gas cost for issue/revoke; verification availability depends on external RPC providers; identity trust is only as strong as DNS.

### 2.3 EBSI (European Blockchain Services Infrastructure) — optional third system

- **Data model:** diplomas issued as W3C Verifiable Credentials signed with JWS; the chain stores identifiers and registries, not the document.
- **Consensus:** a permissioned network of validator nodes operated by member states, described in the literature as proof-of-authority style, with validators taking turns producing blocks.
- **Verification flow:** the verifier checks the credential signature and then resolves the issuer in the **Trusted Issuers Registry**, an on-ledger list of entities authorised by accreditation bodies — issuer authorisation is part of the ledger, not an HTTPS page.
- **Revocation:** status via credential-status mechanisms defined by the framework; the registry can also remove an issuer.
- **Weak points for this thesis:** governance by an institution consortium, no way to compare consensus algorithms, heavy standards stack.

### 2.4 Sources

1. S. Nakamoto, *Bitcoin: A Peer-to-Peer Electronic Cash System*, 2008.
2. R. C. Merkle, "A Digital Signature Based on a Conventional Encryption Function", CRYPTO '87.
3. M. Castro, B. Liskov, "Practical Byzantine Fault Tolerance", OSDI 1999.
4. NIST FIPS 180-4, *Secure Hash Standard*.
5. Blockcerts, `cert-verifier-js` verification-process documentation — https://github.com/blockchain-certificates/cert-verifier-js (docs, v6.x).
6. Security analysis of a blockchain-based protocol for the certification of academic credentials — https://arxiv.org/pdf/1910.04622.
7. OpenAttestation / OpenCerts — https://github.com/Open-Attestation and https://github.com/OpenCerts/certificate-store-contract.
8. EBSI Hub, Verifiable Credentials framework and verify-credentials guideline — https://hub.ebsi.eu/docs/foundations/verifiable-credentials/framework ; Issuer Trust Model — https://ec.europa.eu/digital-building-blocks/ (EBSI documentation).
9. Hyperledger Indy / Aries documentation (summarised in Chapter 1 §1.3.3).

Source quality note: items 5, 7 and 8 are the systems' own documentation and describe intended design, not independent evaluation; version-specific verifier behaviour was not re-checked against the latest releases and should be re-verified before final submission.

---

## 3. Comparison (FR-3)

| Dimension | Blockcerts | OpenCerts / OpenAttestation | EBSI | **This project** |
|---|---|---|---|---|
| Data model | JSON-LD (W3C VC), held by recipient | Salted per-field hashes, Merkle tree of fields; held by recipient | W3C VC signed with JWS; held by holder | `DocumentRecord` (`document_hash`, `issuer_id`, `issued_at`, `metadata`, issuer signature); only the hash goes on the ledger |
| Hashing scheme | SHA-256 Merkle tree per batch, root anchored | Merkle tree of salted field hashes, root issued | JWS over the credential; hashes/identifiers on ledger | SHA-256 over canonical serialization; Merkle tree per block with domain-separated leaf/inner hashes |
| Consensus | Inherited from Bitcoin (PoW) or Ethereum | Inherited from Ethereum / Polygon | Permissioned, authority-style validators | **Own implementation, switchable:** PoW and PBFT (n ≥ 3f + 1) |
| Revocation | Issuer-hosted revocation list (URL) | `DocumentStore` revoke (root or document) | Registry/status mechanisms; issuer can be removed from registry | No document-revocation mechanism is specified in the PRD; issuer set is a static, network-wide `IssuerRegistry` loaded at boot (key revocation is deferred to the node layer) |
| Verification flow | Hash → Merkle proof → on-chain root → issuer profile (HTTPS) keys → revocation list | Recompute root → check contract → DNS-TXT identity | Check JWS → resolve issuer in Trusted Issuers Registry | Lookup hash → Merkle proof against block root → issuer signature vs `IssuerRegistry` key → proposer signature / PoW / commit quorum on the block |

---

## 4. Design decisions traced to research findings (FR-4)

### 4.1 Decisions

| # | Decision (epic) | Research finding it rests on |
|---|---|---|
| DD-1 | **SHA-256 everywhere** — document hash, block hash, Merkle nodes, PoW (Epics 2–3) | SHA-256 is the common primitive of Blockcerts, OpenAttestation and Bitcoin (§1.2, §2.1–2.2); well-reviewed, native in the browser Web Crypto API, so the client can hash the file without any library. |
| DD-2 | **Merkle tree per block with domain-separated leaf/inner hashes; only hashes on ledger** (Epic 2) | Blockcerts and OpenAttestation batch many credentials under one root and anchor only the root (§2.1–2.2); inclusion proofs are O(log N) (§1.3); the second-preimage risk of unprefixed trees (§1.3) motivates the `0x00` leaf prefix. |
| DD-3 | **Implement PoW *and* PBFT, selectable per network** (Epic 3) | Surveyed systems inherit consensus from an external chain (Bitcoin/Ethereum) or a consortium (EBSI) and cannot vary it (§2.1–2.3); comparing the Sybil and fault behaviour of the two families (§1.4) needs both under one codebase. |
| DD-4 | **Issuer keys registered in a network-wide `IssuerRegistry`, not in an HTTPS profile or DNS** (Epics 2–3) | Blockcerts' reliance on an HTTPS issuer profile and OpenCerts' reliance on DNS-TXT are the weakest links of those designs (§2.1, §2.2); EBSI's on-ledger Trusted Issuers Registry (§2.3) shows the registry approach. |
| DD-5 | **PBFT quorum from a static `ValidatorSet`, never from peers** (Epic 3) | PBFT safety requires n ≥ 3f + 1 over a *known* set (§1.4, Castro & Liskov); the PoW/PBFT Sybil difference in §1.4 is the thesis's measured quantity. |
| DD-6 | **Proposer signature on every block** (Epic 2) | Pure hash linking cannot protect the tip block (§1.2); a signature the attacker cannot recompute closes it (§4.2, tests 7.7/7.10). |

### 4.2 Why build from scratch instead of Hyperledger or Ethereum (FR-5)

- The thesis goal is to **implement and compare consensus algorithms first-hand**. Ethereum fixes PoS consensus and Hyperledger Fabric/Indy fixes its ordering/consensus service; neither lets the author swap PoW for PBFT under identical application code, nor run a Sybil experiment at the consensus layer.
- Public chains add fee, latency and external-RPC dependency (§2.1–2.2). A self-contained node network has none of these and is reproducible with `docker compose`.
- Hyperledger Indy needs permissioned-network governance and a heavy agent stack, and its core repositories are archived or in maintenance (Chapter 1 §1.3.3).
- The accepted cost is the loss of an industrial platform's maturity; it is mitigated by a small implementation surface and the tamper/fault test suites described next.

---

## 5. Implemented guarantees vs. surveyed systems (deferred from Slice 9)

The following guarantees are **implemented and tested** in Epic 2 (Slices 7–9, `tests/core/test_tamper_detection.py`, `tests/core/test_validation_consensus.py`, `tests/core/test_persistence.py`) and compared with the surveyed systems:

| Scenario (attacker action on a persisted chain) | Detecting layer | `failure_type` |
|---|---|---|
| Record metadata edited, nothing recomputed | Merkle root | `merkle` |
| Block field edited, hash not recomputed | Block hash | `hash` |
| Middle `previous_hash` edited, hash recomputed | Hash-chain link | `link` |
| Middle block edited, rehashed and re-mined | Proposer signature | `signature` |
| Same, with the node key compromised | Link of the *next* block | `link` |
| **Tip** block edited, rehashed and re-mined | Proposer signature only | `signature` |
| Edit re-signed with the attacker's own key | Signature against the known registry key | `signature` |
| PBFT commit signatures reduced below quorum | Commit quorum | `quorum` |

Comparison paragraph. In Blockcerts and OpenCerts the integrity of a credential reduces to "its hash is in a Merkle tree whose root sits in an external-chain transaction"; the strength against rewriting history is whatever Bitcoin or Ethereum provides, and the application adds no extra layer. Issuer identity is checked out-of-band (HTTPS profile, DNS-TXT). This project, which owns the ledger, must prove tamper-evidence itself, and does so with layered, independently tested checks: recomputation layers (Merkle, hash, link) defeat careless edits; signature layers (proposer, issuer) defeat an attacker who recomputes everything he touches; and the **tip** case, where linking is blind, is covered by the proposer signature alone (once the node key itself is compromised the tip edit is undetectable at that layer, which the test suite states explicitly). For consensus, the PoW check enforces the **exact** configured difficulty (not "at least"), and PBFT blocks must carry a quorum of `floor((n + f)/2) + 1` distinct commit signatures (equal to 2f + 1 when n = 3f + 1), where each commit vote signs a domain-tagged payload (`blockchain_core/pbft-commit/v1`) so a vote cannot be replayed as a proposer signature. Persisted chains are restored through validation, and a missing chain file fails closed unless initialization is explicit, so a silent reset to genesis is impossible. The surveyed external-chain systems get comparable *ordering* guarantees for free but cannot offer a tunable fault model; EBSI offers an on-ledger issuer list but its consensus is fixed. Known limits of this implementation (undetectable rollback of a persisted chain to a valid prefix without peer sync, unencrypted node key PEM) are documented in the plan and are Epic 3 obligations.

---

## 6. Traceability

| PRD requirement | Section |
|---|---|
| FR-1 building blocks | §1 |
| FR-2 survey (Blockcerts required; OpenCerts, EBSI optional) | §2 |
| FR-3 five-dimension comparison | §3 |
| FR-4 ≥ 3 traced design decisions | §4.1 (DD-1…DD-6) |
| FR-5 rationale for building from scratch | §4.2 |
| Deferred from Slice 9 | §5 |
