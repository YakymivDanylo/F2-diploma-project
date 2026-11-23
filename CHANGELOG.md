# Changelog

All notable changes to this project, newest first. Entries are grouped by UTC date.

## 2026-11-20

### Harden the node against abuse and tampering — 14:49 UTC
**Summary:** Before the Docker demo, the nodes were audited end to end and made much harder to overload, impersonate or trick.
**Details:** Every peer must prove it owns its key and announce a real address; peer lists, connections, request sizes and blocks are capped. Forks are compared from the last shared block, with a cheap check first. Keys can be given a start date or revoked. A PBFT node refuses to start without its saved voting state, recorded misbehaviour survives restarts, and the status shows when a node is ready.

### Push new blocks between nodes in real time (completed earlier, Slice 15) — 14:49 UTC
**Summary:** Nodes now send each new block to each other over authenticated live connections, and every block is checked in one place.
**Details:** (completed earlier, Slice 15) Each node keeps a live, mutually authenticated connection to every other node and reconnects with increasing pauses when one drops. A received block is fully checked before it is used; unsigned, unknown or broken blocks are rejected and never passed on, and a block that arrives twice is ignored.

### Add Proof-of-Work mining and block timing (completed earlier, Slice 14) — 14:49 UTC
**Summary:** In Proof-of-Work mode the nodes now mine blocks, and how long each block took is reported.
**Details:** (completed earlier, Slice 14) A node mines pending documents into a block and stops at once when a competing block arrives, then continues on top of it. For every block it records when work started and when the block was added, so the two consensus modes can be compared later.

### Submit and look up documents (completed earlier, Slice 13) — 14:49 UTC
**Summary:** An institution can submit a document fingerprint to be signed and recorded, and anyone can look a document up with its proof.
**Details:** (completed earlier, Slice 13) The node signs a submitted document fingerprint with its institution's key and queues it; duplicates are refused. A lookup returns who issued the document, when, in which block, and a proof that it is in that block. The contract for passing documents to the PBFT leader was defined here.

### Find peers and read the chain page by page (completed earlier, Slice 12) — 14:49 UTC
**Summary:** Nodes can find each other, and the whole chain can be read in pages.
**Details:** (completed earlier, Slice 12) A node can register with another node and learn the others from it. The chain can be read in limited pages, so a long history never has to be sent at once. Joining the network gives no voting rights: only the four configured validators vote.

### Report node status with time-aware keys (completed earlier, Slice 11) — 14:49 UTC
**Summary:** Each node can report who it is, whether its chain is valid and how consensus is doing.
**Details:** (completed earlier, Slice 11) The node checks signatures with the key that was valid at the time something was signed, so rotated keys keep old blocks valid. Its chain status is kept up to date as blocks arrive instead of being recomputed on every request.

### Start a node from its configuration (completed earlier, Slice 10) — 14:49 UTC
**Summary:** A node can now be started from its configuration and the lists of validators and institutions.
**Details:** (completed earlier, Slice 10) The node loads its settings, the validator list and the institution list at start and refuses to start if they are inconsistent. Every error is returned in one common format, and the web application's address is allowed to call the node.

### Accept documents at any validator — 11:37 UTC
**Summary:** A document can now be submitted to any of the four institutions' nodes, not only to the current leader.
**Details:** A node that is not the leader signs the document with its own institution's key and passes it to the leader, which checks the sender, the record and duplicates in a fixed order before queuing it. The client gets the same answer either way. Floods from other nodes are limited, and a leader that accepts documents but never includes them is voted out.

### Replace a failed PBFT leader automatically — 10:55 UTC
**Summary:** If the leading validator goes offline or misbehaves, the others now pick a new leader within seconds and keep accepting documents.
**Details:** Validators vote to change the leader when a round stalls, the leader is unreachable, or it proposes an invalid block. A block that may already be agreed is carried over, never replaced, and votes are saved to disk so a restart cannot cause conflicting votes. The node status now separates a lying validator from too few validators being online, and lists reported misbehaviour.

## 2026-11-13

### Add PBFT voting between validators — 17:18 UTC
**Summary:** In PBFT mode the four institutions now vote on every new block, and a block is accepted only when at least three of them agree.
**Details:** The leading node proposes a block, the other validators check it and vote in two rounds, and the block is added once enough matching votes are collected. Only the official validators can vote, however many other nodes join. Duplicate or out-of-order messages never count twice, and no node signs two different blocks for the same slot. If one validator is offline, blocks are still finalized.

### Protect validator addresses with signed registration — 15:28 UTC
**Summary:** Nobody can redirect another validator's network address anymore; only the validator itself can announce where it lives.
**Details:** Registering a validator node now requires a fresh registration signed with that validator's own key. Attempts to move a validator to a foreign address, replay an old registration or use a wrong key are rejected, and unsigned validator entries passed along by other nodes are ignored. Ordinary non-validator peers are unchanged and still carry no voting weight.

### Add chain synchronization and fork resolution — 15:28 UTC
**Summary:** Nodes now catch up with each other, choose the same winning chain after a fork, and repair a tampered local copy from their peers.
**Details:** A node checks with its peers before it starts serving (with a time limit, so nodes started together never wait forever), then keeps syncing. Only fully re-checked chains are adopted. Proof-of-Work forks resolve the same way on every node; conflicting finalized PBFT blocks are reported as a safety violation instead of being guessed. A tampered chain is replaced, never by a shorter one.

### Make one component the single owner of the chain — 15:28 UTC
**Summary:** All changes to a node's blockchain now go through one guarded place, so simultaneous updates can never corrupt it.
**Details:** Adding a new block and swapping in a whole chain from a peer can no longer interleave: each runs on its own, and the saved copy, the validity status and the document index always match the chain in memory. Blocks handed out to the rest of the system are read-only. Over a hundred randomized timing scenarios confirm no update is lost.

## 2026-10-20

### Complete the blockchain core (Epic 2) — 14:21 UTC
**Summary:** The blockchain core is finished: it checks consensus proofs, saves the chain to disk and reloads it safely, and is proven to detect tampering.
**Details:** Validation now enforces Proof-of-Work difficulty and the PBFT voting quorum, with votes signed separately from block proposals so they cannot be forged by replay. The chain is stored as JSON or SQLite and is fully re-checked at startup; a damaged, tampered or missing chain stops the node instead of being trusted. A tamper-detection test suite shows which defence catches each attack.

## 2026-10-10

### Add chain validation and harden the blockchain core — 17:27 UTC
**Summary:** The system can now check a whole chain for tampering, and the core was made safer against malformed or hostile data.
**Details:** Adds chain validation (hash, link, Merkle, signatures, structure) with full and incremental modes. After a review: strict data encoding, read-only blocks and records, one-form signatures, stronger key checks, atomic key files, atomic chain append, role-typed keys, and ~130 new tests.
