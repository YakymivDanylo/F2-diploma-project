# Use Cases: Non-Functional Requirements and Operations (Epic 6)

> Based on [PRD](../PRD.md) — Epic 6: Non-functional requirements and operations (v1.9, FR-1 to FR-23; depends on Epic 3 FR-22 `forward_record` contract and FR-27 `ChainState`)

> Updated 2026-10-28 (PRD v1.9 alignment): E6-UC-15 CSV column list now uses the exact FR-17 header (nine columns: `nfr_id,value,target,pass_fail,mode,achieved_rps,headline,machine,commit`); E6-UC-4-E1 cross-references the check-order pair 4/5 in Epic 3 UC-16-E9 (owned by Slice 31b). No UC IDs added or removed.

> Updated 2026-10-28 (PRD v1.8 alignment, architecture-review round 3): No new UC IDs; E6-UC numbering is stable. (1) NFR ID count corrected from 21 to 19 (Table 1.5 has 19 unique IDs) in the cross-cutting contract, the traceability table, E6-UC-27 primary flow and E6-UC-27-E3. (2) Forwarding behaviour that belongs to Epic 3 moved out of Epic 6 ownership: the former E6-UC-4-A4, A5, A6, A8, A9, A10, E2, E3, E7, E8, EC5, EC7, EC8 and the Epic 3 part of E6-UC-11-E7 now point to Epic 3 use cases UC-15 (plan Slice 13: `RecordForwarder`, HTTP mapping, timeout, `FORWARD_ACK_TIMEOUT_MS`), UC-16 (plan Slice 17b: channel, authentication, check order, dedupe, view change, late replies) and UC-17 (plan Slice 16: `ChainState` append vs replace) in `consensus_network_use_cases.md`. Epic 6 (plan Slices 31 / 33) keeps only: the `IssuerRegistry` check and `unregistered_issuer` reply (check 4 of the handler order), PoW block-level evidence, and the snapshot-copy extension of `ChainState`. (3) E6-UC-4-A7 now records its dependency on `blocks_rejected_total`, which is delivered by Slice 30. (4) E6-UC-27 SEC3/SEC4 rows: SEC3 is the mode-independent rate limit; SEC4 evidence differs by mode.

> Updated 2026-10-28 (PRD v1.7 alignment, architecture-review round 2): No new UC IDs; E6-UC numbering is stable. Revised E6-UC-3, E6-UC-4, E6-UC-5, E6-UC-8, E6-UC-10, E6-UC-11, E6-UC-12, E6-UC-15, E6-UC-16, E6-UC-19, E6-UC-20, E6-UC-21, E6-UC-22, E6-UC-27, E6-UC-28, E6-UC-29, E6-UC-30 and the cross-cutting contracts. Main changes: (1) the `forward_record` reply codes are the CLOSED enum of Epic 3 FR-22 (`accepted | duplicate | not_primary | not_validator | unregistered_issuer | invalid_record | auth_failed`) with the HTTP mapping on the original `POST /documents`, and the channel is Epic 3's (Epic 6 adds only the `IssuerRegistry` check); new flows for two non-primaries forwarding the same hash, ack timeout and view change in flight; (2) PoW-mode SEC3/SEC4 evidence is block-level rejection by the Epic 2 signature check (new flow E6-UC-4-A7, E6-UC-4-EC6 rewritten, E6-UC-27 row states both modes); (3) per-service key/cert volume isolation with the dev-CA private key never in a runtime volume (E6-UC-8, E6-UC-10, E6-UC-29, attacker cannot read node* keys); (4) `ChainState` owned by Epic 3 FR-27, snapshot copies frozen or deep-copied blocks, append-during-snapshot flow (E6-UC-11, E6-UC-12); (5) P3 is definitively p95 (E6-UC-22); (6) P2 includes the forward round-trip and is reported separately for primary-received and non-primary-received requests (E6-UC-21); (7) supplementary labelled PBFT-fixture row for P5 (E6-UC-16); (8) CSV columns `mode`, `achieved_rps`, `headline`, `machine`, `commit` and re-run of P4/P5/S1-batching headline rows at the final commit (E6-UC-15, E6-UC-28); (9) k6 is the single load tool, run as a service in `docker-compose.bench.yml` with own `cpuset` and the dev-CA cert (E6-UC-19, E6-UC-20, E6-UC-21); (10) single-client-factory static check scoped to `src/node/**` excluding `tls.py`, server-side `minimum_version` hook in `tls.py` called from `main.py` (E6-UC-7, E6-UC-8); (11) fail-fast validation covers all rate-limit, TLS and snapshot keys and `FORWARD_ACK_TIMEOUT_MS` (E6-UC-30).

> Created 2026-10-28: E6-UC-1 through E6-UC-27 for Epic 6 (Slices 30-35 of `docs/IMPLEMENTATION_PLAN.md`). New file because no existing use-case file covers observability, hardening, packaging, or NFR measurement. All IDs use the `E6-UC-n` prefix so they never collide with the `UC-n` IDs of the Epic 2, 3, 4 and 5 files.

> Updated 2026-10-28 (PRD v1.6 alignment, architecture-review resolutions): Added E6-UC-28 (early vs headline runs, FR-21), E6-UC-29 (SPA HTTPS/429 handling and attacker image ownership, FR-22) and E6-UC-30 (fail-fast configuration validation, FR-23). Revised E6-UC-1 to E6-UC-27 in place (numbering unchanged): unregistered-issuer rejection moved from HTTP 403 to the typed `unregistered_issuer` reply on the `forward_record` message of `WS /ws/pbft` (E6-UC-4); rate limiter specified as pure ASGI middleware with CORS exposure, WS denial, `proxy_headers=False`, static-ValidatorSet-only exemption and bounded memory (E6-UC-3); TLS decision changed to server authentication only, no client certificates, with a single client factory and live-listener assertion (E6-UC-7, E6-UC-8); named volumes, init service, read-only root, snapshot copy-under-lock and atomic-write rules (E6-UC-10 to E6-UC-12); dedicated metrics registry, buckets and single-call observation (E6-UC-1, E6-UC-2); Trivy digest pinning, DB cache and node-only gating (E6-UC-13, E6-UC-14); measurement protocol (PBFT headline mode, P3 = p95, P5 fixture, P4 calibration, open-loop k6, bench override) (E6-UC-15 to E6-UC-27). The three open assumptions of the first draft are resolved: the inbound client-certificate flow (old E6-UC-8-E2) is rewritten as application-layer rejection; the P3 statistic (E6-UC-22) is p95; the PoW throughput cap (E6-UC-23-EC2) is reported with arithmetic and the headline S1 row is in PBFT mode.

This document covers the cross-cutting layer that brings the running system up to the Chapter 1 section 1.5 (Table 1.5) targets and makes each target measurable: Prometheus export and the Prometheus/Grafana stack (Slice 30), API hardening (Slice 31), TLS 1.3 (Slice 32), container hardening, snapshots and CI gates (Slice 33), and the NFR measurement suite (Slices 34-35). Epic 6 adds no new consensus or document-lifecycle behavior. Actors are the operator running docker-compose, the thesis author, an API client or attacker, peer nodes, the CI system, and the benchmark harness.

**Measurement configuration (fixed by the thesis):** n = 4, f = 1, a single host, docker-compose. Scale tests vary n between 4 and 10 by configuration only. Results are single-host and are not claimed to generalize. Headline S1 (end-to-end), P1, P2 and P3 are measured in PBFT mode; PoW rows are annotated.

**Cross-cutting contracts reused from Epic 3 and Epic 2:**
- Error envelope (Epic 3 FR-19): `{"error": {"code": "<machine_readable_code>", "message": "<human_readable_message>", "details": {...}}}`. Error flows below reference this envelope instead of restating it. Applies to HTTP responses only.
- `failure_type` values (Epic 2 FR-6): `hash`, `link`, `merkle`, `signature`, `difficulty`, `quorum`, `structural`.
- `WS /ws/pbft` `forward_record` channel (OWNED AND BUILT BY EPIC 3 FR-22; Epic 6 adds ONLY the `IssuerRegistry` check and the `unregistered_issuer` reply): request `{type: "forward_record", request_id, record, sender_id, sender_signature}` (`request_id` is a sender-generated UUID echoed in the reply; the sender signs with its `NodeKeyPair`; only `ValidatorSet` members may send). The primary sends exactly one `forward_record_reply {request_id, code}` after the accept/reject decision (not after finalization). The reply `code` is a CLOSED enum with no other values: `accepted | duplicate | not_primary | not_validator | unregistered_issuer | invalid_record | auth_failed`. These are WebSocket message exchanges, not HTTP statuses; the forwarding non-primary maps them onto the ORIGINAL `POST /documents` response through the error envelope:

  | Reply / condition | HTTP status on the original `POST /documents` |
  |---|---|
  | `accepted` | the normal accepted acknowledgement (same status and body as a primary-received request) |
  | `duplicate` | 409 |
  | `not_primary`, view change in progress, no reply within `FORWARD_ACK_TIMEOUT_MS`, forwarding connection failure | 503 with `Retry-After` (error codes e.g. `not_primary`, `forward_timeout`) |
  | `unregistered_issuer` | 403 |
  | `invalid_record` | 422 |
  | `not_validator`, `auth_failed` | 502 (misconfigured or untrusted node-to-node path; a server-side fault) |

  `FORWARD_ACK_TIMEOUT_MS` is configurable, default 2000, validated at boot (E6-UC-30). A `not_primary` reply triggers no automatic re-forward; the client retries after `Retry-After`.
- Ownership of the forwarding behaviour (v1.8): the reply-code-to-HTTP mapping, timeout and `FORWARD_ACK_TIMEOUT_MS` boot validation are Epic 3 UC-15 (plan Slice 13); the WS channel, sender authentication, handler check order, dedupe, `not_primary`/view change and late-reply discard are Epic 3 UC-16 (plan Slice 17b). The table above is reproduced here only as context for Epic 6 flows that consume it; the normative definition is in `consensus_network_use_cases.md`.
- `ChainState` (Epic 3 FR-27, Epic 3 UC-17, plan Slice 16) owns the single chain-mutation lock shared by the append path and the chain-replace (sync) path; Epic 6 only adds the snapshot-copy operation under that existing lock and creates no new lock or owner.
- NFR IDs are those of Table 1.5: P1-P5, S1-S2, SEC1-SEC4, C1, R1-R3, I1-I3, M1 (19 unique IDs: 5 + 2 + 4 + 1 + 3 + 3 + 1; Table 1.5 has 19 unique NFR IDs).
- Reply-code and mode scope: no flow in this document uses a reply code outside the closed enum above. The `forward_record` channel exists only in PBFT mode; PoW mode has no intake channel for pre-signed records (see E6-UC-4-A7).

**Requirement traceability (UC -> FR -> NFR -> Slice):**

| Use case | PRD FR | NFR | Slice |
|---|---|---|---|
| E6-UC-1 | FR-1, FR-2 | (Chapter 1 section 1.5.2 observability) | 30 |
| E6-UC-2 | FR-3 | (Chapter 1 section 1.5.2 observability) | 30 (https scrape after 32) |
| E6-UC-3 | FR-4, FR-5 | SEC3 | 31 |
| E6-UC-4 | FR-6 (Epic 6 additions only: `IssuerRegistry` check, `unregistered_issuer` reply, PoW block-level evidence). Epic 3-owned behaviour: UC-15 (mapping, Slice 13), UC-16 (channel, check order, dedupe, view change, late replies; Slice 17b) | SEC4 (PBFT: `unregistered_issuer`; PoW: block-level rejection via E6-UC-4-A7). SEC3 is mode-independent (E6-UC-3) | 31 (A7 also needs 30 for `blocks_rejected_total`); redirected flows: 13, 17b |
| E6-UC-5 | FR-7 | SEC3, SEC4 (evidence, both modes) | 31 |
| E6-UC-6 | FR-8 | C1 | 31 |
| E6-UC-7 | FR-9, FR-11 | SEC2 | 32 |
| E6-UC-8 | FR-10, FR-12 (key isolation) | SEC2, I1 | 32 |
| E6-UC-9 | FR-11 | SEC2 | 32 |
| E6-UC-10 | FR-12 | I1 | 33 |
| E6-UC-11 | FR-13 (Epic 6 addition only: snapshot copy under the existing lock). Epic 3-owned: `ChainState`, append-vs-replace concurrency = Epic 3 UC-17 (FR-27) | I3 | 33; redirected flow: 16 |
| E6-UC-12 | FR-14; Epic 3 FR-27 (UC-17) | I3 | 33 |
| E6-UC-13 | FR-15 | M1 | 33 |
| E6-UC-14 | FR-16 | I2 | 33 |
| E6-UC-15 | FR-17, FR-21 | (all measured NFRs) | 34 |
| E6-UC-16 | FR-17, FR-21 | P5 | 34 |
| E6-UC-17 | FR-17, FR-21 | S1 (batching) | 34 |
| E6-UC-18 | FR-17, FR-21 | P4 | 34 |
| E6-UC-19 | FR-18, FR-4, FR-5 | P1, P2 | 35 |
| E6-UC-20 | FR-18 | P1 | 35 |
| E6-UC-21 | FR-18; Epic 3 FR-22 (forward round-trip; Epic 3 UC-15 / UC-16) | P2 | 35 |
| E6-UC-22 | FR-18 | P3 | 35 |
| E6-UC-23 | FR-18 | S1 (end-to-end) | 35 |
| E6-UC-24 | FR-19 | S2 | 35 |
| E6-UC-25 | FR-19 | R1 | 35 |
| E6-UC-26 | FR-19 | R2 | 35 |
| E6-UC-27 | FR-20 | all 19 IDs (SEC3 = mode-independent rate limit; SEC4 row states PBFT and PoW evidence) | 35 |
| E6-UC-28 | FR-21 | all measured NFRs (P1-P5, S1 batching and end-to-end, S2, R1, R2) | 34, 35 |
| E6-UC-29 | FR-22, FR-9, FR-12 | SEC2, SEC3, I1 | 31, 32, 33 |
| E6-UC-30 | FR-23 | SEC2, SEC3, I3 | 31, 32, 33 |

---

## E6-UC-1: Prometheus Metrics Export (`GET /metrics`)

**Actor**: Prometheus server, operator, or any HTTP client
**Preconditions**: Node is running; `PeerConnectionManager` (Epic 3 FR-12) and consensus metrics (Epic 3 FR-9) are initialized; the application metrics live in a dedicated `CollectorRegistry`
**Trigger**: `GET /metrics` on a node

### Primary Flow (Happy Path)
1. Client sends `GET /metrics` to a node (no authentication, like the other read endpoints; accepted prototype risk recorded in OWASP API8/API9, E6-UC-5).
2. Node returns HTTP 200 with `Content-Type: text/plain; version=0.0.4` in Prometheus text exposition format, generated from the dedicated registry only.
3. The body contains the series `chain_height` (gauge), `peer_connections{state}` (gauge, one series per connection state reported by `PeerConnectionManager`), `consensus_finalization_seconds{algorithm}` (histogram, `algorithm` is `pow` or `pbft`), `mempool_size` (gauge), and `blocks_rejected_total{failure_type}` (counter).
4. A block is finalized. A second scrape shows `chain_height` increased by exactly 1 and the `consensus_finalization_seconds_count` for the node's algorithm increased by exactly 1. That count equals the number of `ConsensusMetric` rows returned by `GET /metrics/consensus` (the histogram is observed in the same call that writes the row).
5. A block is rejected with `failure_type = "signature"`. A third scrape shows `blocks_rejected_total{failure_type="signature"}` increased by 1.

**Postconditions**: The metrics reflect state the node already tracks; no new data collection occurred. The JSON `GET /metrics/consensus` endpoint still works unchanged.

### Alternative Flows
- **E6-UC-1-A1: Coexistence with the JSON endpoint** — at step 1 the client calls both `GET /metrics` and `GET /metrics/consensus`. Both return 200; the JSON shape of `/metrics/consensus` is identical to its Epic 3 contract.
- **E6-UC-1-A2: PoW-mode node** — in PoW mode only `algorithm="pow"` histogram series are populated; the `pbft` series is absent or has count 0. In PBFT mode the reverse holds.
- **E6-UC-1-A3: Rejection from any call path** — blocks rejected through the sync path, the PoW broadcast path, and the PBFT path are all counted. Each rejection is incremented exactly once by the single wrapper around the Epic 3 FR-25 validation entry point; there are no per-call-site increments.

### Error Flows
- **E6-UC-1-E1: Key or content leakage attempt** — an automated test greps the full `/metrics` body after a document with distinctive metadata has been issued and after node/issuer keys are loaded. The body MUST NOT contain private-key material, any signature value, `DocumentRecord.metadata` content, or document hashes. Any match fails the test.
- **E6-UC-1-E2: Label or series outside the allow-list** — a test parses every series and fails if any label name other than `state`, `algorithm`, `failure_type` (plus Prometheus built-in `le` on histograms) is present, if a label value contains a per-document hash or a per-peer address, or if any `python_*` / `process_*` series appears (default registry leaking into the export).
- **E6-UC-1-E3: Scrape rate limited** — if the scraping IP exceeds the FR-4 limit, `GET /metrics` returns 429 in the standard error envelope with `Retry-After`. Default scrape interval (15 s, about 4 requests/min) never triggers this; the test asserts the default compose scrape configuration stays well under 100 req/min per node.
- **E6-UC-1-E4: Histogram and JSON endpoint disagree** — a test finalizes N blocks and asserts `consensus_finalization_seconds_count` equals the `ConsensusMetric` row count from `GET /metrics/consensus` on the same node. Any divergence fails the test (it would indicate observation at a different call site).
- **E6-UC-1-E5: Missing histogram boundary** — a test fails if the exported buckets do not include `le="2"` (the NFR-P3 target) or do not include a finite bucket of at least 120 s.

### Edge Cases
- **E6-UC-1-EC1**: Freshly booted node with only the genesis block: `chain_height` is 0 (or the genesis index per Epic 2) and the histogram count is 0; the endpoint still returns 200 with all five series present.
- **E6-UC-1-EC2**: Node with zero peers: `peer_connections` reports 0 for each known state, or only the series that exist; output stays valid exposition text and the endpoint does not error.
- **E6-UC-1-EC3**: Sustained rejection of many invalid blocks: `blocks_rejected_total` grows only along the seven `failure_type` values; series count stays constant (bounded cardinality).
- **E6-UC-1-EC4**: A PoW block taking 60 s and another taking 130 s: the 60 s sample lands in a finite bucket, the 130 s sample in `+Inf` only if it exceeds the largest explicit bucket; `+Inf` bucket and `_sum` remain consistent with `_count`. PoW block times of about 10 s are not collapsed into `+Inf`.
- **E6-UC-1-EC5**: A validation call that raises an unexpected exception rather than returning a `failure_type` does not increment `blocks_rejected_total` with an invalid label value.

### Data Requirements
- **Input**: None (GET).
- **Output**: Prometheus text exposition with the five series from the dedicated registry.
- **Side Effects**: None on chain state; in-process `prometheus_client` dedicated registry is read.

---

## E6-UC-2: Prometheus and Grafana Stack in docker-compose

**Actor**: Operator
**Preconditions**: Docker Engine and `docker compose` v2 available; node image builds; at least 4 node services defined; a local uncommitted `.env` holds the Grafana admin password (a committed `.env.example` documents the key); dev CA generated (E6-UC-8)
**Trigger**: `docker compose up -d --build`

### Primary Flow (Happy Path)
1. Operator copies `.env.example` to `.env`, sets the Grafana admin password, and runs `docker compose up -d --build`.
2. `prometheus` and `grafana` services start alongside the nodes. Prometheus (9090) and Grafana (3000) are published bound to `127.0.0.1` only.
3. Prometheus loads its scrape configuration and scrapes every node's `GET /metrics` over `https` using `tls_config` (`ca_file` = the dev CA, `server_name` matching the node certificate SAN), at least 4 targets.
4. Operator queries Prometheus `/api/v1/targets`: all node targets report `health = "up"`.
5. Operator opens Grafana at `http://127.0.0.1:3000`. The datasource and one dashboard are already provisioned (no manual import or setup beyond logging in with the `.env` credentials).
6. The dashboard renders chain height per node, peer connections by state, and finalization-time p50/p95 by algorithm, with data from at least two nodes.

**Postconditions**: Metrics from all nodes are visible in Grafana; stack is reproducible from the repository files plus a local `.env`.

### Alternative Flows
- **E6-UC-2-A1: Scale beyond 4 nodes** — with the scale compose file (n = 7 or 10), Prometheus scrapes all generated node targets; the dashboard shows each node as a separate series.
- **E6-UC-2-A2: PBFT vs PoW dashboards** — the finalization panel splits by `algorithm`; a PoW-only network shows only the `pow` series without panel errors.
- **E6-UC-2-A3: Prometheus to Grafana traffic** — Grafana reaches Prometheus over plain HTTP inside the compose network; this is explicitly out of scope of "all traffic TLS" (FR-9 covers node endpoints) and is documented, not treated as a defect.

### Error Flows
- **E6-UC-2-E1: A node is down** — one node container is stopped. Prometheus marks that target `down`; the dashboard shows a gap for that node while other nodes continue to render; Grafana does not crash.
- **E6-UC-2-E2: Scrape fails under TLS** — if Prometheus lacks the dev CA, or `server_name` does not match the node certificate SAN, the target shows `up = 0` with a TLS error. The fix is correcting the `tls_config`; the scrape job MUST NOT disable certificate verification (`insecure_skip_verify` is not allowed outside `INSECURE_DEV_MODE`), and a static check on `docker/prometheus.yml` asserts this.
- **E6-UC-2-E3: Invalid provisioning file** — a malformed datasource or dashboard JSON causes Grafana to log a provisioning error. The stack test detects this by asserting the dashboard is retrievable via the Grafana HTTP API after startup; a missing dashboard fails the check.
- **E6-UC-2-E4: Missing Grafana password** — `.env` is absent or the password key is empty. Compose fails or Grafana refuses to start; there is no committed default password and no fallback to the Grafana default `admin/admin`.
- **E6-UC-2-E5: Non-loopback port publication** — a static check on the compose file fails if the Prometheus or Grafana port mapping lacks the `127.0.0.1:` prefix (which would expose them on all host interfaces).

### Edge Cases
- **E6-UC-2-EC1**: Grafana starts before Prometheus is ready: the datasource is provisioned anyway and panels recover once Prometheus is up, without manual intervention.
- **E6-UC-2-EC2**: Grafana container restarted: the datasource and dashboard are re-provisioned from files (no reliance on a persisted manual configuration).
- **E6-UC-2-EC3**: `.env` is never committed (git-ignored); only `.env.example` is tracked, and it contains no real password.

### Data Requirements
- **Input**: `docker/prometheus.yml`, `docker/grafana/provisioning/` (datasource + dashboard JSON), compose services, `.env` (Grafana password).
- **Output**: Running Prometheus (scrape targets) and Grafana (dashboard), reachable on loopback only.
- **Side Effects**: Additional containers and loopback ports; no change to node behavior.

---

## E6-UC-3: Per-IP Rate Limiting (NFR-SEC3)

**Actor**: API client (legitimate or abusive), SPA, peer node, attacker
**Preconditions**: Node running as a single uvicorn worker with `proxy_headers=False` and `FORWARDED_ALLOW_IPS` unset; `RATE_LIMIT_PER_MIN` unset (default 100); `RATE_LIMIT_EXEMPT_VALIDATORS` unset (default `false`); tracked-IP cap at default 10,000
**Trigger**: Any REST request or WebSocket upgrade request to a node

### Primary Flow (Happy Path)
1. Client A (IP X) sends 100 requests within 60 seconds. All are processed normally.
2. Client A sends the 101st request within the same 60-second window.
3. The pure ASGI rate-limit middleware returns HTTP 429 using the standard error envelope (built through the shared envelope function in `errors.py`; `code` identifies rate limiting) and a `Retry-After` header holding a positive integer number of seconds until the sliding window allows another request.
4. Client B (IP Y) sends its 101st request in the same window; it is NOT rate limited because the limit is per source IP.
5. After the window slides forward (60 s since the oldest counted request), Client A's requests succeed again.

**Postconditions**: Limiter state holds at most cap x limit timestamps (default 10,000 x 100); rejected requests have no side effects on chain or mempool.

### Alternative Flows
- **E6-UC-3-A1: Custom limit** — operator sets `RATE_LIMIT_PER_MIN=20` and restarts; the 21st request in the window returns 429. No code change is involved.
- **E6-UC-3-A2: Validator exemption enabled** — the operator sets `RATE_LIMIT_EXEMPT_VALIDATORS=true`. The allow-list is built only from the static `ValidatorSet` configuration. Requests from those validator addresses (and only those) are not counted; requests from any other IP remain limited. The node logs that the exemption is active at boot.
- **E6-UC-3-A3: WebSocket upgrade counted** — each `WS /ws/blocks` or `WS /ws/pbft` upgrade request counts toward the client's window; the 101st upgrade attempt in the window is denied before the upgrade completes (see E6-UC-3-E6 for the mechanism).
- **E6-UC-3-A4: SPA honors Retry-After** — the SPA receives a 429 with `Retry-After: 12`; it shows a "too many requests, retry after 12 seconds" message, does not auto-retry before that time elapses, and may resume (manual or automatic retry) once the interval has passed. A missing or malformed `Retry-After` falls back to a generic rate-limit message with no crash.
- **E6-UC-3-A5: Browser-origin request is readable** — a request from the SPA origin (cross-origin to the node) that is rate limited returns a real 429 carrying the CORS allow-origin header, and `Retry-After` is listed in `Access-Control-Expose-Headers`, so the SPA reads status and header instead of seeing an opaque network/CORS failure. This holds for the simple request and for the preflight path.
- **E6-UC-3-A6: Per-IP acceptance test method** — because a host-side client always appears as the single Docker bridge-gateway IP, per-IP acceptance tests (second IP not limited, window per IP) use ASGI scope injection (in-process, with a controlled client address in the scope) or multiple client containers on distinct bridge addresses. A host-side client is used only for single-IP cases.

### Error Flows
- **E6-UC-3-E1: Limit exceeded on any endpoint** — the 429 envelope and `Retry-After` apply uniformly to `POST /documents`, `GET /documents/{hash}`, `GET /chain`, `GET /node/info`, `GET /metrics/consensus`, `GET /metrics`, `POST /peers/register`, and `GET /peers`. A rejected `POST /documents` does not create a pending record. The middleware runs before FastAPI exception handlers, so the body is produced by the shared envelope builder, not by an exception handler.
- **E6-UC-3-E2: `X-Forwarded-For` spoofing against a real server** — an attacker at IP X sends requests rotating `X-Forwarded-For` (and `X-Real-IP`, `Forwarded`) values per request. The test runs against a REAL uvicorn server (not an in-process ASGI test client, which would bypass `proxy_headers` handling). The limiter keys on the transport-level peer address only, so the 101st request is still 429. Conversely, sending a victim's address in `X-Forwarded-For` does not cause the victim to be limited.
- **E6-UC-3-E3: SPA receives 429** — the Epic 4 SPA treats a 429 as a rate-limit message ("too many requests, retry after N seconds"), not as a verification failure ("document not found/invalid"). See E6-UC-29 for the client implementation ownership.
- **E6-UC-3-E4: Invalid rate-limit configuration** — a `RATE_LIMIT_PER_MIN` that is zero, negative, non-numeric, or empty, a non-boolean `RATE_LIMIT_EXEMPT_VALIDATORS`, or an invalid tracked-IP cap makes the node fail fast at boot with a clear configuration error (see E6-UC-30); it does not silently fall back to unlimited.
- **E6-UC-3-E5: Attacker registers via `POST /peers/register`** — an attacker whose address is not in the static `ValidatorSet` registers itself as a peer through the unauthenticated `POST /peers/register` (it appears in `PeerInfo`/`GET /peers`). With `RATE_LIMIT_EXEMPT_VALIDATORS=true` set, the attacker still does NOT gain exemption: its 101st request in the window returns 429. The allow-list is read only from the static `ValidatorSet` configuration and never from `PeerInfo`. With the flag at default `false`, nobody is exempt.
- **E6-UC-3-E6: Rate-limited WebSocket upgrade** — the upgrade request is denied before it completes. If the pinned uvicorn/websocket backend supports the ASGI websocket denial-response extension, the client receives an HTTP 429 with envelope and `Retry-After`. Otherwise the middleware closes before `accept` and uvicorn answers HTTP 403 (documented fallback; the client then sees 403, not 429). The mechanism actually in effect and the pinned uvicorn version are recorded in the OWASP checklist (E6-UC-5), and a test asserts the behavior of whichever mechanism the pinned version provides. In both cases the websocket handler is never entered and no WebSocket session is created.
- **E6-UC-3-E7: Message flood after upgrade (accepted risk)** — a client that has completed the WebSocket upgrade then sends thousands of messages. The per-IP limiter counts only the upgrade request, not subsequent messages, so they are not limited by it. This is recorded as an accepted risk under OWASP API4 (E6-UC-5); no test requires the flood to be rejected, and a documentation check requires the risk row to exist.
- **E6-UC-3-E8: Multiple workers misconfiguration** — a start configuration with more than one uvicorn worker is rejected (or a static/config check fails), because limiter state is per-process and N workers would multiply the effective limit.

### Edge Cases
- **E6-UC-3-EC1**: Exactly 100 requests in the window all succeed; only the 101st is limited (boundary).
- **E6-UC-3-EC2**: 10,000 distinct source IPs each send one request (and 10,001 to force eviction): limiter memory stays bounded (LRU-capped tracked-IP map; expired entries evicted first), each IP's log is a `deque(maxlen=limit)`, and the node keeps serving requests. Worst-case memory is cap x limit timestamps.
- **E6-UC-3-EC3**: When the tracked-IP cap is reached and the least-recently-used entry is evicted, the evicted IP starts with a fresh window; this is documented as accepted behavior of the bound and does not allow a single actively-used IP to exceed its limit (an active IP is not the LRU entry).
- **E6-UC-3-EC4**: Burst of 150 concurrent requests from one IP: exactly 100 are processed and 50 receive 429 (no race that lets more than 100 through; the check-and-append is atomic within the event loop).
- **E6-UC-3-EC5**: IPv6 and IPv4-mapped IPv6 forms of the same client (`::ffff:1.2.3.4` and `1.2.3.4`) count against one window.
- **E6-UC-3-EC6**: `Retry-After` is an integer of at least 1 and no larger than the window length (60 by default); it is consistent with when the next request would actually succeed.
- **E6-UC-3-EC7**: Default configuration does NOT exempt node-to-node traffic: with the flag unset, a peer node IP is limited like any other client.
- **E6-UC-3-EC8**: The 429 response itself is not counted twice and is not logged with request bodies (no sensitive data in logs).
- **E6-UC-3-EC9**: Middleware order: `CORSMiddleware` is outermost, then the rate limiter. A 429 therefore carries CORS headers; a test asserts `Access-Control-Allow-Origin` and `Access-Control-Expose-Headers` containing `Retry-After` on a 429 from an allowed origin.
- **E6-UC-3-EC10**: The limiter treats `http` and `websocket` scopes identically for keying; a `lifespan` scope is passed through untouched.
- **E6-UC-3-EC11**: With the exemption enabled, a validator address that appears in the static `ValidatorSet` but connects over an IPv4-mapped IPv6 form is still recognized as exempt (same normalization as EC5).
- **E6-UC-3-EC12**: Requests to `GET /metrics` from Prometheus (its own IP) are counted like any other client and stay well under the limit at the default scrape interval.

### Data Requirements
- **Input**: Source IP of the connection (transport peer address only); `RATE_LIMIT_PER_MIN`; `RATE_LIMIT_EXEMPT_VALIDATORS`; tracked-IP cap; static `ValidatorSet`.
- **Output**: Normal response, or 429 with envelope and `Retry-After` (or WebSocket pre-upgrade denial).
- **Side Effects**: In-memory bounded limiter state only; no database writes.

---

## E6-UC-4: Reject Unregistered Issuer on PBFT-Forwarded Pre-Signed Record (NFR-SEC4)

**Actor**: Non-primary validator node forwarding a record (or an attacker impersonating one)
**Preconditions**: Network in PBFT mode (the intake channel requires the Epic 3 PBFT primary); the `forward_record` channel, its message type, `NodeKeyPair` sender signing, `ValidatorSet` sender check, primary accept/queue path, reply-code enum and HTTP mapping are OWNED AND BUILT BY EPIC 3 FR-22 (see the cross-cutting contract above); Epic 6 adds ONLY the `IssuerRegistry` check and the `unregistered_issuer` reply in the primary's handler. The receiving node (the current primary) has a loaded `IssuerRegistry` (Epic 3 FR-23) and the static `ValidatorSet`; the forwarder is connected to the primary over `wss://` `WS /ws/pbft`; `FORWARD_ACK_TIMEOUT_MS` is at its default of 2000
**Trigger**: A `forward_record` message carrying a signed `DocumentRecord` arrives at the primary on `WS /ws/pbft`

**Scope (v1.8):** the channel, authentication, handler check order, dedupe, view-change handling, timeout and HTTP mapping are Epic 3 (UC-15 / UC-16, plan Slices 13 and 17b). This use case, owned by plan Slice 31, adds only check 4 of the handler order (`IssuerRegistry` membership -> `unregistered_issuer`) and the PoW-mode block-level evidence (A7). Before Slice 31 an unknown issuer yields `invalid_record` via resolver miss; Slice 31 updates that Slice 17b test. Flows marked MOVED below are kept as pointers so existing references resolve.

### Primary Flow (Happy Path)
1. Node 2 (non-primary) receives a public `POST /documents`, signs the record server-side with its configured `issuer_id`, and sends it to the primary as `{type: "forward_record", request_id, record, sender_id, sender_signature}` on `WS /ws/pbft`, signed with its `NodeKeyPair`. The original `POST /documents` handler on node 2 awaits the reply for at most `FORWARD_ACK_TIMEOUT_MS`.
2. The primary verifies the `NodeKeyPair` signature of the sender and that the sender is a member of the `ValidatorSet`.
3. The primary checks the record's `issuer_id` against its `IssuerRegistry` (the only Epic 6 addition); it is present.
4. The primary verifies the record signature, applies the single authoritative duplicate rule (finalized blocks and its own mempool) and accepts the record into its pending batch/mempool.
5. The primary replies with exactly one `forward_record_reply {request_id, code: "accepted"}` (sent after the decision, not after finalization). Node 2 returns the normal accepted acknowledgement of `POST /documents`.

**Postconditions**: The record is queued and will be included in the next proposal; the client of node 2 sees the same status and body as for a primary-received request.

### Alternative Flows
- **E6-UC-4-A1: Public path unaffected** — a normal public `POST /documents` signs with the node's own configured `issuer_id` (always registered) and is accepted per Epic 3. A public `POST /documents` that carries a `signature` (or `issuer_id`) body field is still rejected with HTTP 400 (Epic 3), never reaching the registry check.
- **E6-UC-4-A2: Forwarder is the primary itself** — a public `POST /documents` arrives at the current primary. No `forward_record` message is sent; the primary signs with its own registered `issuer_id` and queues the record directly. The registry check still applies to its own issuer (which is registered), so the record is accepted.
- **E6-UC-4-A3: Rate-limit exemption irrelevant** — `forward_record` messages are WebSocket messages and are not rate limited per message (only the WS upgrade counts, E6-UC-3-A3); the exemption flag therefore neither helps nor hinders the issuer check, which always runs.
- **E6-UC-4-A4: Duplicate forward of the same record — MOVED to Epic 3** — owned by Epic 3 UC-16-A5 (duplicate delivery -> `duplicate` -> 409) and UC-15-A1 (mapping), plan Slices 17b / 13. Epic 6 adds nothing here.
- **E6-UC-4-A5: Stale view at the sender (`not_primary`) — MOVED to Epic 3** — owned by Epic 3 UC-16-A4 / UC-16-E3 (`not_primary`, no automatic re-forward UC-15-A3), plan Slices 17b / 13. Epic 6 contribution only: after the retry the record reaches the node that finally accepts it, where the `IssuerRegistry` check (this use case, primary flow step 3) also applies.
- **E6-UC-4-A6: Forward arrives before the sender's connection is authenticated — MOVED to Epic 3** — owned by Epic 3 UC-16-E1 / UC-16-E2 (`auth_failed` / `not_validator`, HTTP 502), plan Slice 17b. Epic 6 adds nothing here.
- **E6-UC-4-A7: PoW mode — no intake channel; block-level rejection is the evidence (SEC4; SEC3 is mode-independent)** — **dependency: this flow asserts `blocks_rejected_total{failure_type="signature"}`, which is delivered by plan Slice 30 (E6-UC-1); the test cannot pass before Slice 30 and Slice 31 therefore depends on Slice 30.** The network runs in PoW mode. There is no primary and no `forward_record` channel, so the `unregistered_issuer` reply cannot occur and is not tested here. The SEC4 evidence in this mode is block-level: a block received from a peer (broadcast over `WS /ws/blocks` or chain sync) contains a `DocumentRecord` whose `issuer_id` the key resolver (Epic 3 FR-23) cannot find. The Epic 2 FR-6 signature check rejects the block with `failure_type = "signature"`; the block is not appended, `blocks_rejected_total{failure_type="signature"}` increases by 1 (E6-UC-1), and the chain tip is unchanged. Test expectation: a dedicated test builds a block whose record carries an `issuer_id` absent from the receiving node's `IssuerRegistry` (otherwise valid hash, link, Merkle root and difficulty), submits it through the PoW broadcast path and through chain sync, and asserts rejection with `failure_type = "signature"` on both paths and no change to the chain. The SEC3 evidence in PoW mode is the per-IP limit (E6-UC-3), which is mode independent. The `nfr_report.md` SEC3/SEC4 rows state both modes (E6-UC-27).
- **E6-UC-4-A8: Two non-primaries forward the same hash (exactly one accepted) — MOVED to Epic 3** — owned by Epic 3 UC-16-A2 (plan Slice 17b): exactly one `accepted` and one `duplicate` (409). Epic 6 adds nothing here.
- **E6-UC-4-A9: Ack timeout (`forward_timeout`) — MOVED to Epic 3** — owned by Epic 3 UC-15-E2 / UC-15-E3 / UC-15-E4 (503 with `Retry-After`, late reply discarded, connection failure), plan Slice 13 (mapping against the stub) and Slice 17b (real channel). Epic 6 adds nothing here; the `FORWARD_ACK_TIMEOUT_MS` boot validation is Epic 3 UC-15-E1 (E6-UC-30 only references it).
- **E6-UC-4-A10: View change in flight — MOVED to Epic 3** — owned by Epic 3 UC-16-A3 (plan Slice 17b, which depends on view-change Slice 18). Epic 6 adds nothing here.

### Error Flows
- **E6-UC-4-E1: Unregistered issuer** — a `forward_record` from a valid validator carries a signed record whose `issuer_id` is absent from `IssuerRegistry`. The primary replies on the WebSocket with `forward_record_reply {request_id, code: "unregistered_issuer"}` (a reply code, not an HTTP status); the record is NOT in the mempool, `mempool_size` is unchanged, and no block can include it. The forwarding non-primary maps the reply to HTTP 403 via the envelope on the original `POST /documents`. Check order: this is check 4 of the handler order, so a record that is both unregistered-issuer and badly signed also gets `unregistered_issuer` (not `invalid_record`); that adjacent pair 4/5 is tested in Epic 3 UC-16-E9 (applies once Slice 31b exists; owned by Slice 31b) and is not duplicated here.
- **E6-UC-4-E2: Non-validator sender — MOVED to Epic 3** — owned by Epic 3 UC-16-E2 (`not_validator`, HTTP 502), plan Slice 17b. Epic 6 cross-reference only: the registry check is not reached for such a sender (it is check 4, after checks 1-3 of the handler order), and TLS admission alone confers no ability to forward (E6-UC-8-EC1).
- **E6-UC-4-E3: Invalid sender authentication — MOVED to Epic 3** — owned by Epic 3 UC-16-E1 (`auth_failed`, HTTP 502), plan Slice 17b. Epic 6 adds nothing here.
- **E6-UC-4-E4: Malformed forwarded record** — missing `issuer_id`, malformed hash, or oversized metadata is rejected with the reply code `invalid_record` (Epic 3 UC-16-E4, handler check 3) BEFORE the registry lookup (check 4, the Epic 6 addition); `unregistered_issuer` is reserved for well-formed records with an unknown issuer. Epic 6 test: the ordering check 3 before check 4 holds after Slice 31 inserts check 4.
- **E6-UC-4-E5: Registered issuer, invalid signature** — `issuer_id` is registered but the record signature does not verify. The record is rejected with `invalid_record` (signature failure per the Epic 2 check, never `unregistered_issuer`) and is not queued; HTTP 422 on the original request.
- **E6-UC-4-E6: Public path never yields an issuer rejection** — a public `POST /documents` containing a `signature` (or `issuer_id`) body field returns HTTP 400 via the envelope (validation error), not 403. HTTP 403 for `unregistered_issuer` reaches a client only as the mapped result of a forwarded record (E6-UC-4-E1) or if a pre-signed record ever reached a public HTTP path; a test asserts that no public route accepts a pre-signed record.
- **E6-UC-4-E7: Reply code outside the closed enum — MOVED to Epic 3** — owned by Epic 3 UC-16-E8 (primary handler) and UC-15-E5 (forwarder reply parser: unknown code -> 502, never acceptance), plan Slices 17b / 13. Epic 6 adds nothing here beyond the fact that `unregistered_issuer` is one of the seven enumerated codes.
- **E6-UC-4-E8: HTTP mapping table — MOVED to Epic 3** — owned by Epic 3 UC-15-A1 / UC-15-E6, plan Slice 13 (parameterised mapping test against a stub `RecordForwarder`). Epic 6 contribution only: once Slice 31 is in, the `unregistered_issuer` -> 403 row is exercised end to end through the real channel (E6-UC-4-E1).

### Edge Cases
- **E6-UC-4-EC1**: `issuer_id` differing from a registered one only by case or trailing whitespace is treated as unregistered (exact match), yielding `unregistered_issuer`.
- **E6-UC-4-EC2**: After an `unregistered_issuer` reject, resubmitting the same `document_hash` with a valid registered issuer is accepted; the rejected attempt did not leave a duplicate-hash lock (Epic 3 409 rule) in the mempool.
- **E6-UC-4-EC3**: The same unregistered record forwarded repeatedly yields `unregistered_issuer` each time; the WS session stays usable (a reject reply does not close the channel), and the rejects are logged without key material. Message-level flooding on the open WS is the accepted API4 risk (E6-UC-3-E7).
- **E6-UC-4-EC4**: A record already finalized on-chain is forwarded again (replayed by a slow forwarder): the primary rejects it as a duplicate and it is not included in a second block (Epic 3 UC-16-E6).
- **E6-UC-4-EC5**: Two different validators forward the same `document_hash` concurrently — MOVED to Epic 3 UC-16-A2 (exactly one `accepted`, the other `duplicate`).
- **E6-UC-4-EC6**: PoW-mode scope: there is no primary and no `forward_record` channel in PoW mode, so the `unregistered_issuer` reply control is PBFT-only. The PoW-mode evidence is the block-level rejection by the Epic 2 FR-6 signature check (`failure_type = "signature"`) when the resolver cannot find the block's record issuer, covered by the dedicated test of E6-UC-4-A7. The OWASP checklist (E6-UC-5) and the NFR report (E6-UC-27) state both modes.
- **E6-UC-4-EC7**: Late or duplicated `forward_record_reply` / unknown `request_id` — MOVED to Epic 3 UC-16-E7 and UC-15-EC3 (plan Slices 17b / 13). Epic 6 adds nothing here.
- **E6-UC-4-EC8**: `FORWARD_ACK_TIMEOUT_MS` boundary — MOVED to Epic 3 UC-15-EC2 (timeout boundary) and UC-15-E1 (value 1 accepted, 0 rejected at boot), plan Slice 13. E6-UC-30 references it only as part of the fail-fast list.

### Data Requirements
- **Input**: `forward_record` message `{type, request_id, record, sender_id, sender_signature}` where `record` is a signed `DocumentRecord` (`document_hash`, `signature`, `issuer_id`, `issued_at`, `metadata`); `FORWARD_ACK_TIMEOUT_MS`.
- **Output**: `forward_record_reply {request_id, code}` with `code` in the closed enum; HTTP response on the original `POST /documents` per the mapping table.
- **Side Effects**: Accepted records enter the mempool; rejected records produce none and are logged without key material.

---

## E6-UC-5: OWASP API Security Top 10 (2023) Checklist

**Actor**: Thesis author, security reviewer
**Preconditions**: Slices 30-32 controls designed; Epic 3 API endpoints defined
**Trigger**: Authoring and reviewing `docs/security/owasp_api_top10_checklist.md`

### Primary Flow (Happy Path)
1. Author creates the checklist with one row for each of API1:2023 through API10:2023.
2. For each row the author states the control addressing it, with the Epic/FR or test that evidences it (for example API4 Unrestricted Resource Consumption to rate limit FR-4/FR-5 and `tests/node/test_rate_limit.py`).
3. Reviewer verifies every referenced test or FR exists.
4. Checklist is committed.

**Postconditions**: All 10 rows are filled; Chapter 3 can cite the checklist for NFR-SEC3 and NFR-SEC4.

### Alternative Flows
- **E6-UC-5-A1: Not applicable row** — a category such as API2 (Broken Authentication) where the prototype has intentionally unauthenticated read endpoints is marked "not applicable" with a written reason tied to the PRD scope.
- **E6-UC-5-A2: Accepted risk row** — a residual risk (for example no authentication on `POST /peers/register`, per the Epic 3 known gap) is marked "accepted risk" with the reason and the epic that measures it (Epic 5).

### Error Flows
- **E6-UC-5-E1: Empty or missing row** — a category is absent, or a cell is blank or says only "TBD". The checklist is considered failing; a docs check (or review gate) rejects it.
- **E6-UC-5-E2: Dangling evidence** — a row cites a test file, FR, or endpoint that does not exist. Review flags the row and it must be corrected before merge.
- **E6-UC-5-E3: Mandatory records missing** — the checklist lacks any of: the API4 row recording WebSocket message-level flooding after upgrade as an accepted risk (FR-5); the API8/API9 rows recording `/metrics` unauthenticated on the node port as an accepted prototype risk with Prometheus/Grafana limited to `127.0.0.1` (FR-3); the WebSocket denial mechanism in effect and the pinned uvicorn version (FR-5). A docs check fails the review.
- **E6-UC-5-E4: Mode scope missing** — the SEC4 row (input validation plus unregistered-issuer rejection; OWASP API5/API3 as applicable) cites the `unregistered_issuer` reply on `forward_record` as PBFT-mode evidence only and does not state the PoW-mode evidence (block-level rejection by the Epic 2 signature check, E6-UC-4-A7). SEC3 (per-IP rate limit, OWASP API4) is a separate row and is mode-independent; it is never merged with the SEC4 row or given a mode scope. The docs check fails the review.

### Edge Cases
- **E6-UC-5-EC1**: API4 (resource consumption) and API8 (security misconfiguration) rows reference `RATE_LIMIT_PER_MIN`, `RATE_LIMIT_EXEMPT_VALIDATORS`, `INSECURE_DEV_MODE`, the `proxy_headers=False` / single-worker settings, and the XFF-spoofing control.
- **E6-UC-5-EC2**: A row legitimately relies on a single control used elsewhere (for example the `unregistered_issuer` check on `forward_record` for API5 Broken Function Level Authorization); duplicate evidence references are allowed.
- **E6-UC-5-EC3**: A new endpoint such as `GET /metrics` is added to the API; the checklist rows are reviewed again for it (API9 Improper Inventory Management) and updated if needed.
- **E6-UC-5-EC4**: The API5/API1 rows cite that attackers hold CA-signed TLS certificates (insider threat model) and that application-layer `NodeKeyPair` authentication, not TLS, gates consensus participation. They also cite the per-service key isolation (E6-UC-10-E6, E6-UC-29-A4): the attacker has its own key volume and cannot read any `node*` key file.
- **E6-UC-5-EC5**: The `forward_record` row cites the Epic 3 FR-22 closed reply-code enum as the contract and Epic 6 FR-6 as only the `IssuerRegistry` addition, so the checklist does not claim the channel as an Epic 6 deliverable.

### Data Requirements
- **Input**: Controls from Epics 2-6, test file names, pinned uvicorn version.
- **Output**: `docs/security/owasp_api_top10_checklist.md` with 10 filled rows.
- **Side Effects**: Documentation only.

---

## E6-UC-6: No-PII Schema Guard (NFR-C1)

**Actor**: Developer, CI system
**Preconditions**: Block and `DocumentRecord` schemas exist (Epic 2); an explicit allow-list of fields exists in `tests/core/test_no_pii.py`
**Trigger**: `pytest` run (local or CI)

### Primary Flow (Happy Path)
1. The test introspects the `DocumentRecord` and `Block` schemas.
2. It compares every field to the allow-list: `document_hash`, `signature`, `issuer_id`, `issued_at`, size-capped `metadata`, plus the Epic 2 block structure fields (index, previous hash, merkle root, timestamp, proposer, consensus fields, etc.).
3. All fields are on the list; the test passes.

**Postconditions**: The on-chain data model is confirmed PII-free by construction; the persisted schema is unchanged by Epic 6.

### Alternative Flows
- **E6-UC-6-A1: Metadata within cap** — a record with metadata exactly at the maximum size is accepted by the schema; the guard also asserts the cap constant is present.
- **E6-UC-6-A2: Legitimate field addition** — a developer intentionally adds a non-PII structural field and updates the allow-list in the same change with justification; the test passes and the diff makes the change reviewable.

### Error Flows
- **E6-UC-6-E1: Unlisted field added** — a developer adds `owner_name` (or any field not on the allow-list) to `DocumentRecord` or `Block`. The test fails and the build (CI) is blocked.
- **E6-UC-6-E2: Metadata cap removed or exceeded** — the cap on `metadata` is removed or oversized metadata is accepted. The test fails because the size bound is part of the guard; oversized metadata submitted via API is rejected with the standard validation error.

### Edge Cases
- **E6-UC-6-EC1**: A nested field is added inside a sub-model of the block (for example inside consensus data); the guard walks nested models and still fails.
- **E6-UC-6-EC2**: `metadata` is free-form content; the guard validates schema and size only, not content, and this limitation is stated in the test docstring and the OWASP checklist (clients must not place PII in metadata).

### Data Requirements
- **Input**: Pydantic/dataclass schema definitions; allow-list.
- **Output**: Test pass/fail.
- **Side Effects**: None.

---

## E6-UC-7: TLS 1.3 for REST and WebSocket (NFR-SEC2)

**Actor**: Client (SPA, script, Prometheus), peer node, security tester
**Preconditions**: Dev CA and per-node server certificates generated (E6-UC-8); `TLS_CERT`, `TLS_KEY`, `TLS_CA` configured; `INSECURE_DEV_MODE` unset; node started by the programmatic uvicorn entry point with `config.ssl.minimum_version = ssl.TLSVersion.TLSv1_3` set after `config.load()`
**Trigger**: Any connection to a node's REST or WebSocket port, or any outbound peer connection

### Primary Flow (Happy Path)
1. Security tester runs `openssl s_client -connect localhost:8001 -tls1_3` against the live node; the handshake succeeds with a server certificate chaining to the dev CA. The client supplies no client certificate and still connects (server authentication only).
2. Tester runs the same with `-tls1_2`; the handshake is refused (protocol version alert).
3. Tester confirms the same behavior on every node of the compose stack.
4. The automated test (`tests/node/test_tls.py`) repeats steps 1-2 programmatically against the LIVE listener (a TLS 1.2-capped Python `ssl` client fails; a TLS 1.3 client succeeds).

**Postconditions**: Every node accepts only TLS 1.3 on its live listener.

### Alternative Flows
- **E6-UC-7-A1: PoW block broadcast over `wss://`** — in PoW mode, a mined block broadcast over `wss://` `WS /ws/blocks` reaches all peers and the network converges.
- **E6-UC-7-A2: PBFT messages over `wss://`** — in PBFT mode, pre-prepare, prepare, and commit messages (and `forward_record`) travel over `wss://` `WS /ws/pbft`; a document submitted to node 1 is finalized on all nodes.
- **E6-UC-7-A3: SPA over HTTPS** — the Epic 4 SPA, with its configurable HTTPS base URL pointing at a node, issues a document and verifies it successfully; the browser trusts the dev CA in the test setup (see E6-UC-29).
- **E6-UC-7-A4: Prometheus scrape over https** — Prometheus scrapes every node's `/metrics` over `https` with `tls_config` (`ca_file`, `server_name`) and all targets are `up` (E6-UC-2).
- **E6-UC-7-A5: Attacker with CA-signed cert** — an Epic 5 attacker container holding a CA-signed certificate connects over TLS 1.3, registers as a peer, and participates at the transport level; its consensus resistance is then measured by Epic 5 (E6-UC-8-EC1).

### Error Flows
- **E6-UC-7-E1: TLS 1.2 client refused** — a client capped at TLS 1.2 (`openssl s_client -tls1_2`, or Python `ssl` with `maximum_version = TLSv1_2`) fails the handshake on REST and WebSocket ports; no HTTP response is produced.
- **E6-UC-7-E2: TLS 1.1/1.0/SSLv3 refused** — older protocol versions are likewise refused.
- **E6-UC-7-E3: Plain HTTP to a TLS port** — `curl http://node:8001/node/info` fails (connection reset or bad-request-to-TLS behavior); no data is served in the clear and no redirect to a plain port exists.
- **E6-UC-7-E4: No plain listener** — with `INSECURE_DEV_MODE` unset, a port scan of the node container finds no plain HTTP/WS listener; an outbound peer attempt to `ws://` is refused by configuration.
- **E6-UC-7-E5: Context-object assertion is not accepted** — the enforcement test must connect to the running listener. A test that only inspects an `SSLContext` object's `minimum_version` does not satisfy the requirement (review criterion); using uvicorn's `ssl_version`/`ssl_ciphers` options as the enforcement mechanism is likewise not accepted.
- **E6-UC-7-E6: Wrong hostname** — an outbound client connects to a node using a name absent from the certificate SAN (for example the raw IP); hostname verification fails and the connection is refused.
- **E6-UC-7-E7: Unknown CA** — an outbound client or Prometheus without the dev CA (or with a different CA) rejects the node certificate; the connection is refused, never downgraded.

### Edge Cases
- **E6-UC-7-EC1**: Expired node certificate: handshakes fail certificate validation on the client side; node logs the cause; no fallback to plain mode occurs.
- **E6-UC-7-EC2**: Certificate Subject Alternative Name does not match the hostname used (for example compose service name vs `localhost`): hostname verification fails and the connection is refused; the generator script includes both names in the SAN.
- **E6-UC-7-EC3**: Re-running the Slice 19 smoke test (and Epic 5 attacker harness) with TLS enabled passes; the attacker image mounts the same dev CA.
- **E6-UC-7-EC4**: TLS overhead on benchmarks: all NFR measurements are taken with TLS on, and the report states this (see E6-UC-27).
- **E6-UC-7-EC5**: A TLS 1.3-only client that offers no client certificate succeeds on every node (no mTLS requirement; a handshake that demands a client certificate would fail this check).
- **E6-UC-7-EC6**: The TLS minimum is set on the context after `config.load()`; if the server is started through a path that skips this step (non-programmatic start), the live-listener test fails, which guards against accidental regressions. The server-side `minimum_version` hook lives in `src/node/tls.py` (alongside the client factory) and is called from `main.py`; a test asserts that `main.py` invokes the hook and that `main.py` itself constructs no `ssl.SSLContext`.

### Data Requirements
- **Input**: `TLS_CERT`, `TLS_KEY`, `TLS_CA`; client TLS parameters.
- **Output**: Encrypted channel at TLS 1.3 minimum with server authentication.
- **Side Effects**: Handshake failures are logged without secrets.

---

## E6-UC-8: Dev CA, Certificate Generation, Server Authentication, and Single Client Factory

**Actor**: Operator, node (as TLS client and server), attacker holding a CA-signed certificate, an impostor with a self-signed or foreign-CA certificate
**Preconditions**: Generation script `docker/certs/gen_dev_certs.py` available; `.gitignore` covers key files
**Trigger**: Operator runs the generation script; nodes make or receive peer connections

### Primary Flow (Happy Path)
1. Operator runs the script for n nodes (any n from 4 to 10); it creates a dev CA and one server certificate/key per node (`node1`..`node10` as requested) plus certificates for the attacker service names (Epic 5), with SANs covering compose service names and `localhost`.
2. Certificates and keys are delivered to containers through named volumes populated by the one-shot init service (E6-UC-10). There is ONE key/cert volume (or compose `volume.subpath`) PER SERVICE: each node and each attacker service gets its own volume holding only its own material (`NodeKeyPair`, `IssuerKeyPair`, TLS key and certificate) plus the CA certificate mounted read-only. The CA certificate (public) is also mounted read-only into Prometheus and k6. The dev-CA PRIVATE key stays in the init service's own volume or on the operator host and is never mounted into any runtime container (node, attacker, Prometheus, Grafana, k6).
3. Node 1 opens `https://` and `wss://` connections to node 2 through the single client factory in `src/node/tls.py`; it verifies node 2's server certificate against `TLS_CA` and the expected hostname; verification succeeds.
4. Node 2 does not request or verify a client certificate. Node 1's identity is established at the application layer by `NodeKeyPair`-signed messages and `ValidatorSet` membership.

**Postconditions**: Every outbound connection is server-authenticated; no private key is tracked by git; the dev CA is documented as prototype-only; there is exactly one client-side SSL-context/HTTP-client factory.

### Alternative Flows
- **E6-UC-8-A1: Regeneration** — rerunning the script produces a fresh CA and certificates (or reuses existing ones when instructed); after regeneration and a stack restart, nodes reconnect.
- **E6-UC-8-A2: Attacker image mounts CA-signed cert** — the Epic 5 attacker container trusts the dev CA (read-only CA certificate), holds a CA-signed certificate and key under its service name in its OWN per-service volume, and connects to nodes over TLS to run attack scenarios (insider threat model; Epic 5 findings state this). It holds no `node*` key material (E6-UC-8-E10).
- **E6-UC-8-A3: Node count parameter** — the generator is invoked with n = 4, 7, and 10; the output contains exactly the requested node names with non-colliding SANs and file names (also E6-UC-24-E3).

### Error Flows
- **E6-UC-8-E1: Server certificate not signed by the CA (outbound)** — node 1 connects to a peer that presents a self-signed or foreign-CA certificate. The TLS handshake fails; the peer is not added as connected, `peer_connections` does not count it as healthy, and an error is logged.
- **E6-UC-8-E2: Unauthorized peer rejected at the application layer, not by TLS** (replaces the first draft's inbound client-certificate flow; there is NO mTLS) — a client with a valid or absent TLS client identity connects to a node's peer-facing endpoint. TLS completes with no client certificate required. A peer that is not in the `ValidatorSet`, or whose `NodeKeyPair` signatures do not verify, is rejected by the application-layer check (for example `not_validator` on `forward_record`, E6-UC-4-E2; rejected consensus messages per Epic 3). A test asserts that a connection without any client certificate is accepted at the TLS layer and rejected, if unauthorized, only at the application layer.
- **E6-UC-8-E3: Missing or unreadable `TLS_CA` / `TLS_CERT` / `TLS_KEY`** — the node refuses to start with a clear error (E6-UC-30). It does NOT fall back to plain HTTP/WS or to unverified TLS.
- **E6-UC-8-E4: Private key tracked by git** — a CI/test check (`git ls-files` for `*.key`, `*.pem` private keys, and the CA key) fails if any private key file is tracked.
- **E6-UC-8-E5: Verification disabled in code** — a static check (grep/AST/ruff rule) fails if `verify=False`, `ssl.CERT_NONE`, `check_hostname = False`, or an `http://`/`ws://` literal appears in outbound peer connection code outside the `INSECURE_DEV_MODE` branch.
- **E6-UC-8-E6: Second client factory** — a static check (test) scoped to `src/node/**` EXCLUDING `tls.py` fails the build if any module there constructs an `ssl.SSLContext` or an HTTP/WebSocket client directly. `connection_manager`, chain sync, the peers registry client and the `forward_record` forwarding client must all use the factory in `src/node/tls.py`. `attacks/`, `benchmarks/` and tests are exempt from the check (the attacker harness and k6/benchmark clients legitimately build their own clients, while still verifying certificates against the dev CA). A positive control: a fixture module under `src/node/` that builds a raw `ssl.SSLContext` makes the check fail, and the same code under `attacks/` or `tests/` does not.
- **E6-UC-8-E8: Dev-CA private key in a runtime volume** — a static compose check plus a container test fails if the CA private key file (for example `ca.key`) is mounted into, or present in the filesystem of, any runtime service (node, attacker, Prometheus, Grafana, k6). It may exist only in the init service's volume or on the operator host.
- **E6-UC-8-E9: Shared keys volume** — a static compose check fails if the same key/cert volume (without a distinct `subpath`) is mounted by more than one service, or if any node mounts another service's key material; each service mounts only its own key volume plus the CA certificate read-only (`:ro`).
- **E6-UC-8-E10: Attacker reads node keys** — a container test executes inside the attacker container and attempts to read every `node*` key file (`NodeKeyPair`, `IssuerKeyPair`, TLS private keys of `node1`..`node10`) by their known paths and by searching its mounted volumes; every attempt fails (file not present or permission denied) and no `node*` key bytes are found. The attacker sees only its own key material and the CA certificate.
- **E6-UC-8-E7: Wrong hostname (outbound)** — a peer presents a CA-signed certificate whose SAN does not include the name the client dialed; the outbound client rejects it (hostname verification stays on).

### Edge Cases
- **E6-UC-8-EC1**: A CA-signed certificate for a service not in the `ValidatorSet` (for example an attacker container) is accepted by outbound and inbound TLS handshakes (insider model); consensus participation is still gated by `ValidatorSet`/`NodeKeyPair` logic, so TLS alone does not confer it. This is intended, not a defect.
- **E6-UC-8-EC2**: Generated private-key files have mode `0600` (owner read/write only) and are readable by the non-root node UID (E6-UC-10); the mode test is skipped (and the skip noted) where the filesystem does not support POSIX permissions.
- **E6-UC-8-EC3**: CA rotation: nodes holding the old CA reject certificates from the new CA until reconfigured; there is no silent trust-on-first-use.
- **E6-UC-8-EC4**: The dev CA is documented as prototype-only (no revocation, no production PKI); the documentation check asserts the statement exists.

### Data Requirements
- **Input**: Script arguments (node count n, node/attacker service names, output directory).
- **Output**: CA certificate, per-node and per-attacker certificate and key files (git-ignored), each delivered into that service's own volume; the CA private key kept out of every runtime volume.
- **Side Effects**: Files written on the operator's machine or into the per-service cert/key volumes; nothing secret committed or logged.

---

## E6-UC-9: Explicit Insecure Dev Mode (`INSECURE_DEV_MODE`)

**Actor**: Operator, developer
**Preconditions**: Node configuration available
**Trigger**: Node boot with `INSECURE_DEV_MODE` unset, `true`, or another value

### Primary Flow (Happy Path)
1. Operator boots a node with `INSECURE_DEV_MODE` unset and valid TLS configuration.
2. Node starts TLS-only (E6-UC-7); no plain listener is opened; no insecure-mode warning appears.

**Postconditions**: Default behavior is secure.

### Alternative Flows
- **E6-UC-9-A1: Explicit insecure mode** — operator sets `INSECURE_DEV_MODE=true`. The node boots with plain HTTP/WS, logs a prominent warning at boot (for example a multi-line "INSECURE DEV MODE - traffic is unencrypted - not for production"), and serves requests in the clear. `TLS_*` paths are not required in this mode.

### Error Flows
- **E6-UC-9-E1: Default must not be plain** — a test boots the node with the flag unset and asserts a plain HTTP request to the service port gets no valid response, and no `ws://` upgrade succeeds.
- **E6-UC-9-E2: TLS misconfiguration without the flag** — with flag unset and certificates missing or invalid, the node exits with an error rather than serving plain traffic. No error path, retry, or fallback may produce unencrypted traffic.
- **E6-UC-9-E3: Ambiguous flag value** — values such as `yes`, `1`, `True ` or empty are either parsed strictly (only the documented truthy value `true` enables insecure mode) or rejected at boot (E6-UC-30); an unrecognized value never enables insecure mode.

### Edge Cases
- **E6-UC-9-EC1**: Mixed network where node 3 runs insecure and others secure: secure nodes still refuse plain connections from node 3 (verification is never disabled on the secure side), so node 3 is partitioned and `peer_connections` reflects it.
- **E6-UC-9-EC2**: The boot warning is logged exactly once per boot, contains no secrets, and is visible in `docker compose logs`.
- **E6-UC-9-EC3**: The committed docker-compose files do not set `INSECURE_DEV_MODE=true` by default; if a separate dev override file sets it, it is clearly named and documented.
- **E6-UC-9-EC4**: Insecure mode does not relax the Prometheus scrape configuration or the outbound-verification static checks (E6-UC-8-E5); those checks permit plain URLs only inside the `INSECURE_DEV_MODE` branch.

### Data Requirements
- **Input**: `INSECURE_DEV_MODE` environment variable.
- **Output**: Listener mode (TLS-only or plain) and boot log.
- **Side Effects**: Log warning only.

---

## E6-UC-10: Non-Root, Read-Only Containers and Volume Ownership (NFR-I1)

**Actor**: Operator, CI system
**Preconditions**: Node and attacker images built; compose defines named volumes (chain store, snapshots, and ONE keys/certs volume or `volume.subpath` per service) and a one-shot init service; the Dockerfile creates volume mount directories and `chown`s them to the node UID
**Trigger**: `docker compose up`, then `docker compose exec node1 id -u`

### Primary Flow (Happy Path)
1. Operator brings the stack up. The one-shot init service populates each service's own keys/certs named volume (or keys are generated in-container) and sets ownership to the node UID before the nodes start. Each container mounts only its own key material plus the CA certificate read-only; the dev-CA private key is never mounted into a runtime container (E6-UC-8-E8).
2. Operator runs `docker compose exec node1 id -u`; the output is a non-zero UID.
3. The node process runs as that UID. The root filesystem is read-only (`read_only: true`), `PYTHONDONTWRITEBYTECODE=1` is set, and `/tmp` is a `tmpfs`; the only writable paths are the named volumes (chain store, snapshots, keys) and `/tmp`.
4. Private-key files are mode `0600` and owned by the node UID.
5. The node serves requests, persists blocks, and writes snapshots normally.

**Postconditions**: No node process runs as root; keys and certs are never delivered via bind mounts.

### Alternative Flows
- **E6-UC-10-A1: Attacker image** — `docker compose exec attacker id -u` also prints a non-zero UID, the attacker mounts the dev CA certificate (read-only) and its own CA-signed certificate and key from its own per-service volume, and the attack harness still runs.
- **E6-UC-10-A2: Keys generated in-container** — instead of the init service copying keys, the node generates its `NodeKeyPair` into the keys volume on first boot with mode `0600` under its own UID.

### Error Flows
- **E6-UC-10-E1: Root UID detected** — the container test (`tests/node/test_container_user.py`) fails if `id -u` returns `0` for the node or attacker image.
- **E6-UC-10-E2: Volume not writable by the UID** — a pre-existing volume owned by root makes persistence fail. The node logs a clear permission error at boot and exits (it does not run degraded silently); documentation states the required ownership and that the init service fixes it on a fresh volume.
- **E6-UC-10-E3: Key file mode wrong** — a private-key file with a mode more permissive than `0600` fails the mode test where the filesystem supports POSIX permissions; the test is skipped with a recorded reason otherwise (for example a Windows bind mount, which is exactly why bind mounts are not used for keys/certs).
- **E6-UC-10-E4: Bind mount used for keys or certs** — a static compose check fails if key or certificate delivery uses a bind mount instead of a named volume (Docker Desktop on Windows presents bind mounts as root-owned and permissive).
- **E6-UC-10-E6: Cross-service key access** — from inside the attacker container a test tries to read each `node*` key file (`NodeKeyPair`, `IssuerKeyPair`, TLS private key) and the dev-CA private key; all attempts fail because those files are in other services' volumes (or the init volume) and are not mounted. Symmetrically, `docker compose exec node1` finds no key file belonging to `node2`..`node10` or the attacker, and its CA certificate mount is read-only (a write attempt fails).
- **E6-UC-10-E7: Single shared keys volume** — a compose static check fails if one named keys volume is mounted by more than one service without distinct `subpath` values (E6-UC-8-E9).
- **E6-UC-10-E5: Write to the read-only root** — an attempt to write outside the volumes and `/tmp` (for example `touch /app/x`) fails with a read-only filesystem error; `.pyc` files are not generated. (E6-UC-10-E6 and E6-UC-10-E7 above cover per-service key isolation.)

### Edge Cases
- **E6-UC-10-EC1**: Only mounted volumes (chain, keys, snapshots) and the `/tmp` tmpfs are writable; the node boots and serves requests with the read-only root.
- **E6-UC-10-EC2**: Upgrading from an earlier image that ran as root with root-owned data volumes: documented migration step (chown or recreate volume) is required; the node does not auto-chmod 777.
- **E6-UC-10-EC3**: `SNAPSHOT_DIR` is on a named volume owned by the non-root UID, so snapshots (E6-UC-11) succeed.
- **E6-UC-10-EC4**: The init service is idempotent: re-running it on populated volumes does not change ownership of chain data or overwrite existing keys, and it does not copy the dev-CA private key into any per-service volume.
- **E6-UC-10-EC5**: The `tmpfs` at `/tmp` is not persisted across restarts; nothing the node needs durably (chain, keys, snapshots) is stored there.

### Data Requirements
- **Input**: Dockerfiles, compose volume configuration (per-service key volumes), init service.
- **Output**: Running containers with unprivileged UID, read-only root, owned volumes and per-service key isolation.
- **Side Effects**: File ownership on named volumes.

---

## E6-UC-11: Periodic Chain Snapshots (NFR-I3)

**Actor**: Node (snapshot task), operator
**Preconditions**: Node running with a persistent chain store on a named volume; `SNAPSHOT_DIR` on a named volume writable by the node UID; defaults `SNAPSHOT_INTERVAL_MIN=60`, `SNAPSHOT_KEEP=24`; `ChainState` is INTRODUCED AND OWNED BY EPIC 3 (FR-27) and owns the single chain-mutation lock shared by the append path and the chain-replace (sync) path; Epic 6 only ADDS the snapshot-copy operation under that existing lock (no new lock, no new owner); blocks are immutable frozen `Block` objects or deep-copied (Epic 3 FR-27)
**Trigger**: The interval timer in `snapshot_task` fires

### Primary Flow (Happy Path)
1. The snapshot task wakes at the configured interval.
2. It acquires the existing `ChainState` lock (Epic 3 FR-27), copies the in-memory block list (the copied blocks are frozen `Block` objects or deep copies, so later mutation of live state cannot alter the copy), and RELEASES the lock. It never reads or copies the chain-store file.
3. Off the event loop (`asyncio.to_thread` or equivalent) it serializes the copied blocks with the Slice 8 chain serializer and writes the snapshot into `SNAPSHOT_DIR` (atomic write, see E6-UC-12) with a name unique per height plus counter.
4. It prunes older snapshots so only the newest `SNAPSHOT_KEEP` remain.
5. It logs the snapshot name and height.

**Postconditions**: A new snapshot exists; retention holds; the lock was held only while copying the block list; consensus was not stalled by serialization or disk I/O.

### Alternative Flows
- **E6-UC-11-A1: Custom interval** — operator sets `SNAPSHOT_INTERVAL_MIN=1` (test setting); a snapshot appears about every minute without code changes.
- **E6-UC-11-A2: Retention** — with `SNAPSHOT_KEEP=3` and 5 snapshot cycles, exactly the 3 newest remain; the 2 oldest are deleted. With defaults, the 25th snapshot removes the oldest so 24 remain.
- **E6-UC-11-A3: Core module purity** — the `blockchain_core` snapshot module takes a block list and a destination, with no node configuration, `asyncio`, or `prometheus_client` imports; the static import check covers it.

### Error Flows
- **E6-UC-11-E1: Invalid configuration** — `SNAPSHOT_INTERVAL_MIN` zero, negative, or non-numeric, or `SNAPSHOT_KEEP` less than 1, makes the node fail fast at boot with a clear error (E6-UC-30).
- **E6-UC-11-E2: Disk full or `SNAPSHOT_DIR` unwritable** — the snapshot attempt fails; any temp file is removed, the previous snapshots are kept, the error is logged, and the node continues serving and retries at the next interval. A snapshot failure never crashes consensus.
- **E6-UC-11-E3: Snapshot taken during block append (append-during-snapshot flow)** — a block is appended while the snapshot runs. Sequence: (1) the snapshot task acquires the `ChainState` lock and copies the block list at height H; (2) it releases the lock; (3) while the copy is being serialized and written off-loop, the append path acquires the same lock (not blocked by serialization) and appends block H+1 to the live chain; (4) the snapshot file is completed. Expected: the snapshot contains exactly the chain as of height H (blocks 0..H, a consistent prefix, no H+1, no torn mix), passes FR-6 validation on load, and the live chain is at H+1 and also valid. Because copied blocks are frozen or deep-copied, the append (and any mutation of the live list) cannot alter the snapshot's contents. A test appends blocks concurrently with a snapshot, then asserts the snapshot's tip equals the height at copy time, validates it, and asserts the copy is unaffected by the append. If the append wins the lock first, the snapshot is at H+1 (also consistent); either outcome is valid, a torn state never is.
- **E6-UC-11-E6: Copy aliasing** — a test mutates (or attempts to mutate) a block object in the live chain after the snapshot copy was taken; for frozen blocks the mutation raises, for deep-copied blocks the snapshot input is unchanged. In both cases the serialized snapshot equals the pre-mutation content. A shallow list copy that shares mutable block objects fails this test.
- **E6-UC-11-E7: Concurrent replace and append plus snapshot copy** — the append-vs-replace concurrency scenario itself belongs to Epic 3 (UC-17, plan Slice 16, `tests/node/test_chain_state_concurrency.py`) and is not repeated or owned here. Epic 6 owns only the EXTENSION of that scenario with a snapshot copy (plan Slice 33): an append, a chain-sync replace and a snapshot copy are issued together; the resulting live chain passes FR-6 validation, no append is lost or interleaved with a replace, and the snapshot is a wholly-old or wholly-new chain.
- **E6-UC-11-E4: Event loop blocked by snapshot** — a test with a large chain and a heartbeat coroutine asserts the event loop keeps ticking while the snapshot is being serialized and written (write is off-loop), and that lock-hold time is limited to the copy (an append attempted during serialization is not blocked).
- **E6-UC-11-E5: Windows replace denied** — on Windows a `PermissionError` while the final rename happens (file briefly held open by AV/indexer) is caught: the cycle is skipped, the temp file cleaned up or left to the ignored-prefix rule, a warning is logged, and the next cycle retries; the node does not crash.

### Edge Cases
- **E6-UC-11-EC1**: `SNAPSHOT_KEEP=1`: each new snapshot replaces the previous one only after the new one is fully written (never zero snapshots at any instant).
- **E6-UC-11-EC2**: Genesis-only chain: a valid snapshot is still produced and loads.
- **E6-UC-11-EC3**: Two snapshots at the same height (no new block between cycles) do not overwrite each other (name includes height plus a counter).
- **E6-UC-11-EC4**: Chain replacement by sync (fork adoption, Epic 3 UC-3) while the snapshot task runs: the replace path takes the same `ChainState` lock (Epic 3 FR-27), so the snapshot reflects either the old or the new chain wholly, not a mixture.
- **E6-UC-11-EC5**: The snapshot task is started only after `ChainState` is initialized; a snapshot cycle that fires before the first block is loaded is skipped.
- **E6-UC-11-EC6**: Epic 6 creates no lock of its own: a static check asserts the snapshot task references only the `ChainState` lock and defines no `Lock`/`RLock` of its own.

### Data Requirements
- **Input**: In-memory block list (frozen or deep-copied under the Epic 3 `ChainState` lock); `SNAPSHOT_INTERVAL_MIN`, `SNAPSHOT_DIR`, `SNAPSHOT_KEEP`.
- **Output**: Snapshot files in `SNAPSHOT_DIR`.
- **Side Effects**: Disk usage bounded by retention; old snapshots deleted.

---

## E6-UC-12: Snapshot Integrity, Atomicity, and Restore

**Actor**: Node (snapshot writer and loader), operator restoring a node
**Preconditions**: At least one snapshot exists
**Trigger**: Snapshot write; or operator restores a snapshot on a fresh node

### Primary Flow (Happy Path)
1. Snapshot writer writes the serialized block list to a temporary file inside `SNAPSHOT_DIR` whose name carries a prefix that retention ignores, flushes, and `fsync`s the file.
2. It renames the temp file to the unique final name (height plus counter) with `os.replace` (atomic).
3. On POSIX it then `fsync`s the directory; on Windows this step is skipped (not supported).
4. Operator stops the target node, copies the snapshot into the chain-store path (the snapshot format is identical to the chain-store format), and starts the node.
5. The node performs its normal chain load and runs the full Epic 2 FR-6 validation.
6. Validation passes; the node adopts the chain at the snapshot height and then syncs the remainder from peers (Epic 3 UC-3).

**Postconditions**: Node state equals the snapshot's chain; no key material was in the snapshot (the snapshot serializes only the block list and never reads the key-store directory).

### Alternative Flows
- **E6-UC-12-A1: Restore then sync** — snapshot is at height 900 while the network is at 1,000; after loading, the node requests missing blocks via paginated `GET /chain` and reaches the tip.
- **E6-UC-12-A2: PBFT chain snapshot** — a PBFT chain snapshot loads and passes validation including `commit_signatures[]` quorum checks using the boot-time `ValidatorSet`.
- **E6-UC-12-A3: No bespoke restore code** — restore uses only the existing Epic 2 chain load plus FR-6 validation; there is no snapshot-specific loader path that could bypass validation.

### Error Flows
- **E6-UC-12-E1: Crash during write (fault injection)** — the crash is simulated by fault injection in the write function (an injected failure after the temp file is written and before `os.replace`), not by killing a process. The previous snapshot is byte-identical to before; the partial temp file is ignored by retention and loading, and cleaned up or ignored on the next boot; the next cycle succeeds.
- **E6-UC-12-E2: Tampered or corrupted snapshot** — a block field is altered in a snapshot file. Loading runs FR-6 validation and fails with the matching `failure_type` (for example `hash` or `merkle`); the node refuses to adopt it and falls back to genesis plus sync.
- **E6-UC-12-E3: Key files excluded by construction** — the snapshot code path never reads the key-store directory. An automated test places `IssuerKeyPair`/`NodeKeyPair` files (and distinctive private-key marker bytes) next to the chain store, takes a snapshot, and asserts no key file name or key-material marker appears in any snapshot file; a static check asserts the snapshot module has no reference to the key-store path or key-pair classes.
- **E6-UC-12-E4: Truncated snapshot** — a snapshot file is cut short. Loading fails with a structural error; it never partially adopts blocks, and the error is logged.
- **E6-UC-12-E5: Replace denied on Windows** — `os.replace` raises `PermissionError`; the writer treats it as a skipped cycle (logged, not fatal), the previous snapshot stays intact, and the next cycle retries.
- **E6-UC-12-E7: Append during snapshot write** — while the writer is between step 1 (temp file) and step 2 (`os.replace`), a block is appended to the live chain through `ChainState`. The resulting snapshot file holds exactly the chain copied at lock time (E6-UC-11-E3), validates on load, and restoring it then syncing the remainder from peers reaches the live tip.
- **E6-UC-12-E6: Directory fsync on Windows** — the code never attempts a directory `fsync` on Windows (a test on the platform branch asserts the call is POSIX-only), so the cycle does not fail with an OS error.

### Edge Cases
- **E6-UC-12-EC1**: Leftover temp files (ignored prefix) are not counted as snapshots for retention, are never deleted by retention as if they were snapshots, and are not loaded as valid snapshots.
- **E6-UC-12-EC2**: Retention pruning never deletes the only valid snapshot, even if a newer temp file exists.
- **E6-UC-12-EC3**: Temp file and final file are on the same filesystem so the rename is atomic: the temp file is created inside `SNAPSHOT_DIR` itself, not in a system temp directory or `/tmp` tmpfs.
- **E6-UC-12-EC4**: Two snapshots at the same height get distinct final names (counter), and neither overwrites the other.
- **E6-UC-12-EC5**: Restoring a snapshot onto a node whose chain store already contains a longer valid chain: the operator procedure replaces the file only on a stopped node; the node never overwrites a live chain store.

### Data Requirements
- **Input**: Copied block list; snapshot file on restore.
- **Output**: Snapshot file; validated in-memory chain on load.
- **Side Effects**: Temp file creation and removal; renames.

---

## E6-UC-13: CI Quality Gates (NFR-M1)

**Actor**: Developer, CI system (GitHub Actions)
**Preconditions**: `.github/workflows/ci.yml` exists; `pyproject.toml` has coverage configuration
**Trigger**: Push or pull request

### Primary Flow (Happy Path)
1. CI checks out the repository and installs dependencies.
2. It runs `ruff`, `mypy`, and `pytest --cov=src/blockchain_core --cov-fail-under=80`.
3. All steps pass and core line coverage is at least 80 %.
4. The job is green.

**Postconditions**: The commit is allowed to merge from a quality standpoint.

### Alternative Flows
- **E6-UC-13-A1: Frontend steps** — the frontend `vitest` and build steps run as specified in the CI/CD section and pass.
- **E6-UC-13-A2: Benchmark smoke test** — `tests/benchmarks/test_bench_smoke.py` runs the harness on a 100-block chain within the normal pytest step.
- **E6-UC-13-A3: Static architecture checks run in pytest** — the import-boundary check (extended to `snapshot.py`; `prometheus_client`/`uvicorn`/`httpx` forbidden in `blockchain_core`; `src/*` never imports `benchmarks/` or `attacks/`), the single-TLS-client-factory check, and the no-tracked-private-key check run as part of the test step.

### Error Flows
- **E6-UC-13-E1: Coverage below 80 %** — a change drops `src/blockchain_core` line coverage to 79.9 %. `pytest` exits non-zero via `--cov-fail-under=80`, and the CI job fails.
- **E6-UC-13-E2: Lint failure** — a ruff violation (for example an unused import) fails the job at the lint step.
- **E6-UC-13-E3: Type failure** — a mypy error fails the job.
- **E6-UC-13-E4: Test failure** — any failing pytest test (including the no-PII guard, E6-UC-6, and the static TLS-factory check, E6-UC-8-E6) fails the job.

### Edge Cases
- **E6-UC-13-EC1**: Coverage exactly 80.0 % passes; the gate is "below 80 %" fails.
- **E6-UC-13-EC2**: Coverage is measured on `src/blockchain_core` only, so high coverage in other packages cannot mask a low core figure.
- **E6-UC-13-EC3**: A fork PR without secrets still runs all gates (no step depends on a secret that would make it silently skip).

### Data Requirements
- **Input**: Repository at the pushed commit.
- **Output**: CI pass/fail status and coverage report.
- **Side Effects**: CI artifacts.

---

## E6-UC-14: Trivy Image Scan (NFR-I2)

**Actor**: CI system, developer
**Preconditions**: Node image can be built in CI; Trivy is available; the node base image reference is pinned by digest (`@sha256:...`); the Trivy vulnerability database is cached between CI runs
**Trigger**: CI job after the image build

### Primary Flow (Happy Path)
1. CI restores the cached Trivy vulnerability database and builds the node image from the digest-pinned base.
2. CI runs `trivy image --severity CRITICAL --exit-code 1 <node-image>`.
3. Trivy reports 0 CRITICAL vulnerabilities and exits 0.
4. The job is green.

**Postconditions**: The shipped node image has no known CRITICAL vulnerabilities at scan time; only the node image is gated.

### Alternative Flows
- **E6-UC-14-A1: Remediation by re-pin** — a CRITICAL finding is resolved by re-pinning the base image to a newer digest that contains the fix, or by bumping the vulnerable dependency; the next CI run is green.
- **E6-UC-14-A2: Attacker image not gated** — the Epic 5 attacker image is built but not scanned by the gate; a CRITICAL in it does not fail the job.

### Error Flows
- **E6-UC-14-E1: CRITICAL found** — Trivy reports at least one CRITICAL; it exits non-zero and the CI job fails.
- **E6-UC-14-E2: Suppression attempted** — a change adds `.trivyignore` or `--ignore-unfixed` or lowers the severity to hide a CRITICAL. This is not an accepted resolution; review rejects it and a CI-configuration check asserts such options are absent from the CRITICAL gate.
- **E6-UC-14-E3: Scanner or database failure** — Trivy cannot download its vulnerability database (and no cached copy is available) or crashes. The job fails (it must not pass silently with an unscanned image).
- **E6-UC-14-E4: Base image not pinned by digest** — a static check fails if the node Dockerfile's `FROM` uses a floating tag without `@sha256:`, because floating tags make the scan result non-reproducible.

### Edge Cases
- **E6-UC-14-EC1**: Only HIGH or lower findings exist: the job passes; they are reported but do not gate (the gate is CRITICAL).
- **E6-UC-14-EC2**: A CRITICAL has no upstream fix: the job stays red and CI is blocked until the base image is re-pinned to a fixed digest (or an alternative base image); this temporary blocking is a recorded accepted risk, and the situation is documented in the report rather than suppressed.
- **E6-UC-14-EC3**: A cached database that is stale (older than the CI cache policy) is refreshed on the next run; the job log records the database version/date used.

### Data Requirements
- **Input**: Built node image; cached Trivy DB.
- **Output**: Trivy report and exit code.
- **Side Effects**: CI logs; CI cache entry for the DB.

---

## E6-UC-15: Benchmark Harness Recording, Reproducibility, and Metadata

**Actor**: Thesis author, CI system
**Preconditions**: `benchmarks/` package and `results/` directory exist; git repository has a commit; `benchmarks/` may import `src/*` but `src/*` never imports `benchmarks/` or `attacks/`
**Trigger**: Any benchmark run via `python -m benchmarks.<name>`

### Primary Flow (Happy Path)
1. Author runs a benchmark module from the repository root.
2. The harness measures the quantity and compares it to the Table 1.5 target.
3. `benchmarks/record.py` appends one row to `results/nfr_measurements.csv` with exactly these nine columns, in this order (FR-17): `nfr_id,value,target,pass_fail,mode,achieved_rps,headline,machine,commit` — where `mode` is `pow` | `pbft` | `core`, `achieved_rps` is filled for load tests and empty where not applicable, `headline` is `true` | `false` (E6-UC-28), `machine` is CPU model, core count, RAM, OS and container host details, and `commit` is the hash. The same columns apply to every row written by the network-level (FR-18) and scale/fault/recovery (FR-19) benchmarks.
4. Re-running the same command on the same commit produces a new row with comparable values.

**Postconditions**: CSV has a complete, self-describing row per measurement; both the first and any re-measurement rows are retained.

### Alternative Flows
- **E6-UC-15-A1: CI smoke run** — the smoke test runs the harness against a 100-block chain, exits 0, and verifies a row with all columns is written (to a temporary CSV so it does not pollute results). The smoke row is never `headline=true`.

### Error Flows
- **E6-UC-15-E1: Commit hash unavailable** — the working directory is not a git repository or `git` is missing. The harness records an explicit `unknown` marker and warns, or refuses to write; it never writes a fabricated hash. Dirty working tree is flagged in the row (for example `-dirty` suffix), and a dirty-tree row cannot be `headline=true`.
- **E6-UC-15-E2: Machine description missing** — platform info cannot be read; the column contains `unknown` rather than being empty.
- **E6-UC-15-E3: CSV write failure** — `results/` is not writable or the file is locked; the harness exits non-zero with an error and does not report success.
- **E6-UC-15-E4: Layering violation** — a static check fails if any module under `src/` imports `benchmarks` or `attacks`.

### Edge Cases
- **E6-UC-15-EC1**: Missing CSV: harness creates it with the header row; existing CSV is appended to, never truncated.
- **E6-UC-15-EC2**: Pass/fail is computed from the target in the row, and targets are constants taken from Table 1.5; a test asserts they equal the documented values (guards against silently editing thresholds).
- **E6-UC-15-EC3**: Seeds and fixtures are deterministic (fixed seed for the synthetic chain), so two runs on the same machine differ only by timing noise.
- **E6-UC-15-EC4**: Rows that have no meaningful achieved RPS (core-level benchmarks) leave `achieved_rps` empty as the PRD specifies, and store `mode = core`; a test asserts that the `mode`, `headline`, `machine` and `commit` columns are never empty for any row, and that `achieved_rps` is non-empty for every load-test row (P1, P2, S1 end-to-end).
- **E6-UC-15-EC5**: Column-set guard: a test asserts the CSV header is exactly the nine FR-17 columns `nfr_id,value,target,pass_fail,mode,achieved_rps,headline,machine,commit`, in that order; `achieved_rps` is empty where not applicable (core-level rows, E6-UC-15-EC4). A row missing a required value in any column other than a not-applicable `achieved_rps` (that is, `nfr_id`, `value`, `target`, `pass_fail`, `mode`, `headline`, `machine`, `commit`) is refused by the harness (E6-UC-28-E4). `mode` takes only the values `pow`, `pbft`, `core`.
- **E6-UC-15-EC6**: Every headline P4, P5 and S1 (batching) row is re-run at the final hardened commit, in the same way as the network-level rows (E6-UC-28); core-level benchmarks are not exempt from FR-21 because they run without containers.

### Data Requirements
- **Input**: Benchmark parameters (block counts, RPS, durations); environment.
- **Output**: Rows in `results/nfr_measurements.csv`.
- **Side Effects**: File append; cached fixtures on disk.

---

## E6-UC-16: NFR-P5 — Full Validation of a 10,000-Block Chain

**Actor**: Benchmark harness
**Preconditions**: Epic 2 `validate_chain` available; deterministic fixture builder available; real time-aware key resolver (Epic 3 FR-23) available
**Trigger**: `python -m benchmarks.bench_validate_chain --blocks 10000`

### Primary Flow (Happy Path)
1. Harness builds (or loads from cache) a deterministic fixture: 10,000 blocks of 1 `DocumentRecord` each, PoW-style blocks at a low fixed difficulty, signed with the project's Epic 2 signature scheme. This fixture is PoW-style and therefore does NOT exercise PBFT `commit_signatures[]` verification (the Epic 2 FR-6 quorum check); that gap is covered by the supplementary row of E6-UC-16-A2.
2. Fixture generation, loading and deserialization complete BEFORE timing starts.
3. It runs only the Epic 2 FR-6 validation function 5 times, using the REAL time-aware key resolver (not a stub), timing each call.
4. It takes the median duration.
5. The median is at most 5 s, so the row is recorded with `pass`.

**Postconditions**: CSV row for NFR-P5 with the median value, target 5 s, machine, commit.

### Alternative Flows
- **E6-UC-16-A1: Cached fixture** — a prior run's on-disk fixture is reused; its integrity (block count and tip hash) is verified before timing; the build and load time are excluded from the measured duration.
- **E6-UC-16-A2: Supplementary PBFT-fixture row** — the harness additionally builds a PBFT-style fixture (for example 1,000 blocks, each carrying n = 4 `commit_signatures` from the boot-time `ValidatorSet`, signed with the Epic 2 scheme), loads it outside the timed region, and times the same Epic 2 FR-6 validation function (median of 5 runs, real time-aware resolver, including the `commit_signatures[]` quorum check). The row is written with `mode = pbft`, a label naming the fixture (block count, n = 4 signatures per block), and is reported SEPARATELY from the headline P5 row. It is never substituted for the 10,000-block headline row and never marked as the P5 pass/fail evidence; the report shows both rows side by side. If the block count differs from 1,000, the label states the actual count.

### Error Flows
- **E6-UC-16-E1: Target missed** — the median exceeds 5 s. The row records the measured value with `fail`; the harness exits successfully (a miss is data, not a crash) and the threshold is NOT changed. The author may optimize (for example caching key-resolver lookups) and re-measure; both rows are retained (see E6-UC-27).
- **E6-UC-16-E2: Fixture invalid** — the generated chain fails validation (builder bug). The harness aborts with an error and writes no timing row, since a timing of an invalid chain is meaningless.
- **E6-UC-16-E3: Stub resolver used** — if the benchmark is wired to a stub or constant key resolver rather than the real time-aware resolver, a test fails; a stub would understate validation cost.
- **E6-UC-16-E4: PBFT fixture mislabelled or substituted** — the supplementary PBFT row is written without a fixture label, with `mode` other than `pbft`, or is used in place of the 10,000-block row as the P5 evidence. The harness refuses to write an unlabelled supplementary row, and a report check (E6-UC-27-E4) rejects a PBFT-fixture row cited as the P5 headline.
- **E6-UC-16-E5: PBFT fixture without quorum signatures** — the PBFT fixture's blocks carry fewer than 2f+1 valid `commit_signatures`; the fixture fails validation (treated as E6-UC-16-E2: abort, no timing row).

### Edge Cases
- **E6-UC-16-EC1**: Fewer than 5 runs completed because of interruption: no median row is written.
- **E6-UC-16-EC2**: Timing includes signature verification, link/hash checks, Merkle recomputation and key resolution per block (full FR-6 checklist, not a subset), and excludes loading and deserialization.
- **E6-UC-16-EC3**: Smoke variant on a 100-block chain (CI) runs the same code path and only checks that it executes and records a row, without asserting the 5 s target for 100 blocks as evidence of NFR-P5.
- **E6-UC-16-EC4**: A low fixed difficulty keeps the fixture buildable; the `difficulty` check of FR-6 is still executed during validation.

### Data Requirements
- **Input**: Block count (10,000), runs (5), records per block (1); supplementary PBFT fixture (for example 1,000 blocks with n = 4 `commit_signatures` each).
- **Output**: CSV row (median seconds) for the headline P5; a separate, labelled `mode = pbft` row for the supplementary PBFT fixture.
- **Side Effects**: Fixture cache files.

---

## E6-UC-17: NFR-S1 (Batching Part) — Records per Second with 256-Record Batches

**Actor**: Benchmark harness
**Preconditions**: Epic 2 batching, signature verification, and Merkle construction available
**Trigger**: `python -m benchmarks.bench_batching`

### Primary Flow (Happy Path)
1. Harness generates signed records and groups them into batches of up to 256.
2. For each batch it performs signature verification and Merkle root construction.
3. It computes records per second over the full run.
4. The value is at least 50 records/s, so the row is recorded with `pass`.

**Postconditions**: CSV row for NFR-S1 (batching), target 50 records/s. This is the core-level figure; the headline end-to-end S1 row is E6-UC-23.

### Alternative Flows
- **E6-UC-17-A1: Smaller batch sizes** — optional additional runs with batches of 1, 32, and 128 record throughput for the report's scaling discussion; they are recorded as supplementary rows and do not replace the 256-record row.

### Error Flows
- **E6-UC-17-E1: Target missed** — throughput below 50 records/s is recorded as `fail` with the measured value; the target is not edited.
- **E6-UC-17-E2: Invalid signature in the workload** — a generated record fails verification; the harness aborts, because throughput must be measured on valid work.

### Edge Cases
- **E6-UC-17-EC1**: A batch of exactly 256 records and a final partial batch (for example 100) are both counted; records/s uses the total records over total elapsed time.
- **E6-UC-17-EC2**: Signing time is excluded from the metric (only verification and Merkle construction are timed), and this boundary is stated in the row notes.
- **E6-UC-17-EC3**: Warm-up iterations are excluded or explicitly documented so that first-call import effects do not skew the value.

### Data Requirements
- **Input**: Number of records, batch size (up to 256).
- **Output**: CSV row (records/s).
- **Side Effects**: None beyond CSV.

---

## E6-UC-18: NFR-P4 — PoW Mean Block Time (10 s, within 5 to 15 s)

**Actor**: Benchmark harness, thesis author
**Preconditions**: PoW miner available (Epic 3); `EXPECTED_DIFFICULTY` calibration procedure available
**Trigger**: `python -m benchmarks.bench_pow_time`

### Primary Flow (Happy Path)
1. Author calibrates `EXPECTED_DIFFICULTY` on the thesis machine over at least 100 blocks so the expected block time is about 10 s.
2. Difficulty is then frozen. Harness mines at least 30 further consecutive blocks (separate from the calibration blocks) at that difficulty.
3. It computes mean and spread (standard deviation, min, max).
4. The mean is within 5 to 15 s, so the row is recorded with `pass`. The row is labelled with its scope: single miner in-process (core-level) or compose network (reported separately if measured).

**Postconditions**: CSV row with mean, spread, difficulty used, scope label, machine, commit.

### Alternative Flows
- **E6-UC-18-A1: Recalibration on a fresh chain** — a first run yields a mean of 22 s; the author recalibrates difficulty (a configuration/calibration step, not a change to the 10 s target). Because changing the calibrated difficulty requires a fresh chain (Epic 3 FR-24), the re-run starts from a new chain; both rows are retained.
- **E6-UC-18-A2: Compose-network scope** — the same measurement on the 4-node compose network is recorded as a separate row labelled `compose network`; it does not replace the single-miner row.

### Error Flows
- **E6-UC-18-E1: Target missed** — the mean falls outside 5 to 15 s even after calibration; the row is recorded as `fail` with the cause note. The tolerance is not widened.
- **E6-UC-18-E2: Fewer than 30 measured blocks** — the run stops early (interrupt); no pass/fail row is written for the NFR (only a partial note).
- **E6-UC-18-E3: Fewer than 100 calibration blocks** — calibration sample is too small; the harness refuses to freeze difficulty and reports that the calibration is insufficient.
- **E6-UC-18-E4: Difficulty changed on an existing chain** — an attempt to change the calibrated difficulty on a chain that already has blocks is rejected (Epic 3 FR-24); the harness requires a fresh chain.

### Edge Cases
- **E6-UC-18-EC1**: High variance (exponential block-time distribution): the row reports spread; the pass/fail judgement uses the mean as defined in the PRD.
- **E6-UC-18-EC2**: The mean is exactly 5 s or 15 s: boundary values count as within the range.
- **E6-UC-18-EC3**: Difficulty recorded in the row is the calibrated one; the calibration blocks are excluded from the 30-or-more-block sample.

### Data Requirements
- **Input**: Difficulty setting, calibration block count (100 or more), measurement block count (30 or more), scope label.
- **Output**: CSV row (mean seconds, spread, scope).
- **Side Effects**: Temporary chain state discarded.

---

## E6-UC-19: Load-Test Client and Rate-Limiter Interplay

**Actor**: Benchmark harness (k6 load generator), operator
**Preconditions**: Rate limiter active (E6-UC-3); stack running with TLS (E6-UC-7); benchmark override compose file `docker-compose.bench.yml` available
**Trigger**: Preparing and running a load benchmark (E6-UC-20, E6-UC-21, E6-UC-23)

### Primary Flow (Happy Path)
1. Operator starts the stack with `docker compose -f docker-compose.yml -f docker-compose.bench.yml up -d`. The override RAISES `RATE_LIMIT_PER_MIN` above the offered rate (for 200 RPS, above 12,000/min); the limiter stays in the measured request path and `RATE_LIMIT_EXEMPT_VALIDATORS` is NOT used.
2. The override defines k6 as a SERVICE in `docker-compose.bench.yml` with its own `cpuset` (distinct from the node containers' CPUs) and the dev-CA certificate mounted read-only; k6 verifies server certificates against that CA and holds no node key material (the dev-CA private key is not mounted either, E6-UC-8-E8). The pinning is recorded.
3. The chosen configuration (value of `RATE_LIMIT_PER_MIN`, k6 `cpuset`, executor `constant-arrival-rate`) is written to the run's metadata. k6 is the SINGLE load tool; no other tool is used.
4. Load runs with the k6 open-loop `constant-arrival-rate` executor; no 429 responses appear.
5. The benchmark row and the report cite the configuration, including that the limiter was active at the raised value.

**Postconditions**: Latency numbers are not contaminated by rate-limit rejections; the limiter's per-request overhead is part of the measured latency; the configuration is auditable.

### Alternative Flows
- **E6-UC-19-A1: Raised limit** — `RATE_LIMIT_PER_MIN=100000` for the benchmark run only (bench override file); the default stays 100 in committed config.
- **E6-UC-19-A2: Per-IP limit tests are not load benchmarks** — "distributed source IPs" is NOT a mitigation for load benchmarks (a host-side client collapses to a single Docker bridge-gateway IP, so spreading load on the host cannot create distinct IPs). Per-IP limiter acceptance tests (E6-UC-3-A6) use ASGI scope injection or multiple client containers; load benchmarks use the raised limit of A1.
- **E6-UC-19-A3: PBFT forwarding path** — POST load sent to non-primaries is forwarded to the primary through `forward_record` on `WS /ws/pbft`, which is not rate limited per request; the report records that forwarding used the WS channel (up to about 3,000 requests/min from one peer IP would otherwise exceed the default limit) and the raised limit value either way.

### Error Flows
- **E6-UC-19-E1: 429s appear during load** — the harness detects any 429 in the response stream. The run is marked invalid (not counted as latency data) and the harness reports that rate limiting interfered; it does not silently include 429 latencies in p95.
- **E6-UC-19-E2: Default limit left on** — a run at 200 RPS against default 100/min would be limited after 0.5 s; the harness preflight check reads the effective configured limit and aborts with a clear message if it is below the offered rate.
- **E6-UC-19-E3: Exemption flag used for benchmarks** — a preflight check fails the run if `RATE_LIMIT_EXEMPT_VALIDATORS=true` is set, because that would remove the limiter from the measured path.
- **E6-UC-19-E4: Closed-loop generator or other tool** — a k6 script that does not use the `constant-arrival-rate` executor (for example a fixed number of virtual users that wait for responses) is rejected for headline use, and any load generator other than k6 is not accepted at all; a static check fails if the benchmark compose files or scripts reference another load tool.
- **E6-UC-19-E5: Generator CPU not pinned** — if the k6 service's `cpuset` cannot be applied or recorded, the row is flagged and not used as headline evidence.
- **E6-UC-19-E6: k6 certificate setup wrong** — the k6 service lacks the dev-CA certificate (or mounts it writable, or mounts the CA private key or any node key): TLS verification fails (no `insecure` skip is permitted) or the compose static check fails; the run does not start.

### Edge Cases
- **E6-UC-19-EC1**: The benchmark configuration is never committed as the default; a test asserts the default compose file has `RATE_LIMIT_PER_MIN` unset (100) and does not reference the bench override.
- **E6-UC-19-EC2**: Prometheus scraping and Grafana traffic during the run consume a few requests/min from their own IPs and do not change the result materially; the report states that metrics export was enabled during measurement.
- **E6-UC-19-EC3**: Achieved RPS is recorded next to the target RPS in every load row; a run whose achieved RPS is below target is flagged.

### Data Requirements
- **Input**: Effective rate-limit configuration, k6 service `cpuset`, k6 executor, dev-CA certificate mount.
- **Output**: Metadata fields in the report/CSV notes.
- **Side Effects**: Temporary environment override and the k6 service via a separate compose file (`docker-compose.bench.yml`).

---

## E6-UC-20: NFR-P1 — `GET /documents/{hash}` at 200 RPS (p95 at most 200 ms)

**Actor**: Load-test client (k6 `constant-arrival-rate`, run as a service in `docker-compose.bench.yml`)
**Preconditions**: n = 4, f = 1 stack on one host in PBFT mode with Epic 6 hardening enabled (metrics, bench rate-limit override per E6-UC-19, TLS 1.3, non-root); known finalized document hashes seeded; k6 service pinned to its own `cpuset` with the dev-CA certificate mounted
**Trigger**: Load-test run against one node

### Primary Flow (Happy Path)
1. Harness seeds a set of finalized documents.
2. It drives `GET /documents/{hash}` at a constant arrival rate of 200 RPS for at least 60 s on one node (open loop).
3. It collects latency percentiles p50, p95, p99, the error count, and the achieved RPS.
4. Achieved RPS is at (or within the stated tolerance of) 200, p95 is at most 200 ms with 0 errors, so the row is recorded with `pass` along with p50/p99, mode `pbft`, and achieved RPS.

**Postconditions**: CSV row for NFR-P1 with p50/p95/p99, error rate, achieved RPS, and configuration.

### Alternative Flows
- **E6-UC-20-A1: Different target node** — the run is repeated against a second node to check results are consistent; both are recorded.
- **E6-UC-20-A2: PoW-mode row** — an optional PoW-mode row is recorded, annotated that the 4 miners share host CPU; it is not the headline row.

### Error Flows
- **E6-UC-20-E1: Target missed** — p95 above 200 ms is recorded as `fail` with p50/p95/p99 and a suspected cause (for example TLS handshakes per request, containers sharing cores). The target stays at 200 ms. Optimization (for example keep-alive, caching) and re-measurement are allowed and both results are retained.
- **E6-UC-20-E2: Non-2xx responses** — 404/5xx responses during the run: the error rate is recorded; a high error rate invalidates the run rather than lowering the latency figure.
- **E6-UC-20-E3: Rate-limit contamination** — see E6-UC-19-E1; the run is invalid if any 429 occurs.

### Edge Cases
- **E6-UC-20-EC1**: First seconds include TLS handshakes and connection warm-up; the harness either excludes a documented warm-up window or reports it, but never trims only bad samples.
- **E6-UC-20-EC2**: Achieved RPS lower than 200 (the generator cannot sustain it): the run is flagged, the row records achieved RPS, and it is not accepted as evidence at 200 RPS.
- **E6-UC-20-EC3**: Lookup of a hash that does not exist (404) is excluded from the measured workload, which consists of existing documents only.

### Data Requirements
- **Input**: 200 RPS, 60 s or more, document hash set.
- **Output**: CSV row and load-tool report (p50/p95/p99), achieved RPS.
- **Side Effects**: Read-only load on the node; metrics counters increase.

---

## E6-UC-21: NFR-P2 — `POST /documents` at 50 RPS (p95 at most 300 ms)

**Actor**: Load-test client (k6 `constant-arrival-rate`)
**Preconditions**: Same stack as E6-UC-20 (PBFT mode, bench override, TLS, generator pinned); unique document hashes generated per request
**Trigger**: Load-test run posting documents to one node

### Primary Flow (Happy Path)
1. Harness generates unique SHA-256 hashes.
2. It sends `POST /documents` at a constant arrival rate of 50 RPS for the configured duration.
3. For each request it measures acceptance latency (time to the node's accept response, up to queueing into the pending batch), not time to finalization. For a request received by a NON-PRIMARY node, the acceptance latency INCLUDES the `forward_record` round-trip (send -> primary reply `accepted`, Epic 3 FR-22); for a request received by the primary it is the direct queueing time.
4. Achieved RPS is recorded; the harness splits the samples by receiving node role and computes p50/p95/p99 for primary-received requests, for non-primary-received requests, and overall, recording each group's share of traffic.
5. The overall p95 is at most 300 ms, so the overall row is recorded with `pass`; the two role rows are recorded alongside it, each with its own value and pass/fail against the same 300 ms target.

**Postconditions**: THREE CSV rows for NFR-P2 (primary-received, non-primary-received, overall), each with p50/p95/p99, achieved RPS, traffic share, mode; documents are queued and later finalized.

### Alternative Flows
- **E6-UC-21-A1: PBFT forwarding** — requests sent to a non-primary node include the forward-to-primary round-trip (`forward_record` on `WS /ws/pbft`, awaited up to `FORWARD_ACK_TIMEOUT_MS`); the row states which node role was the target and whether forwarding was subject to the rate limit (WS messages are not per-request limited). A run that sends all traffic to a single node role still writes all three rows; the group with zero samples is marked `n/a` with a note, never silently omitted.
- **E6-UC-21-A3: Mixed target distribution** — load is spread across all four nodes (one primary, three non-primaries, so about 25 % primary-received and 75 % non-primary-received); the recorded traffic share of each group is checked against the distribution actually sent.
- **E6-UC-21-A2: PoW-mode row** — optional, annotated, non-headline.

### Error Flows
- **E6-UC-21-E1: Target missed** — p95 above 300 ms recorded as `fail` with the cause note; target unchanged. If only the non-primary group misses (forward round-trip overhead), that row is `fail` with that cause, the primary-received row is reported on its own merits, and the overall row is judged on the combined samples without dropping either group.
- **E6-UC-21-E5: Forward failures in the load** — non-primary requests that return 503 (`not_primary`, `forward_timeout`, view change) or other forward-mapped errors (Epic 3 UC-15-A1) are counted in the error rate; a high error rate invalidates the run rather than excluding those samples from the latency figure.
- **E6-UC-21-E6: Roles not separated** — the harness writes a single P2 row without the primary/non-primary split; the harness refuses to write it (all three rows are required).
- **E6-UC-21-E2: Duplicate hashes** — the generator reuses a hash and gets `409` (Epic 3); this invalidates those samples, and the harness ensures uniqueness.
- **E6-UC-21-E3: Mempool backlog** — if the pending batch grows beyond a bound and the node rejects with 4xx/5xx, the error rate is recorded and the run is flagged.
- **E6-UC-21-E4: Rate-limit contamination** — any 429 invalidates the run (E6-UC-19-E1).

### Edge Cases
- **E6-UC-21-EC1**: The measurement is acceptance latency only; the finalization time is reported separately (E6-UC-22 and E6-UC-23) and the report states the difference.
- **E6-UC-21-EC2**: Server-side signing adds latency per request (Epic 3 server-side signing); it is included in the measured latency.
- **E6-UC-21-EC3**: A 50 RPS run that creates blocks during the test (PBFT rounds) is measured as is; the stack is not paused to help the numbers.
- **E6-UC-21-EC4**: Achieved RPS below 50 flags the run (E6-UC-19-EC3).

### Data Requirements
- **Input**: 50 RPS, unique hashes, metadata within cap, target node set (primary and non-primaries).
- **Output**: Three CSV rows (primary-received, non-primary-received, overall) and the k6 report.
- **Side Effects**: Many documents queued and finalized on-chain; the stack should be reset before the next measurement.

---

## E6-UC-22: NFR-P3 — PBFT Finalization Time (n = 4, p95 at most 2 s)

**Actor**: Benchmark harness
**Preconditions**: PBFT network, n = 4, f = 1, single host; `GET /metrics/consensus` (and `/metrics`) available; measurement protocol frozen before the run
**Trigger**: `python -m benchmarks.bench_pbft_finalization --blocks 100` while the S1 load (50 records/s, batches up to 256) is applied

### Primary Flow (Happy Path)
1. Harness applies the S1 load so that at least 100 PBFT blocks are finalized; the batch size in effect is recorded.
2. It reads finalization times from each correct node's `GET /metrics/consensus` (`ConsensusMetric` data), where each sample is the interval `pre-prepare` sent/received -> local commit quorum reached; samples from ALL correct nodes count.
3. It cross-checks counts against `consensus_finalization_seconds{algorithm="pbft"}` from `GET /metrics` (same-call observation, so they agree).
4. It computes the p95 — the statistic is definitively p95, frozen as the thesis definition (Table 1.5 gives no statistic) — plus mean, p50, and max as supplementary values.
5. The p95 is at most 2 s, so the row is recorded with `pass`.

**Postconditions**: CSV row for NFR-P3 with p95 as the judged value, other statistics as supplementary fields, batch size, sample count.

### Alternative Flows
- **E6-UC-22-A1: View change during run** — a primary change occurs; affected blocks are included in the data and counted, with the number of view changes noted.

### Error Flows
- **E6-UC-22-E1: Target missed** — p95 exceeds 2 s; recorded as `fail` with a cause (for example TLS and signature-verification overhead across 4 containers on shared cores).
- **E6-UC-22-E2: Fewer than 100 blocks** — insufficient samples; no pass/fail row is written (partial result is annotated).
- **E6-UC-22-E4: Statistic other than p95 judged** — a row is judged on the mean, median or max instead of p95; the harness always judges the p95 and a test asserts the judged-value field is computed with the p95 definition (the others are supplementary only).
- **E6-UC-22-E3: Samples from a subset of nodes only** — the harness collected from fewer than all correct nodes; the run is flagged because samples from all correct nodes are required.

### Edge Cases
- **E6-UC-22-EC1**: The two sources (JSON metrics and Prometheus histogram) disagree in count; since both are written in the same call this indicates a defect (E6-UC-1-E4); the harness reports the discrepancy, marks the run invalid, and uses `/metrics/consensus` as the documented primary source for the judged value.
- **E6-UC-22-EC2**: Empty blocks vs blocks with full 256-record batches: the run states the batch size used, since finalization time depends on it.
- **E6-UC-22-EC3**: PoW mode is not measured for P3 (P3 is PBFT-specific); the report says PoW finalization is covered by P4.
- **E6-UC-22-EC4**: A node that was not a correct participant (stopped or partitioned) during the run does not contribute samples; the node set is recorded.

### Data Requirements
- **Input**: S1 load, 100 or more finalized blocks, per-node `ConsensusMetric` data.
- **Output**: CSV row (p95 judged, supplementary mean/p50/max, batch size).
- **Side Effects**: Chain grows by 100 or more blocks.

---

## E6-UC-23: NFR-S1 (End-to-End) — At Least 50 Records per Second Sustained

**Actor**: Load-test client
**Preconditions**: n = 4 stack, hardened, bench override per E6-UC-19; headline run in PBFT mode
**Trigger**: Sustained submission run with batches up to 256

### Primary Flow (Happy Path)
1. Harness submits records at a sustained constant arrival rate of at least 50 records/s for the run duration (PBFT mode).
2. The network batches them (up to 256 per block) and finalizes blocks continuously.
3. After the run, harness counts records finalized on-chain divided by the steady-state window.
4. The end-to-end rate is at least 50 records/s with no backlog growth, so the headline row is recorded with `pass`, mode `pbft`.

**Postconditions**: CSV row for NFR-S1 (end-to-end, headline); all submitted records are on-chain or accounted for.

### Alternative Flows
- **E6-UC-23-A1: PoW row with arithmetic** — the run is repeated in PoW mode and recorded as a separate, annotated row. In PoW mode S1 is structurally capped at `block_interval x max_batch` = 10 s x 256 records, which is 256 / 10 = 25.6 records/s, below the 50 records/s target. The row records the measured value, `fail` against the unchanged target, and the annotation "mode limit, not a target change" with that arithmetic. It is not the headline row.

### Error Flows
- **E6-UC-23-E1: Target missed** — sustained finalized rate below 50 records/s in PBFT mode; recorded as `fail` with cause note (for example mempool queueing, consensus round time).
- **E6-UC-23-E2: Records lost** — the count of finalized records is less than accepted records. The run is flagged as a correctness failure (separate from the throughput figure) and investigated.
- **E6-UC-23-E3: Target edited for PoW** — a change that lowers the 50 records/s target, or flips the PoW row to `pass`, to hide the structural cap is rejected by review (E6-UC-27-E2).

### Edge Cases
- **E6-UC-23-EC1**: Steady-state measurement window excludes ramp-up and drain; the row states the window.
- **E6-UC-23-EC2**: PoW cap (resolves the first draft's open assumption): the PoW arithmetic (about 25.6 records/s at 10 s and 256 records) is reported as an explanation of why the target is unreachable in that mode; the headline S1 row is PBFT mode, and the target is not adjusted.
- **E6-UC-23-EC3**: The S1 load of this use case is the same load under which P3 is sampled (E6-UC-22); the batch size in effect is recorded in both rows.

### Data Requirements
- **Input**: Submission rate, duration, batch limit 256, mode.
- **Output**: CSV row (records/s end-to-end, mode, achieved RPS).
- **Side Effects**: Large number of records finalized.

---

## E6-UC-24: NFR-S2 — Scale from n = 4 to n = 7 and n = 10 by Configuration Only

**Actor**: Benchmark harness, operator
**Preconditions**: `docker-compose.scale.yml` and generated `validators.json` for the chosen n; certificates generated for node1..node10 (E6-UC-8); no code changes between runs
**Trigger**: `python -m benchmarks.bench_scale` (for n in 4, 7, 10; for each mode)

### Primary Flow (Happy Path)
1. Harness generates the compose file, certificates and `ValidatorSet` for n = 4 and starts the stack.
2. It submits a document to node 1.
3. It polls all nodes until each reports the document finalized (via `GET /documents/{hash}`).
4. It repeats steps 1-3 for n = 7 and n = 10.
5. For every n the document is finalized on all nodes, so the row is recorded with `pass`.

**Postconditions**: CSV rows (one per n and mode) showing convergence; stacks are torn down cleanly.

### Alternative Flows
- **E6-UC-24-A1: PoW mode** — the same procedure in PoW mode converges on all nodes for n = 4, 7, 10.
- **E6-UC-24-A2: PBFT mode** — the same procedure in PBFT mode converges; the quorum used is 2f+1 computed from the configured n (3 for n = 4, 5 for n = 7, 7 for n = 10).

### Error Flows
- **E6-UC-24-E1: Not all nodes converge** — at some n a node does not report the document within the timeout. Recorded as `fail` with the lagging node(s) and cause (for example resource exhaustion at 10 containers on one host).
- **E6-UC-24-E2: Code change needed** — if scaling requires editing source code (not just configuration), NFR-S2 is recorded as `fail`; the harness verifies by checking that the diff between runs is only generated configuration.
- **E6-UC-24-E3: Port or certificate conflict** — generated node certs (E6-UC-8) or ports collide for n above 4; the generator script must produce non-colliding values for all n or the run fails with a clear error.

### Edge Cases
- **E6-UC-24-EC1**: n = 7 gives f = 2 and n = 10 gives f = 3 (n at least 3f+1); the generated `validators.json` states n and f consistent with this.
- **E6-UC-24-EC2**: Startup order: nodes boot at different speeds; seed-peer retry (Epic 3 UC-1-E1) must let the stack form without manual restart.
- **E6-UC-24-EC3**: Host memory limits: if 10 containers plus Prometheus/Grafana exceed host RAM, the miss is recorded with this cause and not hidden by reducing n.
- **E6-UC-24-EC4**: A unit test (`tests/benchmarks/test_scale_config.py`) verifies the generated compose, `validators.json` and Prometheus targets for each n are internally consistent (names, ports, SANs, n/f) without starting containers.

### Data Requirements
- **Input**: n in {4, 7, 10}; mode in {PoW, PBFT}.
- **Output**: CSV rows (convergence time, nodes converged).
- **Side Effects**: Containers started and stopped; volumes should be fresh per run.

---

## E6-UC-25: NFR-R1 — Finalization with Up to floor((n-1)/3) Nodes Stopped

**Actor**: Benchmark harness
**Preconditions**: Stack with n nodes running (E6-UC-24); PBFT mode (fault tolerance bound applies to quorum)
**Trigger**: Harness stops floor((n-1)/3) nodes (1 for n = 4, 2 for n = 7, 3 for n = 10)

### Primary Flow (Happy Path)
1. Harness stops the chosen number of non-primary nodes (crash faults).
2. It submits a document to a running node.
3. The remaining nodes (at least 2f+1) finalize it.
4. Harness confirms finalization on all running nodes, so the row is recorded with `pass` for that n.

**Postconditions**: CSV row per n; stopped nodes remain stopped until the harness restores them.

### Alternative Flows
- **E6-UC-25-A1: Primary stopped** — the stopped set includes the current primary; view change (Epic 3 UC-6) elects the next primary and finalization resumes within the timeout; time to finalize is recorded.

### Error Flows
- **E6-UC-25-E1: No finalization** — the remaining nodes fail to finalize within the timeout; recorded as `fail` with cause (for example view-change timeout too long).
- **E6-UC-25-E2: One more than the bound stopped** — as a negative control, stopping floor((n-1)/3)+1 nodes must stall finalization (no 2f+1 quorum); the document is not finalized and no conflicting block is produced. This confirms the bound is not trivially satisfied.
- **E6-UC-25-E3: Restore failure** — stopped nodes cannot rejoin after the test; the harness records the problem, and E6-UC-26 covers the recovery behavior.

### Edge Cases
- **E6-UC-25-EC1**: n = 4 (f = 1) is the thesis baseline; n = 7 and n = 10 are run on the same procedure using configuration only.
- **E6-UC-25-EC2**: In PoW mode the statement is liveness of block production by the remaining miners; the row states the mode, and PBFT is the primary evidence.
- **E6-UC-25-EC3**: Rate limiter and TLS stay on during the fault test; peers that are down do not exhaust the limiter or block the event loop (connection retry with backoff).

### Data Requirements
- **Input**: n, set of nodes to stop.
- **Output**: CSV row per n (finalized yes/no, time).
- **Side Effects**: Containers stopped and restarted.

---

## E6-UC-26: NFR-R2 — Node Restart After 1,000 Blocks Converges Within 30 s

**Actor**: Benchmark harness
**Preconditions**: Network at least 1,000 blocks high; node 4 (non-primary) can be stopped and restarted; its chain store persists on a named volume; the 1,000-block state is obtained in PBFT mode or by loading a pre-generated 1,000-block fixture chain into the nodes (building 1,000 blocks live in PoW mode at 10 s each, about 2.8 h, is impractical)
**Trigger**: `python -m benchmarks.bench_recovery_sync --blocks 1000`

### Primary Flow (Happy Path)
1. Harness drives the network to at least 1,000 blocks (PBFT mode) or starts the network from the pre-generated fixture chain; the approach used is recorded.
2. It stops one node.
3. The network continues (or is held at the tip) and the stopped node falls behind.
4. Harness restarts the node and starts a timer.
5. The node reconnects with TLS, performs chain sync (paginated `GET /chain` with full validation), and reaches the network tip.
6. Convergence takes at most 30 s, so the row is recorded with `pass`.

**Postconditions**: CSV row for NFR-R2 with convergence time, block gap, and approach (PBFT-live or fixture).

### Alternative Flows
- **E6-UC-26-A1: Restore from snapshot** — the node restarts with a snapshot (E6-UC-12) at a recent height and syncs only the remainder; the time is recorded as a supplementary row.
- **E6-UC-26-A2: Fixture approach** — the pre-generated chain is loaded and validated through the normal load path (not injected past validation); the report states that the fixture approach was used.

### Error Flows
- **E6-UC-26-E1: Convergence above 30 s** — recorded as `fail` with the measured time and cause (for example full revalidation of 1,000 blocks, pagination size); the threshold is unchanged. Optimization and re-measurement are allowed with both rows retained.
- **E6-UC-26-E2: Node never converges** — validation failure or repeated peer error; the harness times out, records `fail`, and captures node logs.
- **E6-UC-26-E3: Corrupt local store on restart** — the local chain fails validation on boot (Epic 2 FR-6); the node discards it and syncs from peers; the time is measured from restart to tip.
- **E6-UC-26-E4: Rate-limited sync** — peers answer the paginated sync with 429 because the default limit was left in place; the run is invalid for the measurement and flagged (the bench override raises the limit; the exemption flag is not used).

### Edge Cases
- **E6-UC-26-EC1**: The network keeps producing blocks during the sync; convergence means reaching a tip within a small stated tolerance of the live tip, and the definition is recorded.
- **E6-UC-26-EC2**: The restarted node's sync requests count toward peers' limits (default not exempt); the paginated sync must stay under the effective limit, which is the raised bench value (E6-UC-19), and the value is recorded.
- **E6-UC-26-EC3**: Exactly 1,000 blocks (not 999) is the starting condition; the gap size is recorded in the row.

### Data Requirements
- **Input**: Chain height of 1,000 or more; node to stop; approach.
- **Output**: CSV row (convergence seconds, approach).
- **Side Effects**: Chain of 1,000 or more blocks created or loaded; node restarted.

---

## E6-UC-27: NFR Report and Honest Reporting (`docs/results/nfr_report.md`)

**Actor**: Thesis author
**Preconditions**: Measurements E6-UC-16 to E6-UC-26 done at the final hardened commit; controls E6-UC-1 to E6-UC-14 implemented; `results/nfr_measurements.csv` populated
**Trigger**: Authoring and reviewing the report

### Primary Flow (Happy Path)
1. Author creates `docs/results/nfr_report.md` listing all 19 Table 1.5 IDs: P1-P5, S1-S2, SEC1-SEC4, C1, R1-R3, I1-I3, M1.
2. For each ID the report gives the target (unchanged from Table 1.5), the measured value where measurable, pass/fail, and the evidence (slice, test, or CSV row).
3. Reviewer checks every measured value matches the latest headline CSV row for that ID and the commit hash matches the final hardened commit.
4. The report is committed.

**Postconditions**: Chapter 3 can cite results; every ID is mapped to evidence.

### Alternative Flows
- **E6-UC-27-A1: Non-measurable NFR** — IDs such as SEC1, SEC2, SEC3, SEC4, C1, I1, I2, I3, M1 are verified by tests/CI rather than a numeric measurement; the row cites the test or gate (for example SEC2 to `tests/node/test_tls.py`, I2 to the CI Trivy job) and marks pass/fail on that basis. R3 and SEC1 cite their originating Epic evidence. The SEC3 row is the per-IP rate limit (E6-UC-3, `tests/node/test_rate_limit.py`); SEC3 is mode-independent, so the row states a single piece of evidence valid in both PBFT and PoW. The SEC4 row states evidence that DIFFERS by mode: PBFT — the `unregistered_issuer` reply on `forward_record` (E6-UC-4-E1; the channel itself is Epic 3, UC-16); PoW — the block-level rejection by the Epic 2 FR-6 signature check (`failure_type = "signature"`) when the resolver cannot find the block's record issuer (E6-UC-4-A7, which relies on `blocks_rejected_total` from Slice 30), noting that no intake channel exists in PoW mode.
- **E6-UC-27-A2: Re-measurement after optimization** — the report keeps both the original and the post-optimization result for an ID, labeled with commit hashes, and states which one is current.
- **E6-UC-27-A3: Annotated rows** — the S1 PoW row (with the 256 / 10 s = 25.6 records/s arithmetic and "mode limit, not a target change"), the P4 scope (single miner vs compose network), the R2 approach (PBFT-live vs pre-generated fixture), and the P3 statistic (p95) and interval are each stated explicitly. Also stated: the P2 rows split into primary-received, non-primary-received (including the forward round-trip) and overall (E6-UC-21), and the supplementary labelled PBFT-fixture P5 row next to, not in place of, the 10,000-block headline row (E6-UC-16-A2).

### Error Flows
- **E6-UC-27-E1: Missed target** — the report states `fail` plus a suspected cause for each miss (for example "P1 p95 = 240 ms, target 200 ms; suspected cause: 4 nodes plus Prometheus/Grafana sharing laptop cores, TLS overhead"). A miss is never omitted or described as a pass.
- **E6-UC-27-E2: Target edited to pass** — a diff shows a target, threshold, tolerance, or measurement configuration changed in the same change that flips a result to pass. Review rejects it; a test compares report targets to the Table 1.5 constants (E6-UC-15-EC2).
- **E6-UC-27-E3: Missing ID or evidence** — fewer than 19 IDs, or a row without evidence, fails the review (a doc check counts the IDs).
- **E6-UC-27-E5: SEC4 evidence for one mode only, or SEC3 tied to a mode** — the SEC4 row cites only the PBFT evidence (or only PoW), or the SEC3 row is presented as mode-specific; the doc check fails because SEC4 must state both modes and SEC3 must state that it is the mode-independent rate limit.
- **E6-UC-27-E4: Non-headline row cited** — the report cites a CSV row with `headline=false` or from a commit other than the final hardened commit as the pass/fail evidence; review rejects it (E6-UC-28).

### Edge Cases
- **E6-UC-27-EC1**: Result generalization: the report states that measurements are single-host, n = 4 (and 7/10 for scale), TLS on, metrics export on, and that results do not generalize to multi-host.
- **E6-UC-27-EC2**: Rate-limit configuration used for load tests (the raised `RATE_LIMIT_PER_MIN` of the bench override, E6-UC-19), generator pinning, and the achieved RPS are stated in the report.
- **E6-UC-27-EC3**: Rows from before a hardening change are labelled non-headline (E6-UC-28) and are not mixed with final-system rows; the report cites the commit hash of the final hardened system for every headline number, consistent with FR-21.

### Data Requirements
- **Input**: `results/nfr_measurements.csv`, test results, CI results.
- **Output**: `docs/results/nfr_report.md`.
- **Side Effects**: Documentation only.

---

## E6-UC-28: Early Indicative Runs vs Headline Rows (FR-21)

**Actor**: Thesis author, benchmark harness
**Preconditions**: Benchmark harness exists (Slice 34); measurement protocol (statistics, intervals, fixtures, load model, rate-limit override, R2 definition) frozen; some hardening slices (30-33) may not yet be complete
**Trigger**: Running a benchmark before the system is final, and later at the final hardened commit

### Primary Flow (Happy Path)
1. Author runs benchmarks early (for example right after Slice 14) to obtain indicative numbers. The harness writes rows with `headline=false`.
2. Hardening Slices 30-33 are completed (FR-1 to FR-11 enabled).
3. At the final hardened commit, author re-runs every measurement behind a headline row: P1, P2 (all three role rows), P3, P4, P5, S1 (batching AND end-to-end), S2, R1, R2. This explicitly includes every headline P4, P5 and S1-batching row — core-level benchmarks are re-run like the network-level rows. The harness writes rows with `headline=true`, the final commit hash in the `commit` column, and a clean working tree, populating all FR-17 columns (`mode`, `achieved_rps`, `headline`, `machine`, `commit`).
4. The report (E6-UC-27) cites only the `headline=true` rows for pass/fail; earlier rows remain in the CSV, labelled non-headline.

**Postconditions**: Every headline row in the CSV and the report comes from the same final hardened commit; earlier rows are retained and clearly labelled.

### Alternative Flows
- **E6-UC-28-A3: Core-level re-run list** — the final-commit checklist lists P4, P5 and S1 (batching) alongside P1-P3, S1 (end-to-end), S2, R1, R2; an automated check compares the set of NFR IDs with `headline=true` rows at the final commit against this list and reports any ID missing.
- **E6-UC-28-A1: Single metric re-run** — only the P5 measurement is re-run after an optimization at the same final commit family; the new row is headline with its own commit hash and the older P5 row is demoted to non-headline (both retained, per FR-20).
- **E6-UC-28-A2: Early run informs optimization** — an early run shows a miss; the author optimizes, and the headline run is taken after; the early row is never used as pass/fail evidence.

### Error Flows
- **E6-UC-28-E1: Headline row from a stale commit** — a headline row's commit hash differs from the final hardened commit (or is `-dirty`). A report/CSV consistency check (or review) rejects it; the metric must be re-run.
- **E6-UC-28-E2: Early row used for pass/fail** — the report cites a `headline=false` row as evidence. Review rejects it (E6-UC-27-E4).
- **E6-UC-28-E3: Headline row without hardening enabled** — a headline run in which TLS, metrics export, or the rate limiter is disabled is rejected; the run metadata (config snapshot) must show FR-1 to FR-11 enabled.
- **E6-UC-28-E4: Missing headline flag column** — the CSV lacks the `headline` column or has empty values; the harness refuses to write the row (E6-UC-15).
- **E6-UC-28-E5: Core-level headline row from an earlier commit** — a P4, P5 or S1-batching headline row carries a commit hash older than the final hardened commit (it was measured early because "core benchmarks do not depend on hardening"). The consistency check rejects it and the benchmark is re-run at the final commit.
- **E6-UC-28-E6: Supplementary row promoted** — the supplementary PBFT-fixture P5 row (E6-UC-16-A2) or a PoW S1 row is marked `headline=true` as the pass/fail evidence for P5 or S1; the check rejects it (only the 10,000-block P5 row and the PBFT-mode S1 row are headline).

### Edge Cases
- **E6-UC-28-EC1**: A metric measured only early and never re-run has no headline row; the report marks the ID as "not yet measured at final commit" rather than citing the early row.
- **E6-UC-28-EC2**: Two headline rows for the same ID at different commits: only the latest is current; the earlier is flagged non-headline (E6-UC-28-A1).
- **E6-UC-28-EC3**: Non-measurable NFRs (tests/CI) have no CSV row; their evidence is the test or gate result at the final commit.

### Data Requirements
- **Input**: Commit hash, working-tree state, hardening configuration of the run, `headline` flag.
- **Output**: CSV rows with `headline` column; report citing only headline rows.
- **Side Effects**: Documentation and CSV only.

---

## E6-UC-29: SPA HTTPS Base URL, 429 Handling, and Attacker Image Ownership (FR-22)

**Actor**: SPA user, thesis author, attacker harness (Epic 5)
**Preconditions**: Epic 4 SPA built (`web/src/api/client.ts`); nodes serve TLS 1.3 (E6-UC-7); rate limiter active (E6-UC-3); Epic 5 attacker image exists
**Trigger**: SPA issues or verifies a document; the attacker container starts

### Primary Flow (Happy Path)
1. SPA is configured with an `https://` node base URL (configurable setting, no hard-coded plain URL).
2. User issues a document and verifies it; requests go over HTTPS to the node (the browser/test environment trusts the dev CA) and succeed.
3. The SPA receives a normal 2xx response for each call.
4. The attacker container starts as a non-root user, mounts the dev CA certificate read-only and its own CA-signed certificate and key from its OWN per-service volume (no shared keys volume), and its harness connects over `wss://`/`https://` successfully. The dev-CA private key and every `node*` key file are absent from the attacker container.

**Postconditions**: SPA operates against HTTPS nodes; attacker harness operates under the same TLS and non-root constraints as nodes. The code changes to Epic 4's client, and to Epic 5's image/harness, are delivered under Epic 6.

### Alternative Flows
- **E6-UC-29-A1: 429 with Retry-After** — SPA receives 429 with `Retry-After: 8`. It shows a rate-limit message ("too many requests, retry after 8 seconds"), not a "document not found/invalid" result, and does not retry before the interval. After the interval, a retry succeeds and the normal result is shown.
- **E6-UC-29-A2: 429 without usable header** — `Retry-After` missing or non-numeric: generic rate-limit message, no crash, no tight retry loop.
- **E6-UC-29-A3: Configurable base URL** — changing the base URL setting to another node's HTTPS address redirects all SPA calls with no code change.
- **E6-UC-29-A5: 503 with Retry-After (PBFT forwarding, view change, timeout)** — SPA receives 503 from `POST /documents` with `Retry-After: 3` (error codes such as `not_primary`, `forward_timeout`). It treats this as retry guidance exactly like 429 (A1/A2): shows a "node temporarily unavailable, retry after 3 seconds" message, does not retry before the interval, handles a missing or non-numeric header with a generic message and no tight loop, and never shows a verification failure.
- **E6-UC-29-A6: Node errors are not verification failures** — 403 (`unregistered_issuer`), 422 (`invalid_record`) and 502 (`not_validator`, `auth_failed`, or a reply code outside the closed enum) on issuance are each shown as a node/issuance error with the envelope `error.message`; none is rendered as "document not found/invalid" and none triggers an automatic retry.
- **E6-UC-29-A7: No automatic resubmission loop** — the SPA never resubmits an issuance automatically (503 waits for user-initiated retry after `Retry-After`; no background loop), so a double-submit cannot be produced by the client. If a retry (or an earlier forwarded record that the primary did queue) yields 409, the SPA treats it as "already submitted" (not an error and not a new issuance) and offers verification of the hash.
- **E6-UC-29-A4: Attacker key isolation** — inside the running attacker container a test attempts to read every `node*` key file (`NodeKeyPair`, `IssuerKeyPair`, TLS private key of `node1`..`node10`) and the dev-CA private key; every attempt fails and the attacker's volumes contain only its own key material plus the read-only CA certificate (E6-UC-8-E10, E6-UC-10-E6). The attack harness (Epic 5) still runs using its own certificate, so an attacker can join the TLS layer as an insider but cannot impersonate a validator by stealing its `NodeKeyPair`.

### Error Flows
- **E6-UC-29-E1: Opaque CORS failure instead of 429** — if `Retry-After` is not exposed or CORS headers are absent on the 429, the SPA cannot read the status. The client test (`web/src/__tests__/client429.test.ts`) plus the server-side CORS test (E6-UC-3-EC9) together fail in that case.
- **E6-UC-29-E2: 429 shown as verification failure** — a regression that maps 429 to "document invalid/not found" fails the client unit test.
- **E6-UC-29-E3: Plain-HTTP base URL** — the SPA is pointed at `http://` while the node is TLS-only; the request fails at the network layer and the SPA shows a connection error (not a verification result); no downgrade is attempted by the client.
- **E6-UC-29-E4: Untrusted CA** — the browser/environment does not trust the dev CA; requests fail with a certificate error surfaced as a connection problem, not as a verification failure.
- **E6-UC-29-E6: Attacker shares a keys volume** — the attacker service mounts a keys volume also mounted by a node (without a distinct `subpath`), or mounts the CA private key; the compose static check (E6-UC-8-E9, E6-UC-8-E8) fails.
- **E6-UC-29-E5: Attacker runs as root or lacks CA** — `docker compose exec attacker id -u` returns `0`, or the harness cannot validate node certificates; the container test fails (E6-UC-10-E1) and the harness reports a TLS error.

### Edge Cases
- **E6-UC-29-EC1**: `Retry-After` larger than the window (for example 3,600): the SPA shows the value as given but caps any automatic retry timer to a sane maximum; manual retry stays available.
- **E6-UC-29-EC2**: Multiple SPA requests in flight receive 429 at once: one consolidated rate-limit message, not a stack of error toasts.
- **E6-UC-29-EC3**: Epic 5 findings state that attackers hold CA-signed certificates (insider model), so attacker TLS admission is not the thing under test.
- **E6-UC-29-EC5**: Client unit tests (extending `client429.test.ts` or a sibling) cover 503, 403, 422, 502 and 409 mapping; a regression that maps any of them to a verification result, or that adds an auto-retry on issuance, fails the test.
- **E6-UC-29-EC4**: No new React pages or components are added; Grafana remains a separate operator tool outside the SPA.

### Data Requirements
- **Input**: SPA base URL setting; node responses (2xx, 429 with `Retry-After`); attacker CA certificate mount and its own per-service key/cert volume.
- **Output**: Rate-limit message in the UI; successful HTTPS calls; attacker harness connectivity.
- **Side Effects**: Changes in `web/src/api/client.ts` (Epic 4) and attacker image/harness (Epic 5) owned by Epic 6.

---

## E6-UC-30: Fail-Fast Configuration Validation at Boot (FR-23)

**Actor**: Operator, node process
**Preconditions**: New configuration keys exist: `RATE_LIMIT_PER_MIN`, `RATE_LIMIT_EXEMPT_VALIDATORS`, limiter tracked-IP cap, `TLS_CERT`, `TLS_KEY`, `TLS_CA`, `INSECURE_DEV_MODE`, `SNAPSHOT_INTERVAL_MIN`, `SNAPSHOT_DIR`, `SNAPSHOT_KEEP`, `FORWARD_ACK_TIMEOUT_MS`. The limiter tracked-IP cap key is `RATE_LIMIT_MAX_TRACKED_IPS` (default 10000). `FORWARD_ACK_TIMEOUT_MS` boot validation is owned by Epic 3 (plan Slice 13, UC-15-E1); it is listed here (FR-23) for completeness of the fail-fast list only. Coverage explicitly includes ALL rate-limit keys, ALL TLS keys and ALL snapshot keys
**Trigger**: Node boot with a given environment

### Primary Flow (Happy Path)
1. Operator boots a node with valid configuration (or with keys unset so defaults apply: limit 100, exemption false, cap 10,000, insecure mode false, snapshot interval 60, keep 24, `FORWARD_ACK_TIMEOUT_MS` 2000).
2. The node validates all new keys before opening any listener.
3. Validation passes; the node starts and logs the effective non-secret values (never key material).

**Postconditions**: The node runs with an explicit, validated configuration.

### Alternative Flows
- **E6-UC-30-A3: Forward-ack timeout default** — with `FORWARD_ACK_TIMEOUT_MS` unset, the node logs an effective value of 2000; a configured valid value (for example 500) is used by the forwarder (Epic 3 UC-15-A4; boot validation owned by Epic 3 UC-15-E1, plan Slice 13).
- **E6-UC-30-A1: Insecure mode skips TLS path checks** — with `INSECURE_DEV_MODE=true`, unreadable `TLS_*` paths are not an error (the boot warning of E6-UC-9 is logged instead).
- **E6-UC-30-A2: Defaults applied** — unset optional keys take their documented defaults; only invalid or missing-required values fail.

### Error Flows
- **E6-UC-30-E1: Invalid rate limit** — `RATE_LIMIT_PER_MIN` non-numeric, zero, negative, or empty: node exits non-zero with an error naming the key; it never starts with the limiter disabled.
- **E6-UC-30-E2: Non-boolean flag** — `RATE_LIMIT_EXEMPT_VALIDATORS` or `INSECURE_DEV_MODE` has a value that is not a recognized boolean: node exits with an error; an unrecognized value never enables exemption or insecure mode.
- **E6-UC-30-E3: Snapshot configuration** — `SNAPSHOT_KEEP` < 1, `SNAPSHOT_INTERVAL_MIN` < 1 or non-numeric, or `SNAPSHOT_DIR` missing/unwritable: node exits with an error naming the key.
- **E6-UC-30-E4: TLS paths unreadable or unparseable** — each of `TLS_CERT`, `TLS_KEY` and `TLS_CA`, tested one at a time, missing, unreadable or unparseable (not a valid PEM certificate/key) while `INSECURE_DEV_MODE` is not `true`: node exits with an error naming that key; it does not fall back to plain traffic or unverified TLS. A key that does not match its certificate also fails fast.
- **E6-UC-30-E5: Invalid tracked-IP cap** — a cap that is zero, negative (less than 1), or non-numeric fails fast.
- **E6-UC-30-E7: Invalid `FORWARD_ACK_TIMEOUT_MS`** — a value that is non-numeric, empty, zero or negative (less than 1) makes the node exit non-zero with an error naming the key; a value of 1 and the default 2000 are accepted. The node never starts with an unbounded or zero forward-ack wait.
- **E6-UC-30-E8: Per-key coverage matrix** — a parametrized test iterates the complete key set: rate-limit (`RATE_LIMIT_PER_MIN`, `RATE_LIMIT_EXEMPT_VALIDATORS`, tracked-IP cap), TLS (`TLS_CERT`, `TLS_KEY`, `TLS_CA`, `INSECURE_DEV_MODE`), snapshot (`SNAPSHOT_INTERVAL_MIN`, `SNAPSHOT_KEEP`, `SNAPSHOT_DIR`) and `FORWARD_ACK_TIMEOUT_MS`, supplying one invalid value per key and asserting a non-zero exit naming that key. A new configuration key without a row in the matrix fails the test (the key list is compared with the node's configuration schema).
- **E6-UC-30-E6: Multiple problems** — several invalid keys at once: the error lists every invalid key (or the first, with all discoverable on a second run); the node still does not start.

### Edge Cases
- **E6-UC-30-EC1**: Values with surrounding whitespace or different case (`" 100 "`, `TRUE`) are either normalized by a documented rule or rejected; behavior is deterministic and tested.
- **E6-UC-30-EC2**: Error messages name the offending key and the rejected constraint but never print TLS key contents or other secrets.
- **E6-UC-30-EC3**: Validation runs before the snapshot task, limiter, or listener is created, so no partial startup state (open port, running task) remains after a failure.
- **E6-UC-30-EC4**: Very large but numeric `RATE_LIMIT_PER_MIN` (as used by the bench override, for example 100000) is accepted.
- **E6-UC-30-EC5**: `FORWARD_ACK_TIMEOUT_MS` is validated in every consensus mode (also PoW, where it is unused), so a bad value never passes silently when the mode is later changed.

### Data Requirements
- **Input**: Environment variables listed in the preconditions.
- **Output**: Started node with logged effective configuration, or non-zero exit with a clear error.
- **Side Effects**: None on failure (no listener, no files created).
