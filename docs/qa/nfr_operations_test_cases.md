# Test Cases: Non-Functional Requirements and Operations (Epic 6)

> Based on [PRD](../PRD.md) and [Use Cases](../use-cases/nfr_operations_use_cases.md)

This document covers PRD Epic 6 (v1.9, FR-1 to FR-23): Prometheus export and the Prometheus/Grafana stack (Slice 30), API hardening (Slice 31), TLS 1.3 and the dev CA (Slice 32), container hardening, snapshots and CI gates (Slice 33), and the NFR measurement suite and reporting (Slices 34-35). Every E6-UC scenario in `nfr_operations_use_cases.md` is mapped below, one test case per scenario.

**ID and mapping rule.** Test case IDs are `NF-TC-<uc>.<n>`, where `<uc>` is the E6-UC number. Within a use case the numbering follows the order: primary flow (`.1`), alternative flows A1, A2, ... in numeric order, error flows E1, E2, ... in numeric order, then edge cases EC1, EC2, ... For example E6-UC-1 -> NF-TC-1.1, E6-UC-1-A1 -> NF-TC-1.2. The "Use Case" column names the exact scenario. Where a use case contains flows marked MOVED to Epic 3, the numbering skips them (they get no NF-TC); see the pointer table below.

**Flows MOVED to Epic 3 (no NF-TC; covered by CN-TC in `consensus_network_test_cases.md`):**

| Moved E6 flow | Epic 3 owner | Covering test cases |
|---|---|---|
| E6-UC-4-A4 (duplicate forward) | UC-16-A5, UC-15-A1 | CN-TC-16.8, CN-TC-15.4 |
| E6-UC-4-A5 (stale view, `not_primary`) | UC-16-A4, UC-16-E3, UC-15-A3 | CN-TC-16.7, CN-TC-16.12, CN-TC-15.14 |
| E6-UC-4-A6 (unauthenticated forward) | UC-16-E1, UC-16-E2 | CN-TC-16.9, CN-TC-16.10, CN-TC-16.11 |
| E6-UC-4-A8, E6-UC-4-EC5 (two non-primaries, same hash) | UC-16-A2 | CN-TC-16.4 |
| E6-UC-4-A9 (ack timeout) | UC-15-E2, UC-15-E3, UC-15-E4, UC-15-E1 | CN-TC-15.7, CN-TC-15.18, CN-TC-15.19, CN-TC-15.20, CN-TC-15.16 |
| E6-UC-4-A10 (view change in flight) | UC-16-A3 | CN-TC-16.5, CN-TC-16.6 |
| E6-UC-4-E2 (non-validator sender) | UC-16-E2 | CN-TC-16.11 |
| E6-UC-4-E3 (invalid sender auth) | UC-16-E1 | CN-TC-16.9, CN-TC-16.10 |
| E6-UC-4-E7 (reply code outside enum) | UC-16-E8, UC-15-E5 | CN-TC-16.19, CN-TC-15.21 |
| E6-UC-4-E8 (HTTP mapping table) | UC-15-A1, UC-15-E6 | CN-TC-15.2 to CN-TC-15.12, CN-TC-15.22 |
| E6-UC-4-EC7 (late/unknown `request_id`) | UC-16-E7, UC-15-EC3 | CN-TC-16.18, CN-TC-15.25 |
| E6-UC-4-EC8 (`FORWARD_ACK_TIMEOUT_MS` boundary) | UC-15-EC2, UC-15-E1 | CN-TC-15.24, CN-TC-15.16, CN-TC-15.17 |
| Epic 3 part of E6-UC-11-E7 (append vs replace) | UC-17-EC1 | CN-TC-17.10 |

**Measurement use cases (E6-UC-15 to E6-UC-26).** For NFR-P1 to P5, S1, S2, R1 and R2 the test cases specify the harness and the protocol: frozen definitions (statistic, interval, sample sources, fixtures, load model), the CSV schema, honest miss reporting, and the headline re-run at the final commit. They do NOT assert the numeric result (for example "p95 <= 200 ms"). A miss is a valid, recorded outcome; the harness test passes as long as the miss is recorded as `fail` and the threshold is untouched. Harness tests use synthetic inputs, injected clocks and small fixtures; the full-scale measurement is executed under the protocol at the final hardened commit.

**CSV column names.** Test cases use the PRD FR-17 column names: `nfr_id`, `value`, `target`, `pass_fail`, `mode` (`pow` | `pbft` | `core`), `achieved_rps`, `headline` (`true` | `false`), `machine`, `commit` (see ambiguity note in the final section).

---

## 1. Prometheus Metrics Export (E6-UC-1)

| # | Use Case | Test Case | Expected Result |
|---|----------|-----------|-----------------|
| NF-TC-1.1 | E6-UC-1 primary | `GET /metrics` on a running node; finalize one block; scrape again; reject one block with `failure_type = "signature"`; scrape a third time | 200 with `Content-Type: text/plain; version=0.0.4`; body has `chain_height`, `peer_connections{state}`, `consensus_finalization_seconds{algorithm}`, `mempool_size`, `blocks_rejected_total{failure_type}`; after finalize `chain_height` +1 and histogram `_count` +1 (equal to the `ConsensusMetric` row count of `GET /metrics/consensus`); after the reject `blocks_rejected_total{failure_type="signature"}` +1; no auth required |
| NF-TC-1.2 | E6-UC-1-A1 | Call `GET /metrics` and `GET /metrics/consensus` on the same node | Both 200; JSON shape of `/metrics/consensus` is identical to its Epic 3 contract (schema comparison) |
| NF-TC-1.3 | E6-UC-1-A2 | Scrape a PoW-mode node, then a PBFT-mode node after finalizing blocks | PoW node: only `algorithm="pow"` histogram series populated, `pbft` absent or count 0; PBFT node: the reverse |
| NF-TC-1.4 | E6-UC-1-A3 | Reject one invalid block via each path: chain sync, PoW broadcast, PBFT path; then grep source for increments of `blocks_rejected_total` | Each rejection increments the counter exactly once; the only increment site is the single wrapper around the Epic 3 FR-25 validation entry point (no per-call-site increments) |
| NF-TC-1.5 | E6-UC-1-E1 | Issue a document with distinctive metadata and load node/issuer keys; grep the full `/metrics` body | No private-key material, no signature value, no metadata content, no document hash anywhere; any match fails the test |
| NF-TC-1.6 | E6-UC-1-E2 | Parse every series of the body | Only label names `state`, `algorithm`, `failure_type` (plus `le` on histograms); no label value is a document hash or peer address; no `python_*` / `process_*` series (dedicated registry only) |
| NF-TC-1.7 | E6-UC-1-E3 | Send more than the FR-4 limit of requests to `GET /metrics` from one IP; inspect the default compose scrape config | 429 in the standard error envelope with `Retry-After`; default scrape rate (15 s interval, about 4 req/min) is asserted well under 100 req/min per node. Ownership note: the 429 on `/metrics` needs the rate limiter, owned by Slice 31a |
| NF-TC-1.8 | E6-UC-1-E4 | Finalize N blocks; compare histogram `_count` with the `ConsensusMetric` row count from `GET /metrics/consensus` | Equal; any divergence fails (same-call observation) |
| NF-TC-1.9 | E6-UC-1-E5 | Inspect exported bucket boundaries | `le="2"` present and a finite bucket of at least 120 s present; test fails otherwise |
| NF-TC-1.10 | E6-UC-1-EC1 | `GET /metrics` on a freshly booted node (genesis only) | 200; all five series present; `chain_height` is the genesis index (0); histogram count 0 |
| NF-TC-1.11 | E6-UC-1-EC2 | `GET /metrics` on a node with zero peers | Valid exposition text; `peer_connections` 0 per known state (or only existing series); no error |
| NF-TC-1.12 | E6-UC-1-EC3 | Feed many invalid blocks covering all seven `failure_type` values | `blocks_rejected_total` grows only along the seven `failure_type` values; total series count stays constant |
| NF-TC-1.13 | E6-UC-1-EC4 | Observe synthetic durations 10 s, 60 s and 130 s into the histogram | 10 s and 60 s land in finite buckets (not collapsed into `+Inf`); 130 s only in `+Inf` if above the largest explicit bucket; `+Inf` bucket and `_sum` consistent with `_count` |
| NF-TC-1.14 | E6-UC-1-EC5 | Make the validation call raise an unexpected exception instead of returning a `failure_type` | `blocks_rejected_total` is not incremented with an invalid label value; no new series appears |

---

## 2. Prometheus and Grafana Stack (E6-UC-2)

| # | Use Case | Test Case | Expected Result |
|---|----------|-----------|-----------------|
| NF-TC-2.1a | E6-UC-2 primary (plain scrape, Slice 30) | Copy `.env.example` to `.env`, set password, `docker compose up -d --build` (pre-TLS stack); query `/api/v1/targets`; log into Grafana | Prometheus (9090) and Grafana (3000) are bound to `127.0.0.1`; at least 4 node targets scraped over plain `http` and all `health = "up"`; datasource and one dashboard already provisioned; dashboard renders chain height, peer connections by state and finalization p50/p95 by algorithm from at least 2 nodes. Owned by Slice 30 |
| NF-TC-2.1b | E6-UC-2 primary (TLS scrape, Slice 32b) | Same stack after TLS is enabled; query `/api/v1/targets` | At least 4 node targets scraped over `https` with `tls_config` (`ca_file`, `server_name`) and all `health = "up"`; dashboard still renders from at least 2 nodes. Owned by Slice 32b (needs TLS) |
| NF-TC-2.2 | E6-UC-2-A1 | Start the scale compose (n = 7 and n = 10). Note: requires the scale compose, owned by Slice 35b | Prometheus scrapes all generated node targets; dashboard shows each node as a separate series |
| NF-TC-2.3 | E6-UC-2-A2 | Start a PoW-only network and open the finalization panel | Panel splits by `algorithm`; only `pow` series shown; no panel errors |
| NF-TC-2.4 | E6-UC-2-A3 | Inspect Prometheus->Grafana datasource URL and the TLS static checks (needs TLS, Slice 32b) | Grafana reaches Prometheus over plain HTTP inside the compose network; documented as out of scope of "all traffic TLS"; not flagged as a defect by the checks |
| NF-TC-2.5 | E6-UC-2-E1 | Stop one node container | Target shows `down`; dashboard shows a gap for that node only; other nodes keep rendering; Grafana does not crash |
| NF-TC-2.6 | E6-UC-2-E2 | Remove the dev CA from Prometheus, then set a `server_name` that does not match the node SAN; run static check on `docker/prometheus.yml` (needs TLS, Slice 32b) | Target `up = 0` with a TLS error in both cases; static check fails if `insecure_skip_verify` appears outside the `INSECURE_DEV_MODE` configuration |
| NF-TC-2.7 | E6-UC-2-E3 | Corrupt a datasource or dashboard provisioning JSON; start the stack; fetch the dashboard through the Grafana HTTP API | Provisioning error is logged; the stack test fails because the dashboard is not retrievable |
| NF-TC-2.8 | E6-UC-2-E4 | Start the stack with `.env` absent, then with an empty password key | Compose fails or Grafana refuses to start; no fallback to `admin/admin`; no committed default password |
| NF-TC-2.9 | E6-UC-2-E5 | Static check on the compose file with a Prometheus/Grafana port mapping lacking the `127.0.0.1:` prefix | Check fails; the committed compose file passes |
| NF-TC-2.10 | E6-UC-2-EC1 | Start Grafana before Prometheus is ready | Datasource is provisioned anyway; panels recover once Prometheus is up with no manual step |
| NF-TC-2.11 | E6-UC-2-EC2 | Restart the Grafana container | Datasource and dashboard are re-provisioned from files; no reliance on a persisted manual configuration |
| NF-TC-2.12 | E6-UC-2-EC3 | Check `git ls-files` and `.gitignore` for `.env`; read `.env.example` | `.env` is git-ignored and untracked; `.env.example` is tracked and contains no real password |

---

## 3. Per-IP Rate Limiting (E6-UC-3)

| # | Use Case | Test Case | Expected Result |
|---|----------|-----------|-----------------|
| NF-TC-3.1 | E6-UC-3 primary | Client A (IP X) sends 100 requests in 60 s, then the 101st; Client B (IP Y) sends its 101st in the same window; advance time by 60 s | A's 101st is 429 in the standard envelope (built by the shared `errors.py` builder) with `Retry-After` a positive integer; B is not limited; A succeeds again after the window slides; the rejected request has no chain/mempool side effect |
| NF-TC-3.2 | E6-UC-3-A1 | Set `RATE_LIMIT_PER_MIN=20`, restart, send 21 requests | 21st returns 429; no code change involved |
| NF-TC-3.3 | E6-UC-3-A2 | Set `RATE_LIMIT_EXEMPT_VALIDATORS=true`; send 150 requests from a static `ValidatorSet` address and from a non-validator address | Validator address is never counted or limited; other IP limited at the 101st; node logs at boot that the exemption is active |
| NF-TC-3.4 | E6-UC-3-A3 | Issue 101 `WS /ws/blocks` and `WS /ws/pbft` upgrade requests in the window | Each upgrade counts toward the window; the 101st is denied before the upgrade completes |
| NF-TC-3.5 | E6-UC-3-A4 | SPA client unit test with fake timers: 429 with `Retry-After: 12`; then missing and malformed header | Message "too many requests, retry after 12 seconds"; no auto-retry before 12 s; retry allowed after; missing/malformed header yields generic rate-limit message and no crash |
| NF-TC-3.6 | E6-UC-3-A5 | Rate-limited request from the allowed SPA origin (simple request and preflight) | Real 429 carries `Access-Control-Allow-Origin` and `Access-Control-Expose-Headers` containing `Retry-After`; SPA can read status and header |
| NF-TC-3.7 | E6-UC-3-A6 | Run the per-IP acceptance tests (second IP not limited, window per IP) | They use ASGI scope injection or multiple client containers on distinct bridge addresses; a host-side client appears only in single-IP cases |
| NF-TC-3.8 | E6-UC-3-E1 | Exceed the limit on `POST /documents`, `GET /documents/{hash}`, `GET /chain`, `GET /node/info`, `GET /metrics/consensus`, `GET /metrics`, `POST /peers/register`, `GET /peers` | Identical 429 envelope and `Retry-After` on each; rejected `POST /documents` creates no pending record; body produced by the shared builder (middleware runs before exception handlers) |
| NF-TC-3.9 | E6-UC-3-E2 | Against a REAL uvicorn server (`proxy_headers=False`), rotate `X-Forwarded-For`, `X-Real-IP`, `Forwarded` per request from one IP; then send a victim's address in XFF | 101st request is still 429; the victim is not limited; an in-process ASGI client is explicitly not used for this test |
| NF-TC-3.10 | E6-UC-3-E3 | SPA receives 429 on verify and on issue | Rendered as a rate-limit message, never as "document not found/invalid" |
| NF-TC-3.11 | E6-UC-3-E4 | Boot with `RATE_LIMIT_PER_MIN` = 0, -1, `abc`, empty; non-boolean `RATE_LIMIT_EXEMPT_VALIDATORS`; invalid tracked-IP cap | Node exits non-zero naming the key; never starts with the limiter disabled |
| NF-TC-3.12 | E6-UC-3-E5 | Auth boundary: attacker (not in static `ValidatorSet`) registers via `POST /peers/register` (appears in `GET /peers`), flag `true`; then send 101 requests; repeat with flag at default `false` | Attacker is NOT exempt: 101st returns 429; allow-list read only from static `ValidatorSet`, never `PeerInfo`; with default `false` nobody is exempt |
| NF-TC-3.13 | E6-UC-3-E6 | Exceed the limit with a WebSocket upgrade on the pinned uvicorn | Behavior matches the mechanism the pinned version provides (HTTP 429 with envelope via denial extension, else close before accept and HTTP 403); WS handler never entered; no session created; mechanism and uvicorn version recorded in the OWASP checklist |
| NF-TC-3.14 | E6-UC-3-E7 | Docs check for the accepted-risk row; (no flood-rejection assertion) | OWASP API4 row recording post-upgrade message flooding as accepted risk exists; no test requires the flood to be rejected |
| NF-TC-3.15 | E6-UC-3-E8 | Start with more than one uvicorn worker (or run the config/static check) | Start is rejected or the check fails |
| NF-TC-3.16 | E6-UC-3-EC1 | Send exactly 100 requests, then a 101st | First 100 succeed; only the 101st is limited |
| NF-TC-3.17 | E6-UC-3-EC2 | 10,000 distinct source IPs send one request each, then a 10,001st IP | Memory stays bounded (LRU-capped map, expired evicted first, per-IP `deque(maxlen=limit)`); node keeps serving; worst case cap x limit timestamps |
| NF-TC-3.18 | E6-UC-3-EC3 | Force LRU eviction at the cap; revisit the evicted IP; hammer an active IP | Evicted IP gets a fresh window (documented); an actively used IP is never the LRU entry and cannot exceed its limit |
| NF-TC-3.19 | E6-UC-3-EC4 | Concurrency: 150 concurrent requests from one IP | Exactly 100 processed and 50 get 429; no race lets more than 100 through |
| NF-TC-3.20 | E6-UC-3-EC5 | Requests from `::ffff:1.2.3.4` and `1.2.3.4` | Both count against one window |
| NF-TC-3.21 | E6-UC-3-EC6 | Inspect `Retry-After` at several points in the window | Integer >= 1 and <= window length (60); a request sent after that interval succeeds |
| NF-TC-3.22 | E6-UC-3-EC7 | Flag unset; peer node IP sends 101 requests | Peer IP is limited like any client (no default node-to-node exemption) |
| NF-TC-3.23 | E6-UC-3-EC8 | Trigger a 429 and inspect the counter and logs | The 429 response is not counted twice; logs contain no request bodies |
| NF-TC-3.24 | E6-UC-3-EC9 | Inspect middleware stack order; 429 from an allowed origin | `CORSMiddleware` outermost, limiter inside; 429 carries `Access-Control-Allow-Origin` and `Access-Control-Expose-Headers` with `Retry-After` |
| NF-TC-3.25 | E6-UC-3-EC10 | Send `http`, `websocket` and `lifespan` scopes through the middleware | `http` and `websocket` keyed identically; `lifespan` passed through untouched |
| NF-TC-3.26 | E6-UC-3-EC11 | Exemption on; validator connects over its IPv4-mapped IPv6 form | Still recognized as exempt (same normalization as EC5) |
| NF-TC-3.27 | E6-UC-3-EC12 | Prometheus scrapes `GET /metrics` at the default interval | Counted like any client and stays well under the limit |

---

## 4. Reject Unregistered Issuer (E6-UC-4)

Only Epic 6 additions are tested here (check 4 of the handler order and PoW block-level evidence). The channel, authentication, check order, dedupe, view change, timeout and HTTP mapping are CN-TC-15.x and CN-TC-16.x (see the pointer table at the top).

| # | Use Case | Test Case | Expected Result |
|---|----------|-----------|-----------------|
| NF-TC-4.1 | E6-UC-4 primary | PBFT: node 2 (non-primary) forwards a validly signed record with a registered `issuer_id` to the primary | Primary authenticates sender, finds issuer in `IssuerRegistry` (check 4), verifies signature, applies duplicate rule, queues, replies `accepted` once; node 2 returns the normal acknowledgement, identical to a primary-received request |
| NF-TC-4.2 | E6-UC-4-A1 | Public `POST /documents` with a valid body; then with a `signature` and with an `issuer_id` body field | Valid body signed with the node's registered `issuer_id` and accepted; pre-signed bodies return 400 (Epic 3 validation) and never reach the registry check |
| NF-TC-4.3 | E6-UC-4-A2 | `POST /documents` to the current primary | No `forward_record` sent; primary signs with its own registered `issuer_id`; registry check passes; record accepted |
| NF-TC-4.4 | E6-UC-4-A3 | Run the unregistered-issuer scenario with `RATE_LIMIT_EXEMPT_VALIDATORS` both `true` and `false` | `forward_record` messages are not rate limited per message; the issuer check runs and yields the same result in both settings |
| NF-TC-4.5 | E6-UC-4-A7 | PoW mode: build a block whose record has an `issuer_id` absent from the receiving node's `IssuerRegistry` (hash, link, Merkle root, difficulty valid); deliver via PoW broadcast and via chain sync | Both paths reject with `failure_type = "signature"`; block not appended; tip unchanged; `blocks_rejected_total{failure_type="signature"}` +1 per path; no `unregistered_issuer` reply possible in PoW; test depends on Slice 30 |
| NF-TC-4.6 | E6-UC-4-E1 | Valid validator forwards a signed record with an unregistered `issuer_id` | Reply `unregistered_issuer` (WS reply code, not an HTTP status); `mempool_size` unchanged; no block can include it; the forwarding node returns 403 in the envelope on the original `POST /documents` |
| NF-TC-4.7 | E6-UC-4-E4 | Forward a malformed record (missing `issuer_id`, bad hash, oversized metadata) | Reply `invalid_record` (check 3) before the registry lookup; a spy on the registry confirms it is not consulted; ordering 3-before-4 holds after Slice 31; the Slice 17b test for resolver-miss `invalid_record` is updated to `unregistered_issuer` |
| NF-TC-4.8 | E6-UC-4-E5 | Forward a record with a registered `issuer_id` and an invalid signature | Reply `invalid_record`, never `unregistered_issuer`; not queued; 422 on the original request |
| NF-TC-4.9 | E6-UC-4-E6 | Enumerate public routes; submit a pre-signed record body to `POST /documents` | No public route accepts a pre-signed record; response is 400 via envelope, not 403 |
| NF-TC-4.10 | E6-UC-4-EC1 | Forward a record whose `issuer_id` differs from a registered one by case, then by trailing whitespace | Exact match only: both yield `unregistered_issuer` |
| NF-TC-4.11 | E6-UC-4-EC2 | After an `unregistered_issuer` reject, resubmit the same `document_hash` with a registered issuer | Accepted; the earlier reject left no duplicate-hash lock or mempool entry |
| NF-TC-4.12 | E6-UC-4-EC3 | Forward the same unregistered record repeatedly on one connection | `unregistered_issuer` every time; `WS /ws/pbft` stays open; rejections logged without key material |
| NF-TC-4.13 | E6-UC-4-EC4 | Replay a record already finalized on-chain | Primary replies `duplicate`; not included in a second block |
| NF-TC-4.14 | E6-UC-4-EC6 | Docs check on the OWASP checklist and NFR report for SEC4 scope; confirm A7 test is present | `unregistered_issuer` control stated as PBFT-only; PoW evidence (block-level signature rejection, NF-TC-4.5) stated; both modes appear |

---

## 5. OWASP API Security Top 10 Checklist (E6-UC-5)

| # | Use Case | Test Case | Expected Result |
|---|----------|-----------|-----------------|
| NF-TC-5.1 | E6-UC-5 primary | Docs check on `docs/security/owasp_api_top10_checklist.md` | Exactly rows API1:2023 to API10:2023; each has a control and an Epic/FR/test reference; all 10 filled |
| NF-TC-5.2 | E6-UC-5-A1 | Inspect the API2 row | Marked "not applicable" with a written reason tied to the PRD scope (intentionally unauthenticated read endpoints) |
| NF-TC-5.3 | E6-UC-5-A2 | Inspect the row for unauthenticated `POST /peers/register` | Marked "accepted risk" with reason and the measuring epic (Epic 5) |
| NF-TC-5.4 | E6-UC-5-E1 | Docs check against a copy with a missing category, a blank cell and a cell with only "TBD" | Check fails for each |
| NF-TC-5.5 | E6-UC-5-E2 | Docs check against a copy citing a nonexistent test file, FR and endpoint | Dangling references are detected and fail the check; the real checklist passes |
| NF-TC-5.6 | E6-UC-5-E3 | Docs check for mandatory records: API4 WS flooding accepted risk; API8/API9 `/metrics` unauthenticated with Prometheus/Grafana on `127.0.0.1`; WS denial mechanism plus pinned uvicorn version | Check fails if any of the three is missing; real checklist contains all three |
| NF-TC-5.7 | E6-UC-5-E4 | Docs check on SEC3/SEC4 rows | SEC4 row cites `unregistered_issuer` (PBFT) AND block-level rejection (PoW); SEC3 (API4) is a separate mode-independent row, never merged with SEC4; check fails otherwise |
| NF-TC-5.8 | E6-UC-5-EC1 | Inspect API4 and API8 rows | Reference `RATE_LIMIT_PER_MIN`, `RATE_LIMIT_EXEMPT_VALIDATORS`, `INSECURE_DEV_MODE`, `proxy_headers=False`, single worker, and the XFF control |
| NF-TC-5.9 | E6-UC-5-EC2 | Run the dangling-evidence check on a checklist reusing the same control in two rows | Duplicate evidence references are allowed (no failure) |
| NF-TC-5.10 | E6-UC-5-EC3 | Compare the application's route list (including `GET /metrics`) with the API9 inventory row | Every route, including `GET /metrics`, appears in the inventory; a new unlisted route fails the check |
| NF-TC-5.11 | E6-UC-5-EC4 | Inspect API5/API1 rows | Cite the insider threat model (attackers hold CA-signed certs), application-layer `NodeKeyPair` gating, and per-service key isolation (NF-TC-10.9, NF-TC-29.5) |
| NF-TC-5.12 | E6-UC-5-EC5 | Inspect the `forward_record` row | Cites the Epic 3 FR-22 closed enum as the contract and Epic 6 FR-6 as only the `IssuerRegistry` addition; does not claim the channel as an Epic 6 deliverable |

---

## 6. No-PII Schema Guard (E6-UC-6)

| # | Use Case | Test Case | Expected Result |
|---|----------|-----------|-----------------|
| NF-TC-6.1 | E6-UC-6 primary | Run `tests/core/test_no_pii.py` on the current `DocumentRecord` and `Block` schemas | Every field is on the allow-list; test passes |
| NF-TC-6.2 | E6-UC-6-A1 | Build a record with `metadata` exactly at the cap; assert the cap constant exists | Accepted by the schema; guard confirms the cap constant is present |
| NF-TC-6.3 | E6-UC-6-A2 | Add a non-PII structural field and update the allow-list in the same change (fixture) | Test passes; diff makes the change reviewable |
| NF-TC-6.4 | E6-UC-6-E1 | Add `owner_name` (not on the allow-list) to `DocumentRecord`, then to `Block` (fixture/mutation) | Test fails each time; CI would be blocked |
| NF-TC-6.5 | E6-UC-6-E2 | Remove the metadata cap in a fixture; submit oversized metadata through the API | Guard fails because the size bound is part of it; the API rejects oversized metadata with the standard validation error |
| NF-TC-6.6 | E6-UC-6-EC1 | Add a nested field inside a consensus sub-model of the block | Guard walks nested models and fails |
| NF-TC-6.7 | E6-UC-6-EC2 | Inspect the test docstring and OWASP checklist | Both state that `metadata` content is not inspected (schema and size only) and that clients must not place PII there |

---

## 7. TLS 1.3 for REST and WebSocket (E6-UC-7)

| # | Use Case | Test Case | Expected Result |
|---|----------|-----------|-----------------|
| NF-TC-7.1 | E6-UC-7 primary | `openssl s_client -tls1_3` and `-tls1_2` against every node's live listener; repeat programmatically in `tests/node/test_tls.py` | TLS 1.3 succeeds with a certificate chaining to the dev CA and no client certificate; TLS 1.2 refused with a protocol-version alert; the programmatic test connects to the LIVE listener |
| NF-TC-7.2 | E6-UC-7-A1 | PoW mode: mine a block and broadcast over `wss://` `WS /ws/blocks` | All peers receive it; network converges |
| NF-TC-7.3 | E6-UC-7-A2 | PBFT mode: submit a document to node 1 | pre-prepare/prepare/commit and `forward_record` travel over `wss://` `WS /ws/pbft`; document finalized on all nodes |
| NF-TC-7.4 | E6-UC-7-A3 | SPA with an `https://` base URL (test env trusts the dev CA) issues and verifies a document | Both succeed over HTTPS |
| NF-TC-7.5 | E6-UC-7-A4 | Prometheus scrapes every node over `https` with `ca_file` and `server_name` | All targets `up` |
| NF-TC-7.6 | E6-UC-7-A5 | Attacker container with a CA-signed certificate connects over TLS 1.3 and registers as a peer | Connects and registers at transport level; consensus participation remains gated by `ValidatorSet` (see NF-TC-8.15) |
| NF-TC-7.7 | E6-UC-7-E1 | Python `ssl` client with `maximum_version = TLSv1_2` and `openssl -tls1_2` against REST and WS ports | Handshake fails on both; no HTTP response is produced |
| NF-TC-7.8 | E6-UC-7-E2 | Clients forced to TLS 1.1, 1.0 and SSLv3 | All refused |
| NF-TC-7.9 | E6-UC-7-E3 | `curl http://node:8001/node/info` against a TLS port | Fails (reset or bad-request-to-TLS); no data served in clear; no redirect to a plain port |
| NF-TC-7.10 | E6-UC-7-E4 | `INSECURE_DEV_MODE` unset: port-scan the node container; attempt an outbound `ws://` peer connection | No plain HTTP/WS listener; outbound `ws://` refused by configuration |
| NF-TC-7.11 | E6-UC-7-E5 | Review/meta test on `test_tls.py`; static grep for `ssl_version`/`ssl_ciphers` | The enforcement test connects to the running listener (an `SSLContext.minimum_version` inspection alone is rejected); uvicorn `ssl_version`/`ssl_ciphers` are not used to enforce the minimum |
| NF-TC-7.12 | E6-UC-7-E6 | Outbound client dials a node by raw IP (not in SAN) | Hostname verification fails; connection refused |
| NF-TC-7.13 | E6-UC-7-E7 | Outbound client and Prometheus without the dev CA (or with a different CA) | Node certificate rejected; connection refused; never downgraded |
| NF-TC-7.14 | E6-UC-7-EC1 | Use an expired node certificate | Client-side validation fails; node logs the cause; no fallback to plain mode |
| NF-TC-7.15 | E6-UC-7-EC2 | Dial by a hostname not in the SAN; inspect generator output | Verification fails and refuses; generator SANs include compose service names and `localhost` |
| NF-TC-7.16 | E6-UC-7-EC3 | Re-run the Slice 19 compose smoke test and the Epic 5 attacker harness with TLS enabled | Both pass; attacker image mounts the same dev CA |
| NF-TC-7.17 | E6-UC-7-EC4 | Check benchmark run metadata and the report template | TLS-on is recorded for every measurement row/run; the report states all NFR measurements are taken with TLS on |
| NF-TC-7.18 | E6-UC-7-EC5 | TLS 1.3 client offering no client certificate against every node | Succeeds on every node (no mTLS); a server demanding a client certificate would fail this test |
| NF-TC-7.19 | E6-UC-7-EC6 | Test that `main.py` invokes the `tls.py` minimum-version hook and constructs no `ssl.SSLContext`; start via a non-programmatic path | Hook called after `config.load()`; `main.py` builds no context; the non-programmatic start fails the live-listener test (regression guard) |

---

## 8. Dev CA, Certificates, Server Authentication and Single Client Factory (E6-UC-8)

| # | Use Case | Test Case | Expected Result |
|---|----------|-----------|-----------------|
| NF-TC-8.1 | E6-UC-8 primary | Run the generator for n nodes plus attacker names; deliver via the init service; node 1 connects to node 2 through the factory | CA plus one cert/key per node and attacker with SANs for service names and `localhost`; one key/cert volume per service, CA cert read-only; CA private key mounted nowhere at runtime; node 1 verifies node 2's cert against `TLS_CA` and hostname; node 2 requests no client certificate |
| NF-TC-8.2 | E6-UC-8-A1 | Re-run the generator (fresh CA, and reuse mode); restart the stack | Nodes reconnect after regeneration; reuse mode keeps existing material |
| NF-TC-8.3 | E6-UC-8-A2 | Start the attacker container | Trusts dev CA read-only; holds CA-signed cert/key in its OWN volume; connects over TLS; holds no `node*` key material |
| NF-TC-8.4 | E6-UC-8-A3 | Run the generator with n = 4, 7, 10 | Output has exactly the requested node names; SANs and file names do not collide (also NF-TC-24.6) |
| NF-TC-8.5 | E6-UC-8-E1 | Node connects out to a peer presenting a self-signed cert, then a foreign-CA cert | Handshake fails; peer not added as connected; `peer_connections` does not count it healthy; error logged |
| NF-TC-8.6 | E6-UC-8-E2 | Auth boundary: client with no TLS client cert connects to a peer-facing endpoint; unauthorized (non-`ValidatorSet` or bad `NodeKeyPair` signature) vs authorized | TLS completes without a client certificate in all cases; the unauthorized peer is rejected only at the application layer (for example `not_validator`); no mTLS |
| NF-TC-8.7 | E6-UC-8-E3 | Boot with `TLS_CA`, `TLS_CERT`, `TLS_KEY` each missing or unreadable (one at a time) | Node refuses to start with a clear error; no fallback to plain or unverified TLS |
| NF-TC-8.8 | E6-UC-8-E4 | `git ls-files` check for `*.key` and private `*.pem` (including CA key); positive control with a tracked fake key | Check passes on the repo and fails on the control |
| NF-TC-8.9 | E6-UC-8-E5 | Static check (grep/AST/ruff) for `verify=False`, `ssl.CERT_NONE`, `check_hostname = False`, `http://`/`ws://` literals in outbound peer code; fixtures inside and outside the `INSECURE_DEV_MODE` branch | Fails for each pattern outside the insecure branch; passes inside it |
| NF-TC-8.10 | E6-UC-8-E6 | Static check scoped to `src/node/**` excluding `tls.py`; positive control fixture under `src/node/` building a raw `ssl.SSLContext`; same code under `attacks/` and `tests/` | Control under `src/node/` fails the check; same code under `attacks/`, `benchmarks/`, `tests/` passes; `connection_manager`, chain sync, peers client and forwarding client all use the factory |
| NF-TC-8.11 | E6-UC-8-E7 | Peer presents a CA-signed cert whose SAN lacks the dialed name | Outbound client rejects it (hostname verification on) |
| NF-TC-8.12 | E6-UC-8-E8 | Static compose check plus container test for `ca.key` | Fails if the CA private key is mounted into or present in any node, attacker, Prometheus, Grafana or k6 container; allowed only in the init service volume/operator host |
| NF-TC-8.13 | E6-UC-8-E9 | Static compose check with one keys volume mounted by two services (no distinct `subpath`); a node mounting another service's keys; CA cert mounted writable | Check fails for each; each service mounts only its own volume plus CA cert `:ro` |
| NF-TC-8.14 | E6-UC-8-E10 | Auth boundary: inside the attacker container read every `node*` key file by known path and by searching mounted volumes | Every attempt fails (absent or permission denied); no `node*` key bytes found; only own key and CA cert visible |
| NF-TC-8.15 | E6-UC-8-EC1 | Attacker with CA-signed cert completes TLS handshake and then sends consensus/forward messages | TLS accepted (insider model) but consensus participation denied by `ValidatorSet`/`NodeKeyPair` checks |
| NF-TC-8.16 | E6-UC-8-EC2 | Check generated private-key file modes and node-UID readability | Mode `0600`, readable by the node UID; skipped with recorded reason on filesystems without POSIX permissions |
| NF-TC-8.17 | E6-UC-8-EC3 | Node holding the old CA receives a certificate from a new CA | Rejected until reconfigured; no trust-on-first-use |
| NF-TC-8.18 | E6-UC-8-EC4 | Docs check | Dev CA documented as prototype-only (no revocation, no production PKI) |

---

## 9. Explicit Insecure Dev Mode (E6-UC-9)

| # | Use Case | Test Case | Expected Result |
|---|----------|-----------|-----------------|
| NF-TC-9.1 | E6-UC-9 primary | Boot with `INSECURE_DEV_MODE` unset and valid TLS config | TLS-only; no plain listener; no insecure warning |
| NF-TC-9.2 | E6-UC-9-A1 | Boot with `INSECURE_DEV_MODE=true` and no `TLS_*` paths | Boots with plain HTTP/WS; prominent boot warning logged; requests served in the clear |
| NF-TC-9.3 | E6-UC-9-E1 | Flag unset: plain HTTP request to the service port; `ws://` upgrade | No valid response; no upgrade succeeds |
| NF-TC-9.4 | E6-UC-9-E2 | Flag unset with certificates missing/invalid; exercise error and retry paths | Node exits with an error; no code path serves plain traffic |
| NF-TC-9.5 | E6-UC-9-E3 | Boot with `yes`, `1`, `True ` and empty value | Only the documented `true` enables insecure mode; others never enable it (rejected at boot or treated as unset) |
| NF-TC-9.6 | E6-UC-9-EC1 | Mixed network: node 3 insecure, others secure | Secure nodes refuse plain connections; node 3 is partitioned; `peer_connections` reflects it |
| NF-TC-9.7 | E6-UC-9-EC2 | Inspect `docker compose logs` for the boot warning | Logged exactly once per boot; no secrets |
| NF-TC-9.8 | E6-UC-9-EC3 | Static check on committed compose files | None sets `INSECURE_DEV_MODE=true`; any dev override file is clearly named and documented |
| NF-TC-9.9 | E6-UC-9-EC4 | Boot in insecure mode; run Prometheus config and outbound static checks | Prometheus scrape config and NF-TC-8.9 checks are not relaxed; plain URLs permitted only inside the insecure branch |

---

## 10. Non-Root, Read-Only Containers and Volume Ownership (E6-UC-10)

| # | Use Case | Test Case | Expected Result |
|---|----------|-----------|-----------------|
| NF-TC-10.1 | E6-UC-10 primary | `docker compose up`; `docker compose exec node1 id -u`; inspect mounts, env, key files | Init service populates each service's own volume and sets ownership before nodes start; UID non-zero; `read_only: true`, `PYTHONDONTWRITEBYTECODE=1`, `/tmp` tmpfs; key files mode `0600` owned by the node UID; node persists blocks and writes snapshots |
| NF-TC-10.2 | E6-UC-10-A1 | `docker compose exec attacker id -u`; run the attack harness | Non-zero UID; mounts dev CA read-only plus own cert/key; harness runs |
| NF-TC-10.3 | E6-UC-10-A2 | Boot a node that generates its `NodeKeyPair` in-container on first boot | Key written to the keys volume with mode `0600` under the node UID |
| NF-TC-10.4 | E6-UC-10-E1 | `tests/node/test_container_user.py` against node and attacker images (and a root-image control) | Fails if `id -u` is `0`; passes for the shipped images |
| NF-TC-10.5 | E6-UC-10-E2 | Mount a root-owned volume for persistence | Node logs a clear permission error at boot and exits; does not run degraded; docs state required ownership |
| NF-TC-10.6 | E6-UC-10-E3 | Key file with mode more permissive than `0600` | Mode test fails; skipped with recorded reason where POSIX permissions are unsupported |
| NF-TC-10.7 | E6-UC-10-E4 | Static compose check with keys/certs delivered via bind mount | Check fails; committed compose passes (named volumes only) |
| NF-TC-10.8 | E6-UC-10-E5 | `touch /app/x` and import-time bytecode generation in the container | Write fails with read-only filesystem error; no `.pyc` files generated |
| NF-TC-10.9 | E6-UC-10-E6 | Auth boundary: from the attacker container read each `node*` key and the CA private key; from `node1` look for node2..node10/attacker keys; write to the CA cert mount | All reads fail (files in other services' or init volumes, not mounted); node1 sees no foreign key; CA cert mount write fails (read-only) |
| NF-TC-10.10 | E6-UC-10-E7 | Static compose check: one named keys volume mounted by several services without distinct `subpath` | Check fails (same rule as NF-TC-8.13) |
| NF-TC-10.11 | E6-UC-10-EC1 | Boot and serve requests with a read-only root; write test outside volumes and `/tmp` | Node works; only chain, keys, snapshot volumes and `/tmp` are writable |
| NF-TC-10.12 | E6-UC-10-EC2 | Inspect the docs and entrypoint for the root-to-non-root migration | Migration step (chown or recreate volume) documented; node never auto-applies chmod 777 |
| NF-TC-10.13 | E6-UC-10-EC3 | Run a snapshot with `SNAPSHOT_DIR` on the named volume | Snapshot succeeds; volume owned by non-root UID |
| NF-TC-10.14 | E6-UC-10-EC4 | Re-run the init service on populated volumes | Chain data ownership unchanged; existing keys not overwritten; CA private key never copied to a per-service volume |
| NF-TC-10.15 | E6-UC-10-EC5 | Restart containers; inspect what lives in `/tmp` | tmpfs is not persisted; chain, keys and snapshots are never stored there |

---

## 11. Periodic Chain Snapshots (E6-UC-11)

| # | Use Case | Test Case | Expected Result |
|---|----------|-----------|-----------------|
| NF-TC-11.1 | E6-UC-11 primary | Fire the snapshot timer on a node with blocks | Task takes the `ChainState` lock, copies the block list, releases the lock, then serializes and writes off the event loop (atomic write) with a unique height+counter name; prunes to `SNAPSHOT_KEEP`; logs name and height; chain-store file is never read or copied; lock hold time covers only the copy |
| NF-TC-11.2 | E6-UC-11-A1 | `SNAPSHOT_INTERVAL_MIN=1` | A snapshot appears about every minute; no code change |
| NF-TC-11.3 | E6-UC-11-A2 | `SNAPSHOT_KEEP=3` with 5 cycles; defaults with 25 cycles | Exactly the 3 newest remain; with defaults the 25th snapshot leaves 24 |
| NF-TC-11.4 | E6-UC-11-A3 | Static import check on the `blockchain_core` snapshot module | No node config, `asyncio` or `prometheus_client` imports; takes a block list and a destination |
| NF-TC-11.5 | E6-UC-11-E1 | Boot with `SNAPSHOT_INTERVAL_MIN` 0, -1, `abc`; `SNAPSHOT_KEEP` 0 | Node fails fast naming the key (see NF-TC-30.7) |
| NF-TC-11.6 | E6-UC-11-E2 | Make `SNAPSHOT_DIR` unwritable / simulate disk full during a cycle | Temp file removed; previous snapshots kept; error logged; node keeps serving; next interval retries; consensus not crashed |
| NF-TC-11.7 | E6-UC-11-E3 | Concurrency: append block H+1 while the snapshot serializes the copy taken at height H | Snapshot holds exactly blocks 0..H (consistent prefix, no torn mix), passes FR-6 on load; live chain is at H+1 and valid; if the append wins the lock first, snapshot at H+1 is also valid |
| NF-TC-11.8 | E6-UC-11-E4 | Large chain with a heartbeat coroutine; append during serialization | Event loop keeps ticking; the append is not blocked (lock held only for the copy) |
| NF-TC-11.9 | E6-UC-11-E5 | Windows: `PermissionError` at the final rename | Cycle skipped; temp cleaned or left to the ignored-prefix rule; warning logged; next cycle retries; node does not crash |
| NF-TC-11.10 | E6-UC-11-E6 | Mutate a live block after the copy was taken; also a shallow-copy control | Frozen blocks raise on mutation / deep copies are unaffected; serialized snapshot equals pre-mutation content; shallow list copy sharing mutable blocks fails the test |
| NF-TC-11.11 | E6-UC-11-E7 | Concurrency: issue an append, a chain-sync replace and a snapshot copy together (extension of CN-TC-17.10) | Live chain passes FR-6; no append lost or interleaved with a replace; snapshot is wholly old or wholly new chain |
| NF-TC-11.12 | E6-UC-11-EC1 | `SNAPSHOT_KEEP=1` over several cycles | Old snapshot removed only after the new one is fully written; never zero snapshots at any instant |
| NF-TC-11.13 | E6-UC-11-EC2 | Snapshot a genesis-only chain and load it | Valid snapshot produced and loads |
| NF-TC-11.14 | E6-UC-11-EC3 | Two cycles at the same height | Distinct names (height + counter); neither overwrites the other |
| NF-TC-11.15 | E6-UC-11-EC4 | Chain replacement by sync while the snapshot task runs | Snapshot reflects the old or the new chain wholly, never a mixture |
| NF-TC-11.16 | E6-UC-11-EC5 | Fire the timer before `ChainState` is initialized / first block loaded | Cycle skipped; task started only after `ChainState` init |
| NF-TC-11.17 | E6-UC-11-EC6 | Static check on the snapshot task | References only the `ChainState` lock; defines no `Lock`/`RLock` of its own |

## 12. Snapshot Integrity, Atomicity and Restore (E6-UC-12)

| # | Use Case | Test Case | Expected Result |
|---|----------|-----------|-----------------|
| NF-TC-12.1 | E6-UC-12 primary | Write a snapshot; stop a fresh node, copy the snapshot into the chain-store path, start it | Temp file (ignored prefix) in `SNAPSHOT_DIR` is flushed and fsynced, then `os.replace`d to the unique final name; directory fsync on POSIX only; node loads normally, runs FR-6, adopts the snapshot height and syncs the rest; snapshot contains no key material |
| NF-TC-12.2 | E6-UC-12-A1 | Restore a snapshot at height 900 on a network at 1,000 | Node requests missing blocks via paginated `GET /chain` and reaches the tip |
| NF-TC-12.3 | E6-UC-12-A2 | Restore a PBFT chain snapshot | Loads and passes validation including `commit_signatures[]` quorum using the boot-time `ValidatorSet` |
| NF-TC-12.4 | E6-UC-12-A3 | Static check of the restore path | Uses only the Epic 2 chain load plus FR-6; no snapshot-specific loader that could bypass validation |
| NF-TC-12.5 | E6-UC-12-E1 | Fault injection in the write function between temp-file write and `os.replace` (no process kill) | Previous snapshot byte-identical; partial temp ignored by retention and loading and cleaned/ignored on next boot; next cycle succeeds |
| NF-TC-12.6 | E6-UC-12-E2 | Alter a block field in a snapshot file and load it | FR-6 fails with the matching `failure_type` (`hash` or `merkle`); node refuses to adopt, falls back to genesis plus sync |
| NF-TC-12.7 | E6-UC-12-E3 | Place `IssuerKeyPair`/`NodeKeyPair` files and private-key marker bytes next to the chain store; snapshot; static check of the snapshot module | No key file name or marker bytes in any snapshot file; module never references the key-store path or key-pair classes |
| NF-TC-12.8 | E6-UC-12-E4 | Truncate a snapshot file and load it | Structural error; no partial adoption of blocks; error logged |
| NF-TC-12.9 | E6-UC-12-E5 | `os.replace` raises `PermissionError` | Cycle skipped and logged (not fatal); previous snapshot intact; next cycle retries |
| NF-TC-12.10 | E6-UC-12-E6 | Platform-branch test for directory fsync | Directory fsync attempted only on POSIX; never on Windows, so no OS error |
| NF-TC-12.11 | E6-UC-12-E7 | Concurrency: append a block through `ChainState` between temp write and `os.replace` | Snapshot holds exactly the chain copied at lock time (NF-TC-11.7), validates on load; restore plus sync reaches the live tip |
| NF-TC-12.12 | E6-UC-12-EC1 | Leave temp files with the ignored prefix and run retention and load | Not counted as snapshots, never pruned as snapshots, never loaded as valid |
| NF-TC-12.13 | E6-UC-12-EC2 | Only one valid snapshot exists plus a newer temp file; run retention | The only valid snapshot is never deleted |
| NF-TC-12.14 | E6-UC-12-EC3 | Inspect where the temp file is created | Inside `SNAPSHOT_DIR` itself (same filesystem), not in a system temp dir or `/tmp` tmpfs |
| NF-TC-12.15 | E6-UC-12-EC4 | Two snapshots at the same height | Distinct final names (counter); neither overwrites the other |
| NF-TC-12.16 | E6-UC-12-EC5 | Restore onto a node whose store holds a longer valid chain | Operator procedure applies only to a stopped node; node never overwrites a live chain store |

---

## 13. CI Quality Gates (E6-UC-13)

| # | Use Case | Test Case | Expected Result |
|---|----------|-----------|-----------------|
| NF-TC-13.1 | E6-UC-13 primary | Inspect and run `.github/workflows/ci.yml` on a clean push | Runs `ruff`, `mypy`, `pytest --cov=src/blockchain_core --cov-fail-under=80`; all pass; job green |
| NF-TC-13.2 | E6-UC-13-A1 | Inspect workflow frontend steps | `vitest` and build run as specified in the CI/CD section and pass |
| NF-TC-13.3 | E6-UC-13-A2 | Run `tests/benchmarks/test_bench_smoke.py` in the normal pytest step | Harness runs on a 100-block chain and exits 0 |
| NF-TC-13.4 | E6-UC-13-A3 | Run the static architecture checks in pytest | Import-boundary (incl. `snapshot.py`; `prometheus_client`/`uvicorn`/`httpx` forbidden in `blockchain_core`; `src/*` never imports `benchmarks/` or `attacks/`), single TLS client factory and no-tracked-private-key checks all execute in the test step |
| NF-TC-13.5 | E6-UC-13-E1 | Drop `blockchain_core` coverage to 79.9 % (fixture) | `pytest` exits non-zero via `--cov-fail-under=80`; job fails |
| NF-TC-13.6 | E6-UC-13-E2 | Introduce a ruff violation (unused import) | Lint step fails the job |
| NF-TC-13.7 | E6-UC-13-E3 | Introduce a mypy error | Job fails |
| NF-TC-13.8 | E6-UC-13-E4 | Make the no-PII guard, then the static TLS-factory check, fail | Any failing pytest test fails the job |
| NF-TC-13.9 | E6-UC-13-EC1 | Coverage exactly 80.0 % vs 79.9 % | 80.0 % passes; below 80 fails |
| NF-TC-13.10 | E6-UC-13-EC2 | High coverage in other packages with low core coverage | Gate measures `src/blockchain_core` only; low core coverage still fails |
| NF-TC-13.11 | E6-UC-13-EC3 | Run the workflow as a fork PR without secrets | All gates run; none silently skipped for lack of a secret |

---

## 14. Trivy Image Scan (E6-UC-14)

| # | Use Case | Test Case | Expected Result |
|---|----------|-----------|-----------------|
| NF-TC-14.1 | E6-UC-14 primary | Inspect and run the CI job: restore DB cache, build from digest-pinned base, `trivy image --severity CRITICAL --exit-code 1` | 0 CRITICAL, exit 0, job green; only the node image is scanned |
| NF-TC-14.2 | E6-UC-14-A1 | Resolve a CRITICAL by re-pinning the base digest or bumping a dependency | Next run green |
| NF-TC-14.3 | E6-UC-14-A2 | Build the attacker image with a known CRITICAL | Not scanned by the gate; job does not fail on it |
| NF-TC-14.4 | E6-UC-14-E1 | Scan an image with a CRITICAL (fixture image) | Trivy exits non-zero; job fails |
| NF-TC-14.5 | E6-UC-14-E2 | CI-config check for `.trivyignore`, `--ignore-unfixed`, lowered severity on the CRITICAL gate | Check fails if any is present; committed config passes |
| NF-TC-14.6 | E6-UC-14-E3 | Make the DB download fail with no cache; make Trivy crash | Job fails; never passes silently with an unscanned image |
| NF-TC-14.7 | E6-UC-14-E4 | Static check on the node Dockerfile `FROM` (floating tag vs `@sha256:`) | Floating tag fails; digest-pinned passes |
| NF-TC-14.8 | E6-UC-14-EC1 | Image with only HIGH or lower findings | Job passes; findings reported but not gating |
| NF-TC-14.9 | E6-UC-14-EC2 | CRITICAL with no upstream fix | Job stays red; blocking recorded as accepted risk and documented in the report; not suppressed |
| NF-TC-14.10 | E6-UC-14-EC3 | Run with a stale cached DB | DB refreshed per cache policy; log records DB version/date |

---

## 15. Benchmark Harness Recording and Metadata (E6-UC-15)

| # | Use Case | Test Case | Expected Result |
|---|----------|-----------|-----------------|
| NF-TC-15.1 | E6-UC-15 primary | Run a benchmark module twice on the same commit (harness test with a fake measurement) | Each run appends one row to `results/nfr_measurements.csv` with `nfr_id`, `value`, `target`, `pass_fail`, `mode`, `achieved_rps`, `headline`, `machine`, `commit`; the second run adds a new comparable row; first row retained |
| NF-TC-15.2 | E6-UC-15-A1 | CI smoke run on a 100-block chain | Exits 0; a row with all columns is written to a TEMPORARY CSV (results file untouched); row is never `headline=true` |
| NF-TC-15.3 | E6-UC-15-E1 | Run with git unavailable, outside a repo, and on a dirty tree | Explicit `unknown` marker with warning (or refusal), never a fabricated hash; dirty tree flagged (`-dirty`) and cannot be `headline=true` |
| NF-TC-15.4 | E6-UC-15-E2 | Make platform info unreadable | `machine` column contains `unknown`, not empty |
| NF-TC-15.5 | E6-UC-15-E3 | Make `results/` read-only or the file locked | Harness exits non-zero with an error; does not report success |
| NF-TC-15.6 | E6-UC-15-E4 | Static layering check with a fixture `src/` module importing `benchmarks` or `attacks` | Check fails; real tree passes |
| NF-TC-15.7 | E6-UC-15-EC1 | Run with no CSV, then with an existing CSV | Missing CSV created with header row; existing CSV appended to, never truncated |
| NF-TC-15.8 | E6-UC-15-EC2 | Compare harness target constants with the documented Table 1.5 values | Equal; pass/fail computed from the row's target; editing a threshold fails the test |
| NF-TC-15.9 | E6-UC-15-EC3 | Build the synthetic chain twice with the fixed seed | Identical fixtures; runs differ only by timing noise |
| NF-TC-15.10 | E6-UC-15-EC4 | Validate rows for core, load and network benchmarks | `mode`, `headline`, `machine`, `commit` never empty; core rows have `mode = core` and empty `achieved_rps`; `achieved_rps` non-empty for P1, P2 and S1 end-to-end rows |
| NF-TC-15.11 | E6-UC-15-EC5 | Check CSV header; write a row missing a FR-17 column or with `mode = "x"` | Header exactly the nine PRD columns; row missing a column is refused (NF-TC-28.8); `mode` only `pow`, `pbft`, `core` |
| NF-TC-15.12 | E6-UC-15-EC6 | Inspect the final-commit re-run checklist | P4, P5 and S1 (batching) headline rows are listed for re-run alongside network-level rows |

---

## 16. NFR-P5 Full Validation of a 10,000-Block Chain (E6-UC-16)

| # | Use Case | Test Case | Expected Result |
|---|----------|-----------|-----------------|
| NF-TC-16.1 | E6-UC-16 primary | Harness test with an injected clock and a small fixture, plus the protocol run `--blocks 10000` | Fixture is 10,000 PoW-style blocks, 1 record each, low fixed difficulty, Epic 2 signature scheme; generation/load/deserialization completed before timing; only the FR-6 call is timed; 5 runs, median taken, real time-aware resolver; row has target 5 s and pass/fail computed from the measured median (value itself not asserted) |
| NF-TC-16.2 | E6-UC-16-A1 | Reuse a cached fixture | Block count and tip hash verified before timing; build/load time excluded from the measured duration |
| NF-TC-16.3 | E6-UC-16-A2 | Supplementary PBFT fixture run | Row has `mode = pbft` and a label naming the fixture (block count, n = 4 signatures per block; actual count if not 1,000); uses the same FR-6 function, median of 5, real resolver, includes `commit_signatures[]` quorum check; reported separately and never marked as the P5 pass/fail evidence |
| NF-TC-16.4 | E6-UC-16-E1 | Inject a duration whose median exceeds 5 s | Row recorded `fail` with measured value; harness exits 0; threshold unchanged; earlier and later rows both retained |
| NF-TC-16.5 | E6-UC-16-E2 | Builder produces a chain failing validation | Harness aborts with an error and writes no timing row |
| NF-TC-16.6 | E6-UC-16-E3 | Wire the benchmark to a stub/constant resolver | A test fails; benchmark must use the real time-aware resolver |
| NF-TC-16.7 | E6-UC-16-E4 | Write the supplementary row with no label, with `mode` other than `pbft`, and cite it as the P5 headline | Harness refuses an unlabelled supplementary row; report check (NF-TC-27.8) rejects a PBFT-fixture row cited as headline P5 |
| NF-TC-16.8 | E6-UC-16-E5 | PBFT fixture blocks with fewer than 2f+1 valid `commit_signatures` | Fixture fails validation; treated as invalid fixture (abort, no timing row) |
| NF-TC-16.9 | E6-UC-16-EC1 | Interrupt after fewer than 5 runs | No median row written |
| NF-TC-16.10 | E6-UC-16-EC2 | Inspect the timed region | Includes signature verification, link/hash checks, Merkle recomputation and key resolution per block (full FR-6 checklist); excludes load and deserialization |
| NF-TC-16.11 | E6-UC-16-EC3 | Run the 100-block smoke variant | Same code path; row recorded; the 5 s target is not used as P5 evidence for 100 blocks |
| NF-TC-16.12 | E6-UC-16-EC4 | Validate the low-difficulty fixture | Fixture buildable; the `difficulty` check of FR-6 still executed during validation |

---

## 17. NFR-S1 Batching: Records per Second with 256-Record Batches (E6-UC-17)

| # | Use Case | Test Case | Expected Result |
|---|----------|-----------|-----------------|
| NF-TC-17.1 | E6-UC-17 primary | Harness test: generate signed records, group into batches up to 256, verify signatures and build Merkle roots with an injected clock | records/s = total records over elapsed; row for NFR-S1 batching with target 50 records/s and pass/fail from the measured value |
| NF-TC-17.2 | E6-UC-17-A1 | Run the optional batch sizes 1, 32, 128 | Recorded as supplementary rows (distinct labels); they do not replace or stand in for the 256-record row |
| NF-TC-17.3 | E6-UC-17-E1 | Inject a throughput below 50 records/s | Row recorded `fail` with the measured value; target not edited |
| NF-TC-17.4 | E6-UC-17-E2 | Include a record with an invalid signature in the workload | Harness aborts; no throughput row written |
| NF-TC-17.5 | E6-UC-17-EC1 | Workload of full 256 batches plus a final partial batch of 100 | Both counted; records/s uses total records over total elapsed time |
| NF-TC-17.6 | E6-UC-17-EC2 | Inspect the timed region and row notes | Signing time excluded (only verification and Merkle construction timed); the boundary is stated in the row notes |
| NF-TC-17.7 | E6-UC-17-EC3 | Inspect warm-up handling | Warm-up iterations excluded or explicitly documented in the row |

---

## 18. NFR-P4 PoW Mean Block Time (E6-UC-18)

| # | Use Case | Test Case | Expected Result |
|---|----------|-----------|-----------------|
| NF-TC-18.1 | E6-UC-18 primary | Harness test with injected block times: calibrate over at least 100 blocks, freeze difficulty, then mine at least 30 further blocks | Mean, standard deviation, min, max computed from the post-calibration blocks only; row has difficulty, scope label (single miner in-process), machine, commit; pass/fail judged on the mean against 5 to 15 s |
| NF-TC-18.2 | E6-UC-18-A1 | First run mean 22 s; recalibrate on a fresh chain and re-run | Recalibration is a configuration step, target unchanged; new run starts from a fresh chain; both rows retained |
| NF-TC-18.3 | E6-UC-18-A2 | Measure on the 4-node compose network | Separate row labelled `compose network`; does not replace the single-miner row |
| NF-TC-18.4 | E6-UC-18-E1 | Inject a mean outside 5 to 15 s after calibration | Row `fail` with cause note; tolerance not widened |
| NF-TC-18.5 | E6-UC-18-E2 | Interrupt after fewer than 30 measured blocks | No pass/fail row; only a partial note |
| NF-TC-18.6 | E6-UC-18-E3 | Supply fewer than 100 calibration blocks | Harness refuses to freeze difficulty and reports insufficient calibration |
| NF-TC-18.7 | E6-UC-18-E4 | Attempt to change difficulty on a chain that already has blocks | Rejected (Epic 3 FR-24); harness requires a fresh chain |
| NF-TC-18.8 | E6-UC-18-EC1 | Inject a high-variance (exponential) sample | Spread reported; pass/fail uses the mean |
| NF-TC-18.9 | E6-UC-18-EC2 | Inject means of exactly 5.0 s and 15.0 s (and just outside) | Boundary values count as within range; just outside fails |
| NF-TC-18.10 | E6-UC-18-EC3 | Inspect the row | Difficulty recorded is the calibrated one; calibration blocks excluded from the 30-or-more sample |

---

## 19. Load-Test Client and Rate-Limiter Interplay (E6-UC-19)

| # | Use Case | Test Case | Expected Result |
|---|----------|-----------|-----------------|
| NF-TC-19.1 | E6-UC-19 primary | Start with `-f docker-compose.yml -f docker-compose.bench.yml`; inspect config, run metadata and a k6 run | Override raises `RATE_LIMIT_PER_MIN` above the offered rate (above 12,000/min for 200 RPS); limiter stays in the path; exemption flag not used; k6 is a service with its own `cpuset` and dev-CA cert read-only, no node keys or CA key; `constant-arrival-rate`; no 429s; limit value, `cpuset` and executor written to run metadata and cited in the row/report |
| NF-TC-19.2 | E6-UC-19-A1 | Inspect committed config vs the bench override | `RATE_LIMIT_PER_MIN=100000` only in the bench override; committed default stays 100 |
| NF-TC-19.3 | E6-UC-19-A2 | Review per-IP limiter tests and benchmark docs | Per-IP tests use ASGI scope injection or multiple client containers; load benchmarks use the raised limit; "distributed source IPs" is not offered as a benchmark mitigation |
| NF-TC-19.4 | E6-UC-19-A3 | PBFT POST load to non-primaries | Report records that forwarding used `WS /ws/pbft` (not per-request limited) and records the raised limit value |
| NF-TC-19.5 | E6-UC-19-E1 | Inject a 429 into the response stream | Run marked invalid; harness reports rate-limit interference; 429 latencies not included in p95 |
| NF-TC-19.6 | E6-UC-19-E2 | Preflight with default 100/min and an offered 200 RPS | Harness aborts with a clear message when the effective limit is below the offered rate |
| NF-TC-19.7 | E6-UC-19-E3 | Preflight with `RATE_LIMIT_EXEMPT_VALIDATORS=true` | Run fails (limiter would leave the measured path) |
| NF-TC-19.8 | E6-UC-19-E4 | Closed-loop k6 script (fixed VUs); a script or compose file referencing another load tool | Closed-loop script rejected for headline use; static check fails on any non-k6 load tool |
| NF-TC-19.9 | E6-UC-19-E5 | `cpuset` cannot be applied or recorded | Row flagged and not usable as headline evidence |
| NF-TC-19.10 | E6-UC-19-E6 | k6 without the dev CA; CA mounted writable; CA private key or node key mounted | TLS verification fails (no `insecure` skip permitted) or the compose static check fails; run does not start |
| NF-TC-19.11 | E6-UC-19-EC1 | Inspect the default compose file | `RATE_LIMIT_PER_MIN` unset (100) and no reference to the bench override |
| NF-TC-19.12 | E6-UC-19-EC2 | Inspect run metadata and report | States metrics export, Prometheus scraping and Grafana were active during measurement |
| NF-TC-19.13 | E6-UC-19-EC3 | Inject achieved RPS below target | Achieved RPS recorded next to target in every load row; the below-target run is flagged |

---

## 20. NFR-P1 `GET /documents/{hash}` at 200 RPS (E6-UC-20)

| # | Use Case | Test Case | Expected Result |
|---|----------|-----------|-----------------|
| NF-TC-20.1 | E6-UC-20 primary | Harness/protocol test with a stubbed load report: seeded finalized hashes, 200 RPS for at least 60 s open loop, one node, PBFT mode | Row records p50/p95/p99, error count, achieved RPS, `mode = pbft`, target 200 ms judged on p95; pass requires achieved RPS within the stated tolerance of 200 and 0 errors (value itself not asserted) |
| NF-TC-20.2 | E6-UC-20-A1 | Repeat against a second node | Both runs recorded with their own node label |
| NF-TC-20.3 | E6-UC-20-A2 | Optional PoW-mode run | Row annotated that 4 miners share host CPU; `headline=false` |
| NF-TC-20.4 | E6-UC-20-E1 | Inject p95 above 200 ms | Recorded `fail` with p50/p95/p99 and suspected cause; target stays 200 ms; optimization re-run keeps both rows |
| NF-TC-20.5 | E6-UC-20-E2 | Inject 404/5xx responses into the stream | Error rate recorded; a high error rate invalidates the run rather than lowering latency |
| NF-TC-20.6 | E6-UC-20-E3 | Inject a 429 | Run invalid (as NF-TC-19.5) |
| NF-TC-20.7 | E6-UC-20-EC1 | Inspect warm-up handling | A documented warm-up window is excluded or reported; only-bad-samples trimming is never allowed (static/data check) |
| NF-TC-20.8 | E6-UC-20-EC2 | Inject achieved RPS below 200 | Run flagged; achieved RPS recorded; not accepted as 200 RPS evidence |
| NF-TC-20.9 | E6-UC-20-EC3 | Workload includes a nonexistent hash | Workload generator contains existing documents only; a 404 sample is excluded/invalidates the run |

---

## 21. NFR-P2 `POST /documents` at 50 RPS (E6-UC-21)

| # | Use Case | Test Case | Expected Result |
|---|----------|-----------|-----------------|
| NF-TC-21.1 | E6-UC-21 primary | Harness test with a stubbed report containing primary- and non-primary-received samples | Unique SHA-256 hashes at constant 50 RPS; latency is acceptance latency (to the accept response), not finalization; non-primary samples include the `forward_record` round-trip; THREE rows written (primary-received, non-primary-received, overall) each with p50/p95/p99, achieved RPS, traffic share and mode; each judged on p95 against 300 ms |
| NF-TC-21.2 | E6-UC-21-A1 | Send all traffic to a single node role | All three rows still written; the empty group marked `n/a` with a note, never omitted; row states the target role and that forwarding is not per-request rate limited |
| NF-TC-21.3 | E6-UC-21-A2 | Optional PoW-mode run | Annotated, `headline=false` |
| NF-TC-21.4 | E6-UC-21-A3 | Spread load across all four nodes | About 25 % primary / 75 % non-primary; recorded traffic shares are checked against the distribution actually sent |
| NF-TC-21.5 | E6-UC-21-E1 | Inject a non-primary p95 above 300 ms and a primary p95 below | Non-primary row `fail` with forward-overhead cause; primary row judged on its own merits; overall row judged on the combined samples with neither group dropped; target unchanged |
| NF-TC-21.6 | E6-UC-21-E2 | Reuse a hash and get 409 | Those samples invalidate the run; generator uniqueness enforced |
| NF-TC-21.7 | E6-UC-21-E3 | Mempool backlog causes 4xx/5xx | Error rate recorded; run flagged |
| NF-TC-21.8 | E6-UC-21-E4 | Inject a 429 | Run invalid (NF-TC-19.5) |
| NF-TC-21.9 | E6-UC-21-E5 | Inject 503 (`not_primary`, `forward_timeout`, view change) and other forward-mapped errors from non-primaries | Counted in the error rate; a high error rate invalidates the run; samples not excluded from the latency figure |
| NF-TC-21.10 | E6-UC-21-E6 | Attempt to write a single P2 row without the role split | Harness refuses; all three rows are required |
| NF-TC-21.11 | E6-UC-21-EC1 | Inspect row notes and report text | Measurement defined as acceptance latency; finalization reported separately (E6-UC-22, E6-UC-23); difference stated |
| NF-TC-21.12 | E6-UC-21-EC2 | Inspect measured path | Server-side signing time included in the latency |
| NF-TC-21.13 | E6-UC-21-EC3 | Run while PBFT rounds create blocks | Measured as is; stack is not paused or throttled to help the numbers |
| NF-TC-21.14 | E6-UC-21-EC4 | Inject achieved RPS below 50 | Run flagged (NF-TC-19.13) |

---

## 22. NFR-P3 PBFT Finalization Time (E6-UC-22)

| # | Use Case | Test Case | Expected Result |
|---|----------|-----------|-----------------|
| NF-TC-22.1 | E6-UC-22 primary | Harness test with synthetic per-node `ConsensusMetric` data (at least 100 blocks, 4 nodes) and a matching `/metrics` histogram count | S1 load applied and batch size recorded; samples are the interval pre-prepare -> local commit quorum from ALL correct nodes; count cross-checked against `consensus_finalization_seconds{algorithm="pbft"}`; p95 is the judged value with mean/p50/max supplementary; batch size and sample count in the row |
| NF-TC-22.2 | E6-UC-22-A1 | A view change occurs during the run | Affected blocks included and counted; number of view changes noted in the row |
| NF-TC-22.3 | E6-UC-22-E1 | Inject p95 above 2 s | Recorded `fail` with cause; target unchanged |
| NF-TC-22.4 | E6-UC-22-E2 | Provide fewer than 100 blocks | No pass/fail row; partial result annotated |
| NF-TC-22.5 | E6-UC-22-E3 | Provide samples from a subset of correct nodes | Run flagged; samples from all correct nodes are required |
| NF-TC-22.6 | E6-UC-22-E4 | Supply data where mean, median and max would give a different verdict than p95 | Judged-value field is computed with the p95 definition; test asserts the computation; other statistics supplementary only |
| NF-TC-22.7 | E6-UC-22-EC1 | Provide JSON and Prometheus counts that disagree | Discrepancy reported; run invalid; `/metrics/consensus` is the documented primary source |
| NF-TC-22.8 | E6-UC-22-EC2 | Run with empty blocks and with full 256-record batches | Batch size in effect stated in the row |
| NF-TC-22.9 | E6-UC-22-EC3 | Attempt a PoW-mode P3 run | Not measured for P3; report says PoW finalization is covered by P4 |
| NF-TC-22.10 | E6-UC-22-EC4 | A node stopped or partitioned during the run | Contributes no samples; the node set is recorded in the row |

## 23. NFR-S1 End-to-End: At Least 50 Records per Second (E6-UC-23)

| # | Use Case | Test Case | Expected Result |
|---|----------|-----------|-----------------|
| NF-TC-23.1 | E6-UC-23 primary | Harness test with synthetic accepted/finalized counts in PBFT mode | Constant arrival rate of at least 50 records/s, batches up to 256; rate = records finalized on-chain divided by the steady-state window; headline row `mode = pbft` with target 50; backlog growth checked; all submitted records on-chain or accounted for |
| NF-TC-23.2 | E6-UC-23-A1 | PoW-mode S1 run | Separate row, `headline=false`, annotated with 256 / 10 s = 25.6 records/s and "mode limit, not a target change"; `fail` against the unchanged 50 target |
| NF-TC-23.3 | E6-UC-23-E1 | Inject a PBFT rate below 50 records/s | Recorded `fail` with cause note |
| NF-TC-23.4 | E6-UC-23-E2 | Finalized count less than accepted count | Run flagged as a correctness failure, separate from the throughput figure |
| NF-TC-23.5 | E6-UC-23-E3 | Diff that lowers the 50 target or flips the PoW row to `pass` | Target-constant test (NF-TC-15.8) and review check (NF-TC-27.6) reject it |
| NF-TC-23.6 | E6-UC-23-EC1 | Inspect the row | Steady-state window excludes ramp-up and drain and is stated in the row |
| NF-TC-23.7 | E6-UC-23-EC2 | Inspect PoW annotation and headline selection | Arithmetic explains the cap; headline S1 row is PBFT mode; target not adjusted |
| NF-TC-23.8 | E6-UC-23-EC3 | Compare S1 and P3 rows from the same load | Same S1 load drives P3 sampling; batch size in effect recorded in both rows |

---

## 24. NFR-S2 Scale from n = 4 to 7 and 10 by Configuration (E6-UC-24)

| # | Use Case | Test Case | Expected Result |
|---|----------|-----------|-----------------|
| NF-TC-24.1 | E6-UC-24 primary | Harness procedure for n = 4, then 7, then 10: generate compose, certs, `ValidatorSet`; start; submit a document to node 1; poll `GET /documents/{hash}` on all nodes | Row per n and mode: document finalized on every node; convergence time and nodes converged recorded; stacks torn down cleanly |
| NF-TC-24.2 | E6-UC-24-A1 | Run the procedure in PoW mode for n = 4, 7, 10 | Converges on all nodes at each n |
| NF-TC-24.3 | E6-UC-24-A2 | Run in PBFT mode and inspect the quorum used | Converges; quorum 2f+1 computed from configured n (3, 5, 7 for n = 4, 7, 10) |
| NF-TC-24.4 | E6-UC-24-E1 | Inject a lagging node at some n | Recorded `fail` with lagging node(s) and cause |
| NF-TC-24.5 | E6-UC-24-E2 | Diff between n = 4, 7, 10 runs includes a source change | NFR-S2 recorded `fail`; harness verifies the diff is generated configuration only |
| NF-TC-24.6 | E6-UC-24-E3 | Generate for n above 4 with a forced port/cert collision | Generator produces non-colliding ports/certs for all n, or the run fails with a clear error |
| NF-TC-24.7 | E6-UC-24-EC1 | Inspect generated `validators.json` | n = 7 -> f = 2, n = 10 -> f = 3; n >= 3f+1 holds |
| NF-TC-24.8 | E6-UC-24-EC2 | Start nodes at staggered speeds | Seed-peer retry lets the stack form without a manual restart |
| NF-TC-24.9 | E6-UC-24-EC3 | Inject resource exhaustion at 10 containers plus Prometheus/Grafana | Miss recorded with this cause; n is not reduced to hide it |
| NF-TC-24.10 | E6-UC-24-EC4 | `tests/benchmarks/test_scale_config.py` for each n | Generated compose, `validators.json` and Prometheus targets internally consistent (names, ports, SANs, n/f) without starting containers |

---

## 25. NFR-R1 Finalization with Up to floor((n-1)/3) Nodes Stopped (E6-UC-25)

| # | Use Case | Test Case | Expected Result |
|---|----------|-----------|-----------------|
| NF-TC-25.1 | E6-UC-25 primary | Harness procedure: stop floor((n-1)/3) non-primary nodes (1, 2, 3 for n = 4, 7, 10); submit a document to a running node | Remaining nodes finalize; finalization confirmed on all running nodes; row per n; stopped nodes stay stopped until the harness restores them |
| NF-TC-25.2 | E6-UC-25-A1 | Stop set includes the current primary | View change elects the next primary; finalization resumes within the timeout; time to finalize recorded |
| NF-TC-25.3 | E6-UC-25-E1 | No finalization within timeout | Recorded `fail` with cause (for example view-change timeout) |
| NF-TC-25.4 | E6-UC-25-E2 | Negative control: stop floor((n-1)/3)+1 nodes | Document is NOT finalized; no conflicting block produced; confirms the bound is not trivially satisfied |
| NF-TC-25.5 | E6-UC-25-E3 | Stopped nodes cannot rejoin after the test | Harness records the problem; recovery covered by E6-UC-26 |
| NF-TC-25.6 | E6-UC-25-EC1 | Run n = 4 (baseline), then 7 and 10 | Same procedure, configuration only |
| NF-TC-25.7 | E6-UC-25-EC2 | Run in PoW mode | Row states the mode and liveness of block production by remaining miners; PBFT is the primary evidence |
| NF-TC-25.8 | E6-UC-25-EC3 | Run with rate limiter and TLS on and peers down | Down peers neither exhaust the limiter nor block the event loop (connection retry with backoff) |

---

## 26. NFR-R2 Node Restart After 1,000 Blocks (E6-UC-26)

| # | Use Case | Test Case | Expected Result |
|---|----------|-----------|-----------------|
| NF-TC-26.1 | E6-UC-26 primary | Harness procedure `--blocks 1000`: reach 1,000 blocks (PBFT live or fixture), stop node 4, let it fall behind, restart, start timer, wait for tip | Approach recorded; node reconnects over TLS and syncs via paginated `GET /chain` with full validation; row has convergence time, block gap, approach, target 30 s with pass/fail from the measured time (value not asserted) |
| NF-TC-26.2 | E6-UC-26-A1 | Restart with a snapshot at a recent height | Only the remainder is synced; recorded as a supplementary row |
| NF-TC-26.3 | E6-UC-26-A2 | Fixture approach | Pre-generated chain loaded and validated through the normal load path (not injected past validation); report states the fixture approach |
| NF-TC-26.4 | E6-UC-26-E1 | Inject convergence above 30 s | Recorded `fail` with time and cause; threshold unchanged; optimization re-run keeps both rows |
| NF-TC-26.5 | E6-UC-26-E2 | Node never converges (validation failure or repeated peer error) | Harness times out, records `fail`, captures node logs |
| NF-TC-26.6 | E6-UC-26-E3 | Corrupt the local chain store before restart | Local chain fails FR-6 on boot and is discarded; node syncs from peers; time measured from restart to tip |
| NF-TC-26.7 | E6-UC-26-E4 | Peers answer sync with 429 (default limit left in place) | Run invalid and flagged; bench override raises the limit; exemption flag not used |
| NF-TC-26.8 | E6-UC-26-EC1 | Network keeps producing blocks during sync | Convergence defined as within a stated tolerance of the live tip; the definition is recorded |
| NF-TC-26.9 | E6-UC-26-EC2 | Inspect the sync request volume against the effective limit | Paginated sync stays under the raised bench limit; the value is recorded |
| NF-TC-26.10 | E6-UC-26-EC3 | Start with 999 and with 1,001 blocks | Only exactly 1,000 accepted as the starting condition (or the gap size is recorded in the row) |

---

## 27. NFR Report and Honest Reporting (E6-UC-27)

| # | Use Case | Test Case | Expected Result |
|---|----------|-----------|-----------------|
| NF-TC-27.1 | E6-UC-27 primary | Docs check on `docs/results/nfr_report.md` | Lists all 19 IDs (P1-P5, S1-S2, SEC1-SEC4, C1, R1-R3, I1-I3, M1); each has unchanged target, measured value where measurable, pass/fail and evidence; measured values match the latest headline CSV row and commit hash |
| NF-TC-27.2 | E6-UC-27-A1 | Inspect non-measurable rows | SEC1-SEC4, C1, I1-I3, M1 cite a test or gate; R3 and SEC1 cite originating Epic evidence; SEC3 cites the rate limit as mode-independent; SEC4 cites `unregistered_issuer` (PBFT) and block-level signature rejection (PoW, relying on `blocks_rejected_total`) |
| NF-TC-27.3 | E6-UC-27-A2 | Report with a re-measured ID | Original and post-optimization results both kept, labelled with commit hashes, current one stated |
| NF-TC-27.4 | E6-UC-27-A3 | Inspect annotations | S1 PoW 25.6 records/s arithmetic and "mode limit, not a target change"; P4 scope; R2 approach; P3 statistic (p95) and interval; P2 three rows; supplementary PBFT-fixture P5 row beside, not in place of, the headline |
| NF-TC-27.5 | E6-UC-27-E1 | Report with a missed target (fixture) | Shows `fail` plus suspected cause; a miss is never omitted or shown as pass |
| NF-TC-27.6 | E6-UC-27-E2 | Diff changing a target, threshold, tolerance or measurement config together with a flipped result | Target-constant test (NF-TC-15.8) fails and review rejects |
| NF-TC-27.7 | E6-UC-27-E3 | Report with 18 IDs, and one with a row lacking evidence | Doc check counting IDs fails for each |
| NF-TC-27.8 | E6-UC-27-E4 | Report citing a `headline=false` row, a row from another commit, or the PBFT-fixture P5 row as pass/fail evidence | Consistency check rejects each |
| NF-TC-27.9 | E6-UC-27-E5 | Report with SEC4 citing one mode only; with SEC3 presented as mode-specific | Doc check fails; SEC4 must state both modes and SEC3 the mode-independent rate limit |
| NF-TC-27.10 | E6-UC-27-EC1 | Inspect report caveats | States single host, n = 4 (7/10 for scale), TLS on, metrics export on, no multi-host generalization |
| NF-TC-27.11 | E6-UC-27-EC2 | Inspect report configuration section | States raised `RATE_LIMIT_PER_MIN`, generator pinning and achieved RPS |
| NF-TC-27.12 | E6-UC-27-EC3 | Report mixing pre-hardening rows | Pre-hardening rows labelled non-headline and not mixed in; each headline number cites the final hardened commit hash |

---

## 28. Early Indicative Runs vs Headline Rows (E6-UC-28)

| # | Use Case | Test Case | Expected Result |
|---|----------|-----------|-----------------|
| NF-TC-28.1 | E6-UC-28 primary | Early run before hardening, then re-run at the final commit on a clean tree | Early rows `headline=false`; final-commit rows `headline=true` with final commit hash, clean tree and all nine columns populated for P1, P2 (three rows), P3, P4, P5, S1 (batching and end-to-end), S2, R1, R2; report cites only headline rows; early rows retained |
| NF-TC-28.2 | E6-UC-28-A1 | Re-run only P5 after an optimization | New row `headline=true` with its own commit; older P5 row demoted to non-headline; both retained |
| NF-TC-28.3 | E6-UC-28-A2 | Early run shows a miss; optimize; headline run later | Early row is never used as pass/fail evidence |
| NF-TC-28.4 | E6-UC-28-A3 | Automated check on the set of NFR IDs with `headline=true` at the final commit | Compared against the list P1-P5, S1 (batching and end-to-end), S2, R1, R2; any missing ID reported |
| NF-TC-28.5 | E6-UC-28-E1 | Headline row whose commit differs from the final commit or ends `-dirty` | Consistency check rejects; metric must be re-run |
| NF-TC-28.6 | E6-UC-28-E2 | Report citing a `headline=false` row | Review/check rejects (as NF-TC-27.8) |
| NF-TC-28.7 | E6-UC-28-E3 | Headline run with TLS, metrics export or the limiter disabled | Rejected; run metadata config snapshot must show FR-1 to FR-11 enabled |
| NF-TC-28.8 | E6-UC-28-E4 | CSV lacking the `headline` column or with empty values; row missing any FR-17 column | Harness refuses to write the row |
| NF-TC-28.9 | E6-UC-28-E5 | P4, P5 or S1-batching headline row with a commit older than the final commit | Consistency check rejects; benchmark must be re-run |
| NF-TC-28.10 | E6-UC-28-E6 | Mark the PBFT-fixture P5 row or a PoW S1 row `headline=true` as pass/fail evidence | Check rejects; only the 10,000-block P5 row and the PBFT-mode S1 row can be headline |
| NF-TC-28.11 | E6-UC-28-EC1 | ID measured only early, never re-run | No headline row; report marks "not yet measured at final commit" and does not cite the early row |
| NF-TC-28.12 | E6-UC-28-EC2 | Two headline rows for one ID at different commits | Only the latest is current; earlier one flagged non-headline |
| NF-TC-28.13 | E6-UC-28-EC3 | Inspect non-measurable NFRs | No CSV row; evidence is the test/gate result at the final commit |

---

## 29. SPA HTTPS Base URL, 429/503 Handling and Attacker Image Ownership (E6-UC-29)

| # | Use Case | Test Case | Expected Result |
|---|----------|-----------|-----------------|
| NF-TC-29.1a | E6-UC-29 primary (SPA over HTTPS, Slice 32b) | SPA with a configurable `https://` base URL (no hard-coded plain URL) issues and verifies a document | 2xx over HTTPS (dev CA trusted); no hard-coded plain URL. Owned by Slice 32b |
| NF-TC-29.1b | E6-UC-29 primary (attacker container, Slice 33a) | Start the attacker container; inspect user, mounts and connections (cross-ref NF-TC-10.2) | Attacker starts non-root, mounts CA read-only and own cert/key from its own volume, connects over `wss://`/`https://`; no dev-CA private key or `node*` key in the attacker. Owned by Slice 33a |
| NF-TC-29.2 | E6-UC-29-A1 | Client test: 429 with `Retry-After: 8`; advance time | Rate-limit message "retry after 8 seconds", not "document not found/invalid"; no retry before the interval; retry after the interval shows the normal result |
| NF-TC-29.3 | E6-UC-29-A2 | 429 with missing and with non-numeric `Retry-After` | Generic rate-limit message; no crash; no tight retry loop |
| NF-TC-29.4 | E6-UC-29-A3 | Change the base URL setting to another node's HTTPS address | All calls redirect with no code change |
| NF-TC-29.5 | E6-UC-29-A4 | Auth boundary: inside the running attacker container read every `node*` key (`NodeKeyPair`, `IssuerKeyPair`, TLS key of node1..node10) and the CA private key; run the harness | Every read fails; only own key material plus read-only CA cert present; harness still runs with its own certificate (insider can join TLS but cannot impersonate a validator) |
| NF-TC-29.6 | E6-UC-29-A5 | Client test: `POST /documents` returns 503 with `Retry-After: 3` (also missing/non-numeric) | "Node temporarily unavailable, retry after 3 seconds"; no retry before the interval; generic message for bad header; no tight loop; never a verification failure |
| NF-TC-29.7 | E6-UC-29-A6 | Client tests: 403 (`unregistered_issuer`), 422 (`invalid_record`), 502 (`not_validator`, `auth_failed`, out-of-enum code) on issuance | Each shown as a node/issuance error with the envelope `error.message`; none as "document not found/invalid"; no automatic retry |
| NF-TC-29.8 | E6-UC-29-A7 | Client tests: 503 then user retry; 409 on retry; inspect for background resubmission | SPA never auto-resubmits (retry only user-initiated after `Retry-After`); 409 treated as "already submitted" (not an error, not a new issuance) with an offer to verify the hash |
| NF-TC-29.9 | E6-UC-29-E1 | Server and client test: 429 without CORS headers / without `Retry-After` exposed | `client429.test.ts` plus the server CORS test (NF-TC-3.24) together fail in that case |
| NF-TC-29.10 | E6-UC-29-E2 | Regression: map 429 to "document invalid/not found" | Client unit test fails |
| NF-TC-29.11 | E6-UC-29-E3 | Point the SPA at `http://` while the node is TLS-only | Connection error shown (not a verification result); no downgrade attempted |
| NF-TC-29.12 | E6-UC-29-E4 | Environment that does not trust the dev CA | Certificate error surfaced as a connection problem, not a verification failure |
| NF-TC-29.13 | E6-UC-29-E5 | Attacker as root, or without the CA | `id -u` = 0 fails the container test (NF-TC-10.4); harness reports a TLS error when it cannot validate node certs |
| NF-TC-29.14 | E6-UC-29-E6 | Attacker mounting a node-shared keys volume or the CA private key | Compose static checks (NF-TC-8.12, NF-TC-8.13) fail |
| NF-TC-29.15 | E6-UC-29-EC1 | `Retry-After: 3600` | Value shown as given; automatic retry timer capped to a sane maximum; manual retry stays available |
| NF-TC-29.16 | E6-UC-29-EC2 | Several in-flight requests all receive 429 | One consolidated rate-limit message, not a stack of toasts |
| NF-TC-29.17 | E6-UC-29-EC3 | Inspect Epic 5 findings text | States attackers hold CA-signed certs (insider model); attacker TLS admission is not under test |
| NF-TC-29.18 | E6-UC-29-EC4 | Inspect the SPA diff | No new React pages/components; Grafana remains outside the SPA |
| NF-TC-29.19 | E6-UC-29-EC5 | Client unit tests for 503, 403, 422, 502, 409 | Each maps correctly; a regression mapping any to a verification result, or adding auto-retry on issuance, fails |

---

## 30. Fail-Fast Configuration Validation at Boot (E6-UC-30)

| # | Use Case | Test Case | Expected Result |
|---|----------|-----------|-----------------|
| NF-TC-30.1 | E6-UC-30 primary | Boot with valid config, and with keys unset | Validation of all new keys occurs before any listener opens; node starts; logs effective non-secret values (never key material) |
| NF-TC-30.2 | E6-UC-30-A1 | `INSECURE_DEV_MODE=true` with unreadable `TLS_*` paths | Not an error; boot warning of NF-TC-9.2 logged instead |
| NF-TC-30.3 | E6-UC-30-A2 | Boot with all optional keys unset | Defaults applied: limit 100, exemption false, cap 10,000, insecure false, snapshot interval 60, keep 24, `FORWARD_ACK_TIMEOUT_MS` 2000; only invalid/missing-required values fail |
| NF-TC-30.4 | E6-UC-30-A3 | `FORWARD_ACK_TIMEOUT_MS` unset, then 500 | Log shows effective 2000, then 500 used by the forwarder (CN-TC-15.15). Ownership note: same assertions as CN-TC-15.15, implemented once and tagged with both IDs |
| NF-TC-30.5 | E6-UC-30-E1 | `RATE_LIMIT_PER_MIN` non-numeric, 0, negative, empty | Non-zero exit with an error naming the key; never starts with the limiter disabled |
| NF-TC-30.6 | E6-UC-30-E2 | `RATE_LIMIT_EXEMPT_VALIDATORS` and `INSECURE_DEV_MODE` with unrecognized boolean values | Exit with an error; unrecognized value never enables exemption or insecure mode |
| NF-TC-30.7 | E6-UC-30-E3 | `SNAPSHOT_KEEP` < 1; `SNAPSHOT_INTERVAL_MIN` < 1 or non-numeric; `SNAPSHOT_DIR` missing/unwritable | Exit with an error naming the key, one case per key |
| NF-TC-30.8 | E6-UC-30-E4 | Each of `TLS_CERT`, `TLS_KEY`, `TLS_CA` one at a time missing, unreadable, unparseable; and a key not matching its cert, with `INSECURE_DEV_MODE` not `true` | Exit with an error naming that key; no fallback to plain or unverified TLS |
| NF-TC-30.9 | E6-UC-30-E5 | `RATE_LIMIT_MAX_TRACKED_IPS` zero, negative, non-numeric | Fails fast naming the key |
| NF-TC-30.10 | E6-UC-30-E6 | Several invalid keys at once | Error lists every invalid key (or first, with all discoverable on a second run); node does not start |
| NF-TC-30.11 | E6-UC-30-E7 | `FORWARD_ACK_TIMEOUT_MS` non-numeric, empty, 0, negative; then 1 and 2000 | Invalid values exit non-zero naming the key (core validation CN-TC-15.16/15.17); 1 and the default accepted; never unbounded or zero wait. Ownership note: same assertions as CN-TC-15.16/15.17, implemented once and tagged with both IDs |
| NF-TC-30.12 | E6-UC-30-E8 | Parametrized test over the full key set: rate-limit (3 keys), TLS (`TLS_CERT`, `TLS_KEY`, `TLS_CA`, `INSECURE_DEV_MODE`), snapshot (3 keys), `FORWARD_ACK_TIMEOUT_MS`; compare key list with the node configuration schema | One invalid value per key gives non-zero exit naming that key; a configuration key without a matrix row fails the test |
| NF-TC-30.13 | E6-UC-30-EC1 | Values `" 100 "` and `TRUE` | Normalized by a documented rule or rejected; deterministic and tested |
| NF-TC-30.14 | E6-UC-30-EC2 | Inspect error messages for invalid TLS material | Name the key and constraint; never print key contents or other secrets |
| NF-TC-30.15 | E6-UC-30-EC3 | Fail validation and inspect process state | Validation precedes creation of the snapshot task, limiter and listener; no open port or running task remains |
| NF-TC-30.16 | E6-UC-30-EC4 | `RATE_LIMIT_PER_MIN=100000` | Accepted (bench override) |
| NF-TC-30.17 | E6-UC-30-EC5 | Bad `FORWARD_ACK_TIMEOUT_MS` in PoW mode | Still fails fast; validated in every consensus mode. Ownership note: same assertions as CN-TC-15.17 (validation in every mode), implemented once and tagged with both IDs |

---

## 31. Coverage Matrix (UC -> TC IDs)

| Use case | Scenarios | Test cases | Count |
|---|---|---|---|
| E6-UC-1 | primary, A1-A3, E1-E5, EC1-EC5 | NF-TC-1.1 to 1.14 | 14 |
| E6-UC-2 | primary, A1-A3, E1-E5, EC1-EC3 | NF-TC-2.1a, 2.1b, 2.2 to 2.12 | 13 |
| E6-UC-3 | primary, A1-A6, E1-E8, EC1-EC12 | NF-TC-3.1 to 3.27 | 27 |
| E6-UC-4 | primary, A1-A3, A7, E1, E4-E6, EC1-EC4, EC6 (A4-A6, A8-A10, E2, E3, E7, E8, EC5, EC7, EC8 MOVED) | NF-TC-4.1 to 4.14; moved flows -> CN-TC-15.x / 16.x (pointer table) | 14 |
| E6-UC-5 | primary, A1-A2, E1-E4, EC1-EC5 | NF-TC-5.1 to 5.12 | 12 |
| E6-UC-6 | primary, A1-A2, E1-E2, EC1-EC2 | NF-TC-6.1 to 6.7 | 7 |
| E6-UC-7 | primary, A1-A5, E1-E7, EC1-EC6 | NF-TC-7.1 to 7.19 | 19 |
| E6-UC-8 | primary, A1-A3, E1-E10, EC1-EC4 | NF-TC-8.1 to 8.18 | 18 |
| E6-UC-9 | primary, A1, E1-E3, EC1-EC4 | NF-TC-9.1 to 9.9 | 9 |
| E6-UC-10 | primary, A1-A2, E1-E7, EC1-EC5 | NF-TC-10.1 to 10.15 | 15 |
| E6-UC-11 | primary, A1-A3, E1-E7 (E7 Epic 6 extension only), EC1-EC6 | NF-TC-11.1 to 11.17; Epic 3 part of E7 -> CN-TC-17.10 | 17 |
| E6-UC-12 | primary, A1-A3, E1-E7, EC1-EC5 | NF-TC-12.1 to 12.16 | 16 |
| E6-UC-13 | primary, A1-A3, E1-E4, EC1-EC3 | NF-TC-13.1 to 13.11 | 11 |
| E6-UC-14 | primary, A1-A2, E1-E4, EC1-EC3 | NF-TC-14.1 to 14.10 | 10 |
| E6-UC-15 | primary, A1, E1-E4, EC1-EC6 | NF-TC-15.1 to 15.12 | 12 |
| E6-UC-16 | primary, A1-A2, E1-E5, EC1-EC4 | NF-TC-16.1 to 16.12 | 12 |
| E6-UC-17 | primary, A1, E1-E2, EC1-EC3 | NF-TC-17.1 to 17.7 | 7 |
| E6-UC-18 | primary, A1-A2, E1-E4, EC1-EC3 | NF-TC-18.1 to 18.10 | 10 |
| E6-UC-19 | primary, A1-A3, E1-E6, EC1-EC3 | NF-TC-19.1 to 19.13 | 13 |
| E6-UC-20 | primary, A1-A2, E1-E3, EC1-EC3 | NF-TC-20.1 to 20.9 | 9 |
| E6-UC-21 | primary, A1-A3, E1-E6, EC1-EC4 | NF-TC-21.1 to 21.14 | 14 |
| E6-UC-22 | primary, A1, E1-E4, EC1-EC4 | NF-TC-22.1 to 22.10 | 10 |
| E6-UC-23 | primary, A1, E1-E3, EC1-EC3 | NF-TC-23.1 to 23.8 | 8 |
| E6-UC-24 | primary, A1-A2, E1-E3, EC1-EC4 | NF-TC-24.1 to 24.10 | 10 |
| E6-UC-25 | primary, A1, E1-E3, EC1-EC3 | NF-TC-25.1 to 25.8 | 8 |
| E6-UC-26 | primary, A1-A2, E1-E4, EC1-EC3 | NF-TC-26.1 to 26.10 | 10 |
| E6-UC-27 | primary, A1-A3, E1-E5, EC1-EC3 | NF-TC-27.1 to 27.12 | 12 |
| E6-UC-28 | primary, A1-A3, E1-E6, EC1-EC3 | NF-TC-28.1 to 28.13 | 13 |
| E6-UC-29 | primary, A1-A7, E1-E6, EC1-EC5 | NF-TC-29.1a, 29.1b, 29.2 to 29.19 | 20 |
| E6-UC-30 | primary, A1-A3, E1-E8, EC1-EC5 | NF-TC-30.1 to 30.17 | 17 |
| **Total** | | | **387** |

### Coverage by test category

| Category | Test cases |
|---|---|
| Auth boundaries (per-IP, role, insider, non-validator) | NF-TC-3.12, 4.6, 4.9, 8.6, 8.14, 8.15, 10.9, 29.5 |
| Concurrency and race conditions | NF-TC-3.19, 3.17, 11.7, 11.8, 11.11, 12.11, 4.11 |
| Config fail-fast (FR-23) | NF-TC-3.11, 8.7, 9.4, 9.5, 11.5, 30.1 to 30.17 |
| Negative / static-check controls | NF-TC-2.9, 8.8 to 8.13, 10.7, 10.10, 14.5, 14.7, 15.6, 19.8, 19.10 |
| TLS and transport | NF-TC-7.1 to 7.19, 8.1 to 8.18, 9.1 to 9.9 |
| Measurement harness / protocol (P1-P5, S1, S2, R1, R2) | NF-TC-15.x to 26.x |
| Honest miss reporting | NF-TC-16.4, 17.3, 18.4, 20.4, 21.5, 22.3, 23.3, 24.4, 25.3, 26.4, 27.5 |
| Headline re-run at final commit | NF-TC-15.12, 28.1 to 28.13, 27.8, 27.12 |

### Totals

- NF-TC cases: **387** across 30 use cases.
- E6-UC scenarios with no NF-TC because they are MOVED to Epic 3: 13 rows of the pointer table (covered by CN-TC-15.x, CN-TC-16.x, CN-TC-17.10).
- Unmapped E6-UC scenarios: none.

### Documentation notes

- The use case E6-UC-15-EC5 names the CSV header columns "NFR ID, measured value, target, pass/fail, mode, achieved_rps, headline, machine, commit", while PRD FR-17 (v1.8/v1.9) names them `nfr_id`, `value`, `target`, `pass_fail`, ... These test cases follow the PRD names (NF-TC-15.11 asserts the header exactly).
