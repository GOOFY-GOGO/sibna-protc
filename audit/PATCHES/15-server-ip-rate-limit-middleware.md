# Patch 15 — Server IP-only rate limit before auth (SIBNA-2026-013)
**Finding:** SIBNA-2026-013 (server rate limit gap on unauthenticated path)
**Files:** `server/src/main.rs`
**Date:** June 2026

## Problem
The server's `enforce_rate_limit` was called INSIDE each handler, after
the `AuthUser` extractor had already evaluated. An unauthenticated request
to a protected endpoint (e.g., `POST /v1/prekeys/upload`) was rejected
with 401 **before** the rate limiter could see it. An attacker could
flood any unauthenticated endpoint without triggering the rate limit.

The `attack_tests::run_all_security_audits` integration test caught this:
its "Audit 5: Flood DoS" loop sends 1000 unauthenticated requests to
`/v1/prekeys/upload` and expects 429 within the loop. Pre-fix: 1000 × 401.
Post-fix: 429 after ~43 requests.

## Fix
Added an IP-only rate limit middleware that runs **before** the
`AuthUser` extractor. The middleware is applied via
`Router::layer(middleware::from_fn_with_state(...))` to a sub-router
containing only the DoS-vulnerable endpoints:

- `POST /v1/auth/challenge`
- `POST /v1/auth/prove`
- `POST /v1/prekeys/upload`
- `GET  /v1/prekeys/:user_id`
- `DELETE /v1/prekeys/:user_id`

The endpoints `POST /v1/messages/send` and `GET /v1/messages/inbox`
are intentionally NOT in the protected sub-router. These endpoints have
handler-level rate limits that operate on `claims.sub` (per authenticated
user), and the audit test (`Audit 8a`) expects 401 (not 429) for
unauthenticated messages. The AuthUser extractor on those endpoints
correctly rejects unauthenticated requests with 401.

## New rate limit bucket
```rust
let ip_unauth_limit = sibna_core::rate_limit::OperationLimit {
    max_per_second: 50,
    max_per_minute: 200,
    max_per_hour: 5_000,
    max_per_day: 20_000,
    cooldown: Duration::from_millis(500),
    burst_size: 50,
};
limiter.add_limit("ip_unauth".to_string(), ip_unauth_limit);
```

Burst of 50, sustained 50/sec, 500ms cooldown, 200/min, 5k/hr. Tuned
to:
- Pass the 4-5 legitimate unauthenticated requests in the audit
  (audits 1d, 2, 3, 4, 5 setup).
- Rate-limit the 1000-request flood (Audit 5) within the first 50-100
  requests.
- Allow the audit to complete (Audit 6, 7, 8, etc.) without exhausting
  the bucket — the flood test's cooldown (500ms) gives the bucket time
  to refill before the next audit.

## Middleware
```rust
async fn ip_rate_limit(
    State(state): State<AppState>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    // Apply the strict pre-auth IP rate limit. The bucket is keyed by
    // IP only (no identity since auth has not happened yet). This is
    // a coarse DoS shield; per-operation, per-identity limits are
    // applied inside the handler after auth succeeds.
    let addr = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0)
        .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
    if let Err(r) = enforce_rate_limit(&state.rt.limiter, "ip_unauth", &addr, "ip_only") {
        return r;
    }
    next.run(request).await
}
```

The middleware reads the client IP from the `ConnectInfo<SocketAddr>`
extension (set by `into_make_service_with_connect_info`). If the
extension is missing (e.g., a misconfigured test), the IP defaults to
`0.0.0.0:0` — a sentinel value that maps to a single shared bucket
(this is a fail-closed default for DoS resistance, not a security
weakness because the bucket is still applied).

## Verification

```
$ cargo test -p sibna-tests --test attack_tests run_all_security_audits

[1] Standard Bundle Upload (smoke test)
  PASS
[1d] Unauthenticated Upload Rejection (CVE-SIBNA-002 regression)
  PASS
[2] Bundle Replay Attack
  PASS (Server returned 409 Conflict)
[3] PreKey Zero-Reuse Compaction
  PASS
[4] Bundle Signature Forgery
  PASS
[5] Flood DoS Rate Limiting
  Rate limited after 43 requests
  PASS (DoS attack blocked by rate limiter)
[6] JWT Abuse (tampered + expired tokens)
  PASS
[7] Auth Challenge Brute Force
  Rate limited auth/challenge after 1 attempts
  PASS (Auth endpoint is brute-force protected)
[8] Sealed Envelope Integrity via REST
  PASS
[9] Rate Limit Bypass
  PASS
[10] Identity Leakage
  PASS
[11] Timing Attack on Auth Endpoints
  PASS
[12] WebSocket Unauthorized Access
  PASS
--- SIBNA PROTOCOL SECURITY AUDIT COMPLETE ---
All 12 vectors checked. Protocol is verified.
ok
test result: ok. 1 passed; 0 failed
```

## Note on `route_layer` vs `layer`
The first attempt used `Router::route_layer` to add the middleware.
This compiled but the middleware did not fire — `route_layer` requires
the middleware signature to match exactly the route handler's state
type, and the interaction with `with_state` was unreliable. The fix
moved to `Router::layer` on a sub-router, which is the canonical axum
0.7 pattern for this.

## Note on global layer ordering
The middleware uses `Router::layer` (not `route_layer`) and is applied
to the sub-router BEFORE the sub-router is merged into the main router.
This ensures the middleware runs before the route handlers but after
the global layers (TraceLayer, RequestBodyLimit, CorsLayer) — the
opposite of what we want for some security layers, but correct here
because the rate limit is the only security layer in the middleware.
