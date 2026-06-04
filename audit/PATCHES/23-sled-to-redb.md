# PATCH 23 — Replace unmaintained sled with redb

**Finding:** SIBNA-2026-033  
**Severity:** MEDIUM (dependency)  
**Date:** 2026-06-03

## Problem

The server uses `sled 0.34.7` as its embedded database. Sled has been
unmaintained since 2021 (last release: 0.34.7). An unmaintained
database dependency is a supply-chain liability: security fixes and
Rust-version compatibility patches will never arrive.

Additionally, sled's sync-only API was called directly from async
handlers, blocking the tokio runtime thread on every database
operation. This is a pre-existing performance issue that remains
unaddressed by this patch (redb is also sync-only).

## Solution

Replace `sled = "0.34"` with `redb = "2.6.3"` in `server/Cargo.toml`.

### New module: `server/src/db.rs`

A thin wrapper (`RedbTree`) that mirrors sled's `Tree` API:

| sled method | redb wrapper | Notes |
|---|---|---|
| `tree.insert(key, value)` | `RedbTree::insert(key, value)` | Opens a write-transaction, commits immediately |
| `tree.get(key)` | `RedbTree::get(key)` | Returns `Result<Option<Vec<u8>>>` |
| `tree.remove(key)` | `RedbTree::remove(key)` | Returns old value |
| `tree.scan_prefix(prefix)` | `RedbTree::scan_prefix(prefix)` | Returns `Vec<(Vec<u8>, Vec<u8>)>` (collected) |
| `tree.iter()` | `RedbTree::iter()` | Returns `Vec<(Vec<u8>, Vec<u8>)>` (collected) |
| `db.flush_async()` | N/A | redb commits on every transaction; no flush needed |

### Changes to existing code

**`server/Cargo.toml`:** `sled = "0.34"` → `redb = "2"`.

**`server/src/main.rs`:**
- Added `mod db;` and `use db::DbState;`
- Removed `DbState` struct (now in `db.rs`)
- Replaced `sled::open()` with `db::open_db()`
- Replaced `db.open_tree()` with the pre-built `DbState` from `open_db()`
- Removed `sled.flush_async()` from graceful shutdown (unnecessary with redb)
- Fixed `scan_prefix`/`iter` iteration: removed `if let Ok((key, value))` wrappers
  (new iterator yields owned tuples, not `Result`s)
- Updated stale comments referencing "sled"

**`server/src/ws.rs`:** Same iteration-pattern fix in `deliver_queued_messages`.

**`server/src/auth.rs`:** Added type annotation for `get()` result.

### Test results

| Suite | Count | Status |
|---|---|---|
| Core lib (`cargo test --lib -p sibna-core`) | 145/145 | ✅ |
| Attack (`cargo test --test attack_tests`) | 1/1 | ✅ |
| Multi-device | 3/3 | ✅ |
| Integration (excl. mDNS) | 29/29 | ✅ |
| `cargo check --workspace` | — | ✅ (warnings only) |

### Known limitations

1. redb is also sync-only; database calls still block the tokio thread.
   A future refactor should wrap all DB operations in
   `tokio::task::spawn_blocking`.
2. `scan_prefix` and `iter` collect into `Vec` eagerly. For very large
   datasets this could use more memory than sled's streaming iterator.
   The current data volumes (prekeys, message queues) are small enough
   that this is not a concern.

### Catalog update

`FINDING_CATALOG.md` entry SIBNA-2026-033 updated from ❌ to
**✅ (PATCH 23)**. Summary table updated.
