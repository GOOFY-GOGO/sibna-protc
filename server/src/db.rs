//! redb Database Layer — replaces unmaintained sled 0.34
//!
//! Provides `RedbTree` (insert / get / remove / scan_prefix / iter) and
//! `DbState` with the four named tables the server uses.
//! Each mutation opens its own write-transaction and commits immediately,
//! so no external flush is required on shutdown.

use redb::{Database, TableDefinition};
use std::path::Path;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Table definitions — all keys and values are raw byte slices
// ---------------------------------------------------------------------------

const T_PREKEYS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("prekeys");
const T_DEDUP: TableDefinition<&[u8], &[u8]> = TableDefinition::new("dedup");
const T_QUEUE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("queue");
const T_CHALLENGES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("challenges");

#[derive(Clone, Copy, Debug)]
pub(crate) enum TableKind {
    Prekeys,
    Dedup,
    Queue,
    Challenges,
}

// ---------------------------------------------------------------------------
// RedbTree — drop-in replacement for sled::Tree
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct RedbTree {
    db: Arc<Database>,
    kind: TableKind,
}

impl RedbTree {
    fn table_def(&self) -> TableDefinition<'static, &'static [u8], &'static [u8]> {
        match self.kind {
            TableKind::Prekeys => T_PREKEYS,
            TableKind::Dedup => T_DEDUP,
            TableKind::Queue => T_QUEUE,
            TableKind::Challenges => T_CHALLENGES,
        }
    }

    /// Insert or overwrite a key-value pair.
    /// Opens a short-lived write transaction and commits immediately.
    pub fn insert(
        &self,
        key: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(self.table_def())?;
            table.insert(key.as_ref(), value.as_ref())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Look up a key.  Returns `Ok(None)` when the key or table is absent.
    pub fn get(
        &self,
        key: impl AsRef<[u8]>,
    ) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
        let read_txn = self.db.begin_read()?;
        let table = match read_txn.open_table(self.table_def()) {
            Ok(t) => t,
            Err(_) => return Ok(None),
        };
        match table.get(key.as_ref())? {
            Some(guard) => Ok(Some(guard.value().to_vec())),
            None => Ok(None),
        }
    }

    /// Remove a key.  Returns the old value if it existed.
    pub fn remove(
        &self,
        key: impl AsRef<[u8]>,
    ) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
        let write_txn = self.db.begin_write()?;
        let result;
        {
            let mut table = write_txn.open_table(self.table_def())?;
            let removed = table.remove(key.as_ref())?;
            result = match removed {
                Some(guard) => Ok(Some(guard.value().to_vec())),
                None => Ok(None),
            };
        }
        write_txn.commit()?;
        result
    }

    /// Iterate over all entries whose key starts with `prefix`.
    /// Returns owned data so callers do not need to fight redb lifetimes.
    pub fn scan_prefix(&self, prefix: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
        let read_txn = match self.db.begin_read() {
            Ok(txn) => txn,
            Err(_) => return Vec::new(),
        };
        let table = match read_txn.open_table(self.table_def()) {
            Ok(t) => t,
            Err(_) => return Vec::new(),
        };
        let iter = match table.range::<&[u8]>(prefix..) {
            Ok(i) => i,
            Err(_) => return Vec::new(),
        };
        iter.map(|r| r.map(|(k, v)| (k.value().to_vec(), v.value().to_vec())))
            .take_while(|r| {
                r.as_ref()
                    .map(|(k, _)| k.starts_with(prefix))
                    .unwrap_or(false)
            })
            .filter_map(|r| r.ok())
            .collect()
    }

    /// Iterate over every entry in the table.
    pub fn iter(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        let read_txn = match self.db.begin_read() {
            Ok(txn) => txn,
            Err(_) => return Vec::new(),
        };
        let table = match read_txn.open_table(self.table_def()) {
            Ok(t) => t,
            Err(_) => return Vec::new(),
        };
        let iter = match table.range::<&[u8]>(..) {
            Ok(i) => i,
            Err(_) => return Vec::new(),
        };
        iter.filter_map(|r| {
            r.ok()
                .map(|(k, v)| (k.value().to_vec(), v.value().to_vec()))
        })
        .collect()
    }
}

// ---------------------------------------------------------------------------
// DbState — owned set of tables; mirrors the old sled-backed struct
// ---------------------------------------------------------------------------

pub struct DbState {
    #[allow(dead_code)]
    pub db: Arc<Database>,
    pub tree_prekeys: RedbTree,
    pub tree_dedup: RedbTree,
    pub tree_queue: RedbTree,
    pub tree_challenges: RedbTree,
}

/// Open (or create) the redb database at `path` and ensure all four tables
/// exist.
pub(crate) fn open_db(
    path: impl AsRef<Path>,
) -> Result<DbState, Box<dyn std::error::Error + Send + Sync>> {
    let db = Arc::new(Database::create(path)?);

    // Ensure tables exist — open_table on a WriteTransaction creates them.
    {
        let write_txn = db.begin_write()?;
        write_txn.open_table(T_PREKEYS).ok();
        write_txn.open_table(T_DEDUP).ok();
        write_txn.open_table(T_QUEUE).ok();
        write_txn.open_table(T_CHALLENGES).ok();
        write_txn.commit()?;
    }

    let make = |kind: TableKind| RedbTree {
        db: db.clone(),
        kind,
    };

    Ok(DbState {
        db: db.clone(),
        tree_prekeys: make(TableKind::Prekeys),
        tree_dedup: make(TableKind::Dedup),
        tree_queue: make(TableKind::Queue),
        tree_challenges: make(TableKind::Challenges),
    })
}
