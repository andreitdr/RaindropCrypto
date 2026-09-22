//! The encrypted local database: one SQLCipher file per server profile.
//!
//! It holds everything a device must never lose to a stolen disk or a backup of the app's data
//! folder — its private keys, the MLS group state, the identity keys it has pinned for other users —
//! and the **decrypted message cache**. That cache is not an optimisation: MLS deletes each epoch's
//! keys once it moves on (that is what forward secrecy means), so ciphertext fetched again from the
//! server later can no longer be decrypted. The plaintext kept here is the only copy.
//!
//! MLS state and Raindrop's own tables share the file but not the connection: OpenMLS's storage
//! provider owns one, [`Store`] another, and WAL mode lets them coexist.

use std::path::Path;

use rusqlite::{Connection, OptionalExtension, params};
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};

/// The 32-byte key a store is encrypted with. The client keeps it in the platform keystore
/// (`flutter_secure_storage`), never beside the file.
pub type StoreKey = Zeroizing<[u8; 32]>;

/// Opens (creating if needed) the SQLCipher database at `path` and proves `key` unlocks it.
pub(crate) fn open_connection(path: &Path, key: &[u8; 32]) -> Result<Connection> {
    let connection = Connection::open(path)?;

    // A raw key, not a passphrase: SQLCipher then skips its own PBKDF2, which would only slow down
    // every open for a key that is already random.
    let hex = Zeroizing::new(hex_lower(key));
    connection.execute_batch(&format!("PRAGMA key = \"x'{}'\";", hex.as_str()))?;

    // The key is only checked when a page is first read. A wrong key surfaces here as "file is not
    // a database" rather than somewhere later.
    connection
        .query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))
        .map_err(|_| CryptoError::StoreLocked)?;

    connection.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA foreign_keys = ON;
         PRAGMA secure_delete = ON;",
    )?;
    connection.busy_timeout(std::time::Duration::from_secs(5))?;
    Ok(connection)
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A user's identity key as this device has pinned it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedIdentity {
    pub user_id: String,
    pub identity_key: Vec<u8>,
    /// Whether the user compared safety numbers and confirmed this key, rather than it being
    /// trusted on first sight.
    pub verified: bool,
    pub first_seen_unix: i64,
}

/// One decrypted message, as the chat UI renders it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedMessage {
    /// The MLS group (one per channel).
    pub group_id: Vec<u8>,
    /// The server's id for the message.
    pub message_id: String,
    pub sender_user_id: String,
    pub sender_device_id: String,
    pub epoch: u64,
    pub sent_at_unix_ms: i64,
    /// The inner payload, still in its wire encoding — the client decodes it.
    pub payload: Vec<u8>,
}

/// Raindrop's own tables in the encrypted database.
pub struct Store {
    connection: Connection,
}

impl Store {
    /// Opens the store at `path`, creating it on first use.
    pub fn open(path: &Path, key: &[u8; 32]) -> Result<Self> {
        let connection = open_connection(path, key)?;
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS rd_meta (
                 key   TEXT PRIMARY KEY,
                 value BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS rd_peer_identities (
                 user_id      TEXT PRIMARY KEY,
                 identity_key BLOB NOT NULL,
                 verified     INTEGER NOT NULL DEFAULT 0,
                 first_seen   INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS rd_messages (
                 group_id         BLOB NOT NULL,
                 message_id       TEXT NOT NULL,
                 sender_user_id   TEXT NOT NULL,
                 sender_device_id TEXT NOT NULL,
                 epoch            INTEGER NOT NULL,
                 sent_at          INTEGER NOT NULL,
                 payload          BLOB NOT NULL,
                 PRIMARY KEY (group_id, message_id)
             );
             CREATE INDEX IF NOT EXISTS rd_messages_by_time ON rd_messages (group_id, sent_at);",
        )?;
        Ok(Self { connection })
    }

    // ── Key/value: this device's own secrets and settings ────────────────────────────────────

    pub fn get_meta(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        Ok(self
            .connection
            .query_row("SELECT value FROM rd_meta WHERE key = ?1", [key], |row| {
                row.get::<_, Vec<u8>>(0)
            })
            .optional()?
            .map(Zeroizing::new))
    }

    pub fn put_meta(&self, key: &str, value: &[u8]) -> Result<()> {
        self.connection.execute(
            "INSERT INTO rd_meta (key, value) VALUES (?1, ?2)
             ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn delete_meta(&self, key: &str) -> Result<()> {
        self.connection.execute("DELETE FROM rd_meta WHERE key = ?1", [key])?;
        Ok(())
    }

    // ── Other users' identity keys ───────────────────────────────────────────────────────────

    pub fn pinned_identity(&self, user_id: &str) -> Result<Option<PinnedIdentity>> {
        Ok(self
            .connection
            .query_row(
                "SELECT user_id, identity_key, verified, first_seen FROM rd_peer_identities WHERE user_id = ?1",
                [user_id],
                |row| {
                    Ok(PinnedIdentity {
                        user_id: row.get(0)?,
                        identity_key: row.get(1)?,
                        verified: row.get::<_, i64>(2)? != 0,
                        first_seen_unix: row.get(3)?,
                    })
                },
            )
            .optional()?)
    }

    pub fn pinned_identities(&self) -> Result<Vec<PinnedIdentity>> {
        let mut statement = self
            .connection
            .prepare("SELECT user_id, identity_key, verified, first_seen FROM rd_peer_identities ORDER BY user_id")?;
        let rows = statement.query_map([], |row| {
            Ok(PinnedIdentity {
                user_id: row.get(0)?,
                identity_key: row.get(1)?,
                verified: row.get::<_, i64>(2)? != 0,
                first_seen_unix: row.get(3)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// Pins `identity_key` for `user_id` the first time the user is seen (trust on first use).
    ///
    /// Returns the pin now in force. A *different* key for a user already pinned is refused with
    /// [`CryptoError::IdentityChanged`] and changes nothing — replacing it is
    /// [`Store::replace_identity`], which only a user's explicit decision may call.
    pub fn pin_identity(&self, user_id: &str, identity_key: &[u8], now_unix: i64) -> Result<PinnedIdentity> {
        if let Some(existing) = self.pinned_identity(user_id)? {
            if existing.identity_key != identity_key {
                return Err(CryptoError::IdentityChanged {
                    user_id: user_id.to_owned(),
                });
            }
            return Ok(existing);
        }

        self.connection.execute(
            "INSERT INTO rd_peer_identities (user_id, identity_key, verified, first_seen) VALUES (?1, ?2, 0, ?3)",
            params![user_id, identity_key, now_unix],
        )?;
        Ok(PinnedIdentity {
            user_id: user_id.to_owned(),
            identity_key: identity_key.to_vec(),
            verified: false,
            first_seen_unix: now_unix,
        })
    }

    /// Accepts a changed identity key for `user_id`. Resets verification: the new key has not been
    /// compared with anyone yet.
    pub fn replace_identity(&self, user_id: &str, identity_key: &[u8], now_unix: i64) -> Result<()> {
        self.connection.execute(
            "INSERT INTO rd_peer_identities (user_id, identity_key, verified, first_seen) VALUES (?1, ?2, 0, ?3)
             ON CONFLICT (user_id) DO UPDATE SET identity_key = excluded.identity_key, verified = 0,
                                                 first_seen = excluded.first_seen",
            params![user_id, identity_key, now_unix],
        )?;
        Ok(())
    }

    /// Records that the user compared safety numbers for `user_id` and they matched.
    pub fn mark_verified(&self, user_id: &str, identity_key: &[u8]) -> Result<()> {
        let changed = self.connection.execute(
            "UPDATE rd_peer_identities SET verified = 1 WHERE user_id = ?1 AND identity_key = ?2",
            params![user_id, identity_key],
        )?;
        if changed == 0 {
            return Err(CryptoError::NotFound(format!("pinned identity for {user_id}")));
        }
        Ok(())
    }

    // ── Decrypted messages ───────────────────────────────────────────────────────────────────

    /// Stores a decrypted message. Storing the same message twice keeps the first copy: a message
    /// can only be decrypted once, so a second arrival is an echo.
    pub fn put_message(&self, message: &CachedMessage) -> Result<()> {
        self.connection.execute(
            "INSERT OR IGNORE INTO rd_messages
                 (group_id, message_id, sender_user_id, sender_device_id, epoch, sent_at, payload)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                message.group_id,
                message.message_id,
                message.sender_user_id,
                message.sender_device_id,
                message.epoch as i64,
                message.sent_at_unix_ms,
                message.payload
            ],
        )?;
        Ok(())
    }

    pub fn message(&self, group_id: &[u8], message_id: &str) -> Result<Option<CachedMessage>> {
        Ok(self
            .connection
            .query_row(
                "SELECT group_id, message_id, sender_user_id, sender_device_id, epoch, sent_at, payload
                 FROM rd_messages WHERE group_id = ?1 AND message_id = ?2",
                params![group_id, message_id],
                Self::read_message,
            )
            .optional()?)
    }

    /// The newest `limit` messages of a group sent before `before_unix_ms` (or the newest overall),
    /// newest first.
    pub fn messages(&self, group_id: &[u8], before_unix_ms: Option<i64>, limit: u32) -> Result<Vec<CachedMessage>> {
        let mut statement = self.connection.prepare(
            "SELECT group_id, message_id, sender_user_id, sender_device_id, epoch, sent_at, payload
             FROM rd_messages
             WHERE group_id = ?1 AND sent_at < ?2
             ORDER BY sent_at DESC, message_id DESC
             LIMIT ?3",
        )?;
        let rows = statement.query_map(
            params![group_id, before_unix_ms.unwrap_or(i64::MAX), limit],
            Self::read_message,
        )?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// Removes a message's plaintext — when it was deleted, or its channel was.
    pub fn delete_message(&self, group_id: &[u8], message_id: &str) -> Result<()> {
        self.connection.execute(
            "DELETE FROM rd_messages WHERE group_id = ?1 AND message_id = ?2",
            params![group_id, message_id],
        )?;
        Ok(())
    }

    pub fn delete_group_messages(&self, group_id: &[u8]) -> Result<()> {
        self.connection
            .execute("DELETE FROM rd_messages WHERE group_id = ?1", [group_id])?;
        Ok(())
    }

    fn read_message(row: &rusqlite::Row<'_>) -> rusqlite::Result<CachedMessage> {
        Ok(CachedMessage {
            group_id: row.get(0)?,
            message_id: row.get(1)?,
            sender_user_id: row.get(2)?,
            sender_device_id: row.get(3)?,
            epoch: row.get::<_, i64>(4)? as u64,
            sent_at_unix_ms: row.get(5)?,
            payload: row.get(6)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn a_wrong_key_does_not_open_the_store() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.db");
        Store::open(&path, &key(1)).unwrap().put_meta("x", b"secret").unwrap();

        assert!(matches!(Store::open(&path, &key(2)), Err(CryptoError::StoreLocked)));
        assert_eq!(
            Store::open(&path, &key(1))
                .unwrap()
                .get_meta("x")
                .unwrap()
                .unwrap()
                .as_slice(),
            b"secret"
        );
    }

    #[test]
    fn the_file_on_disk_is_not_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.db");
        let store = Store::open(&path, &key(7)).unwrap();
        store.put_meta("marker", b"PLAINTEXT-MARKER-1234567890").unwrap();
        drop(store);

        let mut raw = std::fs::read(&path).unwrap();
        if let Ok(wal) = std::fs::read(dir.path().join("s.db-wal")) {
            raw.extend(wal);
        }
        assert!(!raw.windows(6).any(|w| w == b"SQLite"), "file header must be encrypted");
        assert!(!raw.windows(16).any(|w| w == b"PLAINTEXT-MARKER"));
    }

    #[test]
    fn identity_pins_refuse_a_changed_key() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("s.db"), &key(3)).unwrap();

        store.pin_identity("alice", b"key-1", 100).unwrap();
        store.pin_identity("alice", b"key-1", 200).unwrap();
        assert!(matches!(
            store.pin_identity("alice", b"key-2", 300),
            Err(CryptoError::IdentityChanged { .. })
        ));

        store.mark_verified("alice", b"key-1").unwrap();
        assert!(store.pinned_identity("alice").unwrap().unwrap().verified);

        store.replace_identity("alice", b"key-2", 400).unwrap();
        let pinned = store.pinned_identity("alice").unwrap().unwrap();
        assert_eq!(pinned.identity_key, b"key-2");
        assert!(!pinned.verified);
    }

    #[test]
    fn messages_page_newest_first() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("s.db"), &key(4)).unwrap();
        for i in 0..5 {
            store
                .put_message(&CachedMessage {
                    group_id: b"g".to_vec(),
                    message_id: format!("m{i}"),
                    sender_user_id: "u".into(),
                    sender_device_id: "d".into(),
                    epoch: 1,
                    sent_at_unix_ms: i,
                    payload: vec![i as u8],
                })
                .unwrap();
        }

        let page = store.messages(b"g", None, 2).unwrap();
        assert_eq!(
            page.iter().map(|m| m.message_id.as_str()).collect::<Vec<_>>(),
            ["m4", "m3"]
        );
        let older = store.messages(b"g", Some(3), 10).unwrap();
        assert_eq!(older.len(), 3);
    }
}
