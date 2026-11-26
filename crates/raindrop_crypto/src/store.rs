//! The encrypted local database: one SQLCipher file per server profile.
//!
//! It holds everything a device must never lose to a stolen disk or a backup of the app's data
//! folder — its private keys, the MLS group state, the identity keys it has pinned for other users —
//! and the **decrypted message cache**. That cache is not an optimisation: MLS deletes each epoch's
//! keys once it moves on (that is what forward secrecy means), so ciphertext fetched again from the
//! server later can no longer be decrypted. The plaintext kept here is the only copy.
//!
//! Beside it are **held messages**: ones MLS decrypted (spending their key) from a sender whose
//! identity key no longer matches this device's pin. They are not shown until the user accepts the
//! changed key, and then move into the cache; until then they stay here, as protected as the cache.
//!
//! A device that **left a group because a member's identity key changed** (their commit was refused,
//! or joining was) records that too, with the key it was shown, so the client can list what is waiting
//! for the user's decision after a restart and rejoin those groups once the key is accepted
//! ([`Store::pending_identity_changes`]).
//!
//! MLS state and Raindrop's own tables share the file but not the connection: OpenMLS's storage
//! provider owns one, [`Store`] another, and WAL mode lets them coexist.

use std::collections::BTreeMap;
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

    // Before the first read: another connection (or process) briefly holding the file must make
    // this wait, not fail.
    connection.busy_timeout(std::time::Duration::from_secs(5))?;

    // The key is only checked when a page is first read. A wrong key surfaces here as "file is not
    // a database" rather than somewhere later. Only that error means "locked by the key"; a busy
    // or I/O failure is reported as what it is, so it is not mistaken for a wrong key.
    connection
        .query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))
        .map_err(|e| match e.sqlite_error_code() {
            Some(rusqlite::ErrorCode::NotADatabase) => CryptoError::StoreLocked,
            _ => CryptoError::Store(format!("opening the local store: {e}")),
        })?;

    connection.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA foreign_keys = ON;
         PRAGMA secure_delete = ON;",
    )?;
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

/// A decrypted message withheld because its sender's identity key differs from the one pinned for
/// them. Released into the message cache when the user accepts that key
/// ([`Store::release_held_messages`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldMessage {
    pub message: CachedMessage,
    /// The identity key the sender's certificate carried: only accepting this key releases it.
    pub sender_identity_key: Vec<u8>,
}

/// A changed identity key waiting for the user's decision, as the client lists it: one per user and
/// presented key, built from the held messages and the groups this device left because of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingIdentityChange {
    pub user_id: String,
    /// The key this device has pinned for the user now; `None` if it has none (it cannot be, for a
    /// held message, but a pin can be removed by restoring a store).
    pub pinned_key: Option<Vec<u8>>,
    /// The key the user's certificate presented: the one to pass to accept.
    pub presented_key: Vec<u8>,
    /// How many of their messages are held under `presented_key`.
    pub held_messages: usize,
    /// The groups those held messages are in.
    pub held_group_ids: Vec<Vec<u8>>,
    /// The groups this device is out of because of this change, to join again once it is accepted.
    pub left_group_ids: Vec<Vec<u8>>,
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
             CREATE INDEX IF NOT EXISTS rd_messages_by_time ON rd_messages (group_id, sent_at);
             CREATE TABLE IF NOT EXISTS rd_held_messages (
                 group_id            BLOB NOT NULL,
                 message_id          TEXT NOT NULL,
                 sender_user_id      TEXT NOT NULL,
                 sender_device_id    TEXT NOT NULL,
                 sender_identity_key BLOB NOT NULL,
                 epoch               INTEGER NOT NULL,
                 sent_at             INTEGER NOT NULL,
                 payload             BLOB NOT NULL,
                 PRIMARY KEY (group_id, message_id)
             );
             CREATE INDEX IF NOT EXISTS rd_held_messages_by_sender
                 ON rd_held_messages (sender_user_id, sender_identity_key);
             CREATE TABLE IF NOT EXISTS rd_identity_left_groups (
                 group_id      BLOB NOT NULL,
                 user_id       TEXT NOT NULL,
                 presented_key BLOB NOT NULL,
                 recorded_at   INTEGER NOT NULL,
                 PRIMARY KEY (group_id, user_id)
             );",
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
                    pinned_key: existing.identity_key,
                    presented_key: identity_key.to_vec(),
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

    /// Removes a message's plaintext — when it was deleted, or its channel was. A held copy goes too.
    pub fn delete_message(&self, group_id: &[u8], message_id: &str) -> Result<()> {
        self.connection.execute(
            "DELETE FROM rd_messages WHERE group_id = ?1 AND message_id = ?2",
            params![group_id, message_id],
        )?;
        self.connection.execute(
            "DELETE FROM rd_held_messages WHERE group_id = ?1 AND message_id = ?2",
            params![group_id, message_id],
        )?;
        Ok(())
    }

    /// Removes every message of a group, cached or held.
    pub fn delete_group_messages(&self, group_id: &[u8]) -> Result<()> {
        self.connection
            .execute("DELETE FROM rd_messages WHERE group_id = ?1", [group_id])?;
        self.connection
            .execute("DELETE FROM rd_held_messages WHERE group_id = ?1", [group_id])?;
        self.forget_left_group(group_id)?;
        Ok(())
    }

    // ── Held messages ────────────────────────────────────────────────────────────────────────

    /// Withholds a decrypted message whose sender's identity key changed. Like
    /// [`Store::put_message`], a second copy of the same message keeps the first.
    pub fn hold_message(&self, held: &HeldMessage) -> Result<()> {
        let message = &held.message;
        self.connection.execute(
            "INSERT OR IGNORE INTO rd_held_messages
                 (group_id, message_id, sender_user_id, sender_device_id, sender_identity_key, epoch, sent_at,
                  payload)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                message.group_id,
                message.message_id,
                message.sender_user_id,
                message.sender_device_id,
                held.sender_identity_key,
                message.epoch as i64,
                message.sent_at_unix_ms,
                message.payload
            ],
        )?;
        Ok(())
    }

    /// Who sent a held message and under which identity key, if `message_id` is one.
    pub fn held_message_origin(&self, group_id: &[u8], message_id: &str) -> Result<Option<(String, Vec<u8>)>> {
        Ok(self
            .connection
            .query_row(
                "SELECT sender_user_id, sender_identity_key FROM rd_held_messages
                 WHERE group_id = ?1 AND message_id = ?2",
                params![group_id, message_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?)
    }

    /// Every message of a group still held, oldest first.
    pub fn held_messages(&self, group_id: &[u8]) -> Result<Vec<HeldMessage>> {
        let mut statement = self.connection.prepare(
            "SELECT group_id, message_id, sender_user_id, sender_device_id, epoch, sent_at, payload,
                    sender_identity_key
             FROM rd_held_messages
             WHERE group_id = ?1
             ORDER BY sent_at, message_id",
        )?;
        let rows = statement.query_map([group_id], |row| {
            Ok(HeldMessage {
                message: Self::read_message(row)?,
                sender_identity_key: row.get(7)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// Moves every message held for `user_id` under `identity_key` into the message cache, in one
    /// transaction, and returns how many. Messages held under any other key stay held.
    pub fn release_held_messages(&self, user_id: &str, identity_key: &[u8]) -> Result<usize> {
        let transaction = self.connection.unchecked_transaction()?;
        transaction.execute(
            "INSERT OR IGNORE INTO rd_messages
                 (group_id, message_id, sender_user_id, sender_device_id, epoch, sent_at, payload)
             SELECT group_id, message_id, sender_user_id, sender_device_id, epoch, sent_at, payload
             FROM rd_held_messages WHERE sender_user_id = ?1 AND sender_identity_key = ?2",
            params![user_id, identity_key],
        )?;
        let released = transaction.execute(
            "DELETE FROM rd_held_messages WHERE sender_user_id = ?1 AND sender_identity_key = ?2",
            params![user_id, identity_key],
        )?;
        transaction.commit()?;
        Ok(released)
    }

    // ── Groups left because of a changed identity ────────────────────────────────────────────

    /// Records that this device is out of `group_id` because `user_id` presented `presented_key`
    /// against a different pin. A second record for the same group and user replaces the first (the
    /// key may have changed again).
    pub fn record_left_group(&self, group_id: &[u8], user_id: &str, presented_key: &[u8], now_unix: i64) -> Result<()> {
        self.connection.execute(
            "INSERT INTO rd_identity_left_groups (group_id, user_id, presented_key, recorded_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (group_id, user_id) DO UPDATE SET presented_key = excluded.presented_key,
                                                           recorded_at = excluded.recorded_at",
            params![group_id, user_id, presented_key, now_unix],
        )?;
        Ok(())
    }

    /// Forgets every record for `group_id`: the device is in the group again, or the group is gone.
    pub fn forget_left_group(&self, group_id: &[u8]) -> Result<()> {
        self.connection
            .execute("DELETE FROM rd_identity_left_groups WHERE group_id = ?1", [group_id])?;
        Ok(())
    }

    /// Forgets the records made for `user_id` under `presented_key`, because the user accepted that
    /// key. Records under any other key stay.
    pub fn clear_left_groups(&self, user_id: &str, presented_key: &[u8]) -> Result<()> {
        self.connection.execute(
            "DELETE FROM rd_identity_left_groups WHERE user_id = ?1 AND presented_key = ?2",
            params![user_id, presented_key],
        )?;
        Ok(())
    }

    /// Every changed identity key waiting for the user's decision, ordered by user and key: the
    /// held messages grouped by sender and key, joined with the groups left because of them. All of
    /// it is read from the encrypted store, so it is the same after a restart.
    pub fn pending_identity_changes(&self) -> Result<Vec<PendingIdentityChange>> {
        let mut pending: BTreeMap<(String, Vec<u8>), PendingIdentityChange> = BTreeMap::new();
        fn entry(
            pending: &mut BTreeMap<(String, Vec<u8>), PendingIdentityChange>,
            user_id: String,
            key: Vec<u8>,
        ) -> &mut PendingIdentityChange {
            pending
                .entry((user_id.clone(), key.clone()))
                .or_insert_with(|| PendingIdentityChange {
                    user_id,
                    pinned_key: None,
                    presented_key: key,
                    held_messages: 0,
                    held_group_ids: Vec::new(),
                    left_group_ids: Vec::new(),
                })
        }

        let mut held = self.connection.prepare(
            "SELECT sender_user_id, sender_identity_key, group_id, COUNT(*)
             FROM rd_held_messages
             GROUP BY sender_user_id, sender_identity_key, group_id
             ORDER BY sender_user_id, sender_identity_key, group_id",
        )?;
        let rows = held.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?;
        for row in rows {
            let (user_id, key, group_id, count) = row?;
            let change = entry(&mut pending, user_id, key);
            change.held_messages += usize::try_from(count).unwrap_or(0);
            change.held_group_ids.push(group_id);
        }

        let mut left = self.connection.prepare(
            "SELECT user_id, presented_key, group_id FROM rd_identity_left_groups
             ORDER BY user_id, presented_key, group_id",
        )?;
        let rows = left.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })?;
        for row in rows {
            let (user_id, key, group_id) = row?;
            entry(&mut pending, user_id, key).left_group_ids.push(group_id);
        }

        let mut changes: Vec<PendingIdentityChange> = pending.into_values().collect();
        for change in &mut changes {
            change.pinned_key = self.pinned_identity(&change.user_id)?.map(|pin| pin.identity_key);
        }
        Ok(changes)
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
    fn left_groups_are_recorded_per_key_and_cleared_by_that_key_or_the_group() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("s.db"), &key(5)).unwrap();
        store.pin_identity("bob", b"old", 1).unwrap();

        store.record_left_group(b"g1", "bob", b"new-1", 10).unwrap();
        store.record_left_group(b"g2", "bob", b"new-1", 11).unwrap();
        // Bob changed again before the first was accepted: the record is replaced, not duplicated.
        store.record_left_group(b"g2", "bob", b"new-2", 12).unwrap();

        let pending = store.pending_identity_changes().unwrap();
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0].presented_key, b"new-1");
        assert_eq!(pending[0].left_group_ids, vec![b"g1".to_vec()]);
        assert_eq!(pending[1].presented_key, b"new-2");
        assert_eq!(pending[1].left_group_ids, vec![b"g2".to_vec()]);
        assert_eq!(pending[0].pinned_key.as_deref(), Some(&b"old"[..]));
        assert_eq!(pending[0].held_messages, 0);

        store.clear_left_groups("bob", b"new-1").unwrap();
        assert_eq!(store.pending_identity_changes().unwrap().len(), 1);
        store.delete_group_messages(b"g2").unwrap();
        assert!(store.pending_identity_changes().unwrap().is_empty());
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
