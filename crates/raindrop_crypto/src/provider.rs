//! The OpenMLS provider: RustCrypto for the primitives, and MLS state kept in the same encrypted
//! SQLCipher file as everything else (see [`crate::store`]).

use std::path::Path;

use openmls_rust_crypto::RustCrypto;
use openmls_sqlite_storage::{Codec, Connection, SqliteStorageProvider};
use openmls_traits::OpenMlsProvider;

use crate::error::{CryptoError, Result};
use crate::store::open_connection;

/// Serialises OpenMLS's stored values as JSON.
#[derive(Default)]
pub struct JsonCodec;

impl Codec for JsonCodec {
    type Error = serde_json::Error;

    fn to_vec<T: serde::Serialize>(value: &T) -> std::result::Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(value)
    }

    fn from_slice<T: serde::de::DeserializeOwned>(slice: &[u8]) -> std::result::Result<T, Self::Error> {
        serde_json::from_slice(slice)
    }
}

pub struct RaindropProvider {
    crypto: RustCrypto,
    storage: SqliteStorageProvider<JsonCodec, Connection>,
}

impl RaindropProvider {
    pub(crate) fn open(path: &Path, key: &[u8; 32]) -> Result<Self> {
        let mut storage = SqliteStorageProvider::new(open_connection(path, key)?);
        storage
            .run_migrations()
            .map_err(|e| CryptoError::Store(format!("mls storage migrations: {e}")))?;
        Ok(Self {
            crypto: RustCrypto::default(),
            storage,
        })
    }
}

impl OpenMlsProvider for RaindropProvider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = SqliteStorageProvider<JsonCodec, Connection>;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}
