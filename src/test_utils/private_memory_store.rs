//! This module contains in-memory implementations of the `PrivateKeyStore` trait.
use async_trait::async_trait;
use std::{
    collections::{HashMap, hash_map::Entry},
    fmt::Debug,
};
use tokio::sync::Mutex;
use voprf::*;

use crate::{
    TruncatedTokenKeyId,
    common::{private::PrivateCipherSuite, store::PrivateKeyStore},
};

/// Private key store that stores keys in memory.
pub struct MemoryKeyStoreVoprf<CS: PrivateCipherSuite> {
    keys: Mutex<HashMap<TruncatedTokenKeyId, VoprfServer<CS>>>,
}

#[async_trait]
impl<C: PrivateCipherSuite> PrivateKeyStore for MemoryKeyStoreVoprf<C> {
    type CS = C;

    async fn insert(
        &self,
        truncated_token_key_id: TruncatedTokenKeyId,
        server: VoprfServer<C>,
    ) -> bool {
        let mut keys = self.keys.lock().await;
        if let Entry::Vacant(e) = keys.entry(truncated_token_key_id) {
            e.insert(server);
            true
        } else {
            false
        }
    }

    async fn get(&self, truncated_token_key_id: &TruncatedTokenKeyId) -> Option<VoprfServer<C>> {
        self.keys.lock().await.get(truncated_token_key_id).cloned()
    }
}

impl<CS: PrivateCipherSuite> Debug for MemoryKeyStoreVoprf<CS> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryKeyStoreVoprf")
            .field("keys", &"keys".to_string())
            .finish()
    }
}

impl<CS: PrivateCipherSuite> Default for MemoryKeyStoreVoprf<CS> {
    fn default() -> Self {
        Self {
            keys: Mutex::new(HashMap::new()),
        }
    }
}
