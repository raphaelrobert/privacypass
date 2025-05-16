//! This module contains in-memory implementations of the `PrivateKeyStore` trait.
use async_trait::async_trait;
use std::{collections::HashMap, fmt::Debug};
use tokio::sync::Mutex;
use voprf::*;

use crate::{
    TruncatedTokenKeyId,
    common::{private::PPCipherSuite, store::PrivateKeyStore},
};

/// Private key store that stores keys in memory.
pub struct MemoryKeyStoreVoprf<CS: PPCipherSuite> {
    keys: Mutex<HashMap<TruncatedTokenKeyId, VoprfServer<CS>>>,
}

#[async_trait]
impl<C: PPCipherSuite> PrivateKeyStore for MemoryKeyStoreVoprf<C> {
    type CS = C;

    async fn insert(&self, truncated_token_key_id: TruncatedTokenKeyId, server: VoprfServer<C>) {
        let mut keys = self.keys.lock().await;
        keys.insert(truncated_token_key_id, server.clone());
    }

    async fn get(&self, truncated_token_key_id: &TruncatedTokenKeyId) -> Option<VoprfServer<C>> {
        self.keys.lock().await.get(truncated_token_key_id).cloned()
    }
}

impl<CS: PPCipherSuite> Debug for MemoryKeyStoreVoprf<CS> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryKeyStoreVoprf")
            .field("keys", &"keys".to_string())
            .finish()
    }
}

impl<CS: PPCipherSuite> Default for MemoryKeyStoreVoprf<CS> {
    fn default() -> Self {
        Self {
            keys: Mutex::new(HashMap::new()),
        }
    }
}
