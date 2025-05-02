use async_trait::async_trait;
use std::collections::{HashMap, HashSet};
use tokio::sync::Mutex;
use voprf::*;

use privacypass::{Nonce, NonceStore, PPCipherSuite, TruncatedTokenKeyId};

#[derive(Default)]
pub struct MemoryNonceStore {
    nonces: Mutex<HashSet<Nonce>>,
}

#[async_trait]
impl NonceStore for MemoryNonceStore {
    async fn exists(&self, nonce: &Nonce) -> bool {
        let nonces = self.nonces.lock().await;
        nonces.contains(nonce)
    }

    async fn insert(&self, nonce: Nonce) {
        let mut nonces = self.nonces.lock().await;
        nonces.insert(nonce);
    }
}

#[derive(Default)]
pub struct MemoryKeyStoreVoprf<CS: PPCipherSuite> {
    keys: Mutex<HashMap<TruncatedTokenKeyId, VoprfServer<CS>>>,
}

#[async_trait]
impl<C: PPCipherSuite> privacypass::common::store::PrivateKeyStore for MemoryKeyStoreVoprf<C> {
    type CS = C;

    async fn insert(&self, truncated_token_key_id: TruncatedTokenKeyId, server: VoprfServer<C>) {
        let mut keys = self.keys.lock().await;
        keys.insert(truncated_token_key_id, server.clone());
    }

    async fn get(&self, truncated_token_key_id: &TruncatedTokenKeyId) -> Option<VoprfServer<C>> {
        self.keys.lock().await.get(truncated_token_key_id).cloned()
    }
}
