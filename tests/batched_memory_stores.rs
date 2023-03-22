use async_trait::async_trait;
use std::collections::{HashMap, HashSet};
use tokio::sync::Mutex;
use voprf::*;

use privacypass::batched_tokens::server::*;
use privacypass::{Nonce, NonceStore, TokenKeyId};

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
pub struct MemoryKeyStore {
    keys: Mutex<HashMap<TokenKeyId, VoprfServer<Ristretto255>>>,
}

#[async_trait]
impl BatchedKeyStore for MemoryKeyStore {
    async fn insert(&self, token_key_id: TokenKeyId, server: VoprfServer<Ristretto255>) {
        let mut keys = self.keys.lock().await;
        keys.insert(token_key_id, server);
    }

    async fn get(&self, token_key_id: &TokenKeyId) -> Option<VoprfServer<Ristretto255>> {
        self.keys.lock().await.get(token_key_id).cloned()
    }
}
