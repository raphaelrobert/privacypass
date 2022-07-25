use async_trait::async_trait;
use std::collections::{HashMap, HashSet};
use tokio::sync::Mutex;
use voprf::*;

use privacypass::batched_tokens::server::*;
use privacypass::{KeyId, Nonce, NonceStore};

#[derive(Default)]
pub struct MemoryNonceStore {
    nonces: HashSet<Nonce>,
}

#[async_trait]
impl NonceStore for MemoryNonceStore {
    async fn exists(&self, nonce: &Nonce) -> bool {
        self.nonces.contains(nonce)
    }

    async fn insert(&mut self, nonce: Nonce) {
        self.nonces.insert(nonce);
    }
}

#[derive(Default)]
pub struct MemoryKeyStore {
    keys: Mutex<HashMap<KeyId, VoprfServer<Ristretto255>>>,
}

#[async_trait]
impl KeyStore for MemoryKeyStore {
    async fn insert(&mut self, key_id: KeyId, server: VoprfServer<Ristretto255>) {
        let mut keys = self.keys.lock().await;
        keys.insert(key_id, server);
    }

    async fn get(&self, key_id: &KeyId) -> Option<VoprfServer<Ristretto255>> {
        self.keys.lock().await.get(key_id).cloned()
    }
}
