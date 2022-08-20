use async_trait::async_trait;
use p256::NistP256;
use std::collections::{HashMap, HashSet};
use tokio::sync::Mutex;
use voprf::*;

use privacypass::private_tokens::server::*;
use privacypass::{KeyId, Nonce, NonceStore};

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
    keys: Mutex<HashMap<KeyId, VoprfServer<NistP256>>>,
}

#[async_trait]
impl KeyStore for MemoryKeyStore {
    async fn insert(&self, key_id: KeyId, server: VoprfServer<NistP256>) {
        let mut keys = self.keys.lock().await;
        keys.insert(key_id, server);
    }

    async fn get(&self, key_id: &KeyId) -> Option<VoprfServer<NistP256>> {
        self.keys.lock().await.get(key_id).cloned()
    }
}
