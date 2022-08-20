use std::collections::{HashMap, HashSet};
use tokio::sync::Mutex;

use async_trait::async_trait;
use blind_rsa_signatures::KeyPair;
use privacypass::{public_tokens::server::*, KeyId, Nonce, NonceStore};

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
    keys: Mutex<HashMap<KeyId, KeyPair>>,
}

#[async_trait]
impl KeyStore for MemoryKeyStore {
    async fn insert(&self, key_id: KeyId, key_pair: KeyPair) {
        let mut keys = self.keys.lock().await;
        keys.insert(key_id, key_pair);
    }

    async fn get(&self, key_id: &KeyId) -> Option<KeyPair> {
        self.keys.lock().await.get(key_id).cloned()
    }
}
