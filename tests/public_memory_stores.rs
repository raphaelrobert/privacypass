use std::collections::{HashMap, HashSet};
use tokio::sync::Mutex;

use async_trait::async_trait;
use blind_rsa_signatures::{KeyPair, PublicKey};
use privacypass::{public_tokens::server::*, KeyId, Nonce, NonceStore};

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
pub struct IssuerMemoryKeyStore {
    keys: Mutex<HashMap<KeyId, KeyPair>>,
}

#[async_trait]
impl IssuerKeyStore for IssuerMemoryKeyStore {
    async fn insert(&mut self, key_id: KeyId, key_pair: KeyPair) {
        let mut keys = self.keys.lock().await;
        keys.insert(key_id, key_pair);
    }

    async fn get(&self, key_id: &KeyId) -> Option<KeyPair> {
        self.keys.lock().await.get(key_id).cloned()
    }
}

#[derive(Default)]
pub struct OriginMemoryKeyStore {
    keys: Mutex<HashMap<KeyId, PublicKey>>,
}

#[async_trait]
impl OriginKeyStore for OriginMemoryKeyStore {
    async fn insert(&mut self, key_id: KeyId, public_key: PublicKey) {
        let mut keys = self.keys.lock().await;
        keys.insert(key_id, public_key);
    }

    async fn get(&self, key_id: &KeyId) -> Option<PublicKey> {
        self.keys.lock().await.get(key_id).cloned()
    }
}
