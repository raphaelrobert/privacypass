use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use tokio::sync::Mutex;

use async_trait::async_trait;
use blind_rsa_signatures::KeyPair;
use privacypass::{
    public_tokens::{client::*, server::*},
    KeyId, Nonce, NonceStore, TokenType,
};

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
    keys: Mutex<HashMap<KeyId, KeyPair>>,
}

#[async_trait]
impl KeyStore for MemoryKeyStore {
    async fn insert(&mut self, key_id: KeyId, key_pair: KeyPair) {
        let mut keys = self.keys.lock().await;
        keys.insert(key_id, key_pair);
    }

    async fn get(&self, key_id: &KeyId) -> Option<KeyPair> {
        self.keys.lock().await.get(key_id).cloned()
    }
}
