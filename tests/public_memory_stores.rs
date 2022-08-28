use std::collections::{HashMap, HashSet};
use tokio::sync::Mutex;

use async_trait::async_trait;
use blind_rsa_signatures::{KeyPair, PublicKey};
use privacypass::{public_tokens::server::*, Nonce, NonceStore, TokenKeyId};

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
pub struct IssuerMemoryKeyStore {
    keys: Mutex<HashMap<TokenKeyId, KeyPair>>,
}

#[async_trait]
impl IssuerKeyStore for IssuerMemoryKeyStore {
    async fn insert(&self, token_key_id: TokenKeyId, key_pair: KeyPair) {
        let mut keys = self.keys.lock().await;
        keys.insert(token_key_id, key_pair);
    }

    async fn get(&self, token_key_id: &TokenKeyId) -> Option<KeyPair> {
        self.keys.lock().await.get(token_key_id).cloned()
    }
}

#[derive(Default)]
pub struct OriginMemoryKeyStore {
    keys: Mutex<HashMap<TokenKeyId, PublicKey>>,
}

#[async_trait]
impl OriginKeyStore for OriginMemoryKeyStore {
    async fn insert(&self, token_key_id: TokenKeyId, public_key: PublicKey) {
        let mut keys = self.keys.lock().await;
        keys.insert(token_key_id, public_key);
    }

    async fn get(&self, token_key_id: &TokenKeyId) -> Option<PublicKey> {
        self.keys.lock().await.get(token_key_id).cloned()
    }
}
