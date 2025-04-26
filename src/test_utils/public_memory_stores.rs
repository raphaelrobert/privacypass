//! This module contains in-memory implementations of the `NonceStore`, `IssuerKeyStore`, and
//! `OriginKeyStore` traits.
use crate::{public_tokens::server::*, Nonce, NonceStore, TruncatedTokenKeyId};
use async_trait::async_trait;
use blind_rsa_signatures::{KeyPair, PublicKey};
use std::collections::{HashMap, HashSet};
use tokio::sync::Mutex;

/// Private key store that stores nonces in memory.
#[derive(Default, Debug)]
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

/// Private key store that stores keys in memory.
#[derive(Default, Debug)]
pub struct IssuerMemoryKeyStore {
    keys: Mutex<HashMap<TruncatedTokenKeyId, KeyPair>>,
}

#[async_trait]
impl IssuerKeyStore for IssuerMemoryKeyStore {
    async fn insert(&self, truncated_token_key_id: TruncatedTokenKeyId, key_pair: KeyPair) {
        let mut keys = self.keys.lock().await;
        keys.insert(truncated_token_key_id, key_pair);
    }

    async fn get(&self, truncated_token_key_id: &TruncatedTokenKeyId) -> Option<KeyPair> {
        self.keys.lock().await.get(truncated_token_key_id).cloned()
    }
}

/// Public key store that stores keys in memory.
#[derive(Default, Debug)]
pub struct OriginMemoryKeyStore {
    keys: Mutex<HashMap<TruncatedTokenKeyId, PublicKey>>,
}

#[async_trait]
impl OriginKeyStore for OriginMemoryKeyStore {
    async fn insert(&self, truncated_token_key_id: TruncatedTokenKeyId, public_key: PublicKey) {
        let mut keys = self.keys.lock().await;
        keys.insert(truncated_token_key_id, public_key);
    }

    async fn get(&self, truncated_token_key_id: &TruncatedTokenKeyId) -> Option<PublicKey> {
        self.keys.lock().await.get(truncated_token_key_id).cloned()
    }
}
