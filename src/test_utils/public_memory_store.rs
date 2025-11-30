//! This module contains in-memory implementations of the `IssuerKeyStore`, and
//! `OriginKeyStore` traits.
use crate::{TruncatedTokenKeyId, public_tokens::server::*};
use async_trait::async_trait;
use blind_rsa_signatures::{KeyPair, PublicKey};
use std::collections::{HashMap, hash_map::Entry};
use tokio::sync::Mutex;

/// Public key store that stores keys in memory.
#[derive(Default, Debug)]
pub struct IssuerMemoryKeyStore {
    keys: Mutex<HashMap<TruncatedTokenKeyId, KeyPair>>,
}

#[async_trait]
impl IssuerKeyStore for IssuerMemoryKeyStore {
    async fn insert(&self, truncated_token_key_id: TruncatedTokenKeyId, key_pair: KeyPair) -> bool {
        let mut keys = self.keys.lock().await;
        if let Entry::Vacant(e) = keys.entry(truncated_token_key_id) {
            e.insert(key_pair);
            true
        } else {
            false
        }
    }

    async fn get(&self, truncated_token_key_id: &TruncatedTokenKeyId) -> Option<KeyPair> {
        self.keys.lock().await.get(truncated_token_key_id).cloned()
    }
}

/// Public key store that stores keys in memory.
#[derive(Default, Debug)]
pub struct OriginMemoryKeyStore {
    keys: Mutex<HashMap<TruncatedTokenKeyId, Vec<PublicKey>>>,
}

#[async_trait]
impl OriginKeyStore for OriginMemoryKeyStore {
    async fn insert(&self, truncated_token_key_id: TruncatedTokenKeyId, public_key: PublicKey) {
        let mut keys = self.keys.lock().await;
        keys.entry(truncated_token_key_id)
            .or_default()
            .push(public_key);
    }

    async fn get(&self, truncated_token_key_id: &TruncatedTokenKeyId) -> Vec<PublicKey> {
        self.keys
            .lock()
            .await
            .get(truncated_token_key_id)
            .cloned()
            .unwrap_or_default()
    }
}
