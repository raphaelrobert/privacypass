use async_trait::async_trait;
use p384::NistP384;
use std::collections::{HashMap, HashSet};
use tokio::sync::Mutex;
use voprf::*;

use privacypass::private_tokens::server::*;
use privacypass::{Nonce, NonceStore, TruncatedTokenKeyId};

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
    keys: Mutex<HashMap<TruncatedTokenKeyId, VoprfServer<NistP384>>>,
}

#[async_trait]
impl PrivateKeyStore for MemoryKeyStore {
    async fn insert(
        &self,
        truncated_token_key_id: TruncatedTokenKeyId,
        server: VoprfServer<NistP384>,
    ) {
        let mut keys = self.keys.lock().await;
        keys.insert(truncated_token_key_id, server);
    }

    async fn get(
        &self,
        truncated_token_key_id: &TruncatedTokenKeyId,
    ) -> Option<VoprfServer<NistP384>> {
        self.keys.lock().await.get(truncated_token_key_id).cloned()
    }
}
