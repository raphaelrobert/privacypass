use async_trait::async_trait;
use p384::NistP384;
use std::collections::{HashMap, HashSet};
use tokio::sync::Mutex;
use voprf::*;

use privacypass::private_tokens::server::*;
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
    keys: Mutex<HashMap<TokenKeyId, VoprfServer<NistP384>>>,
}

#[async_trait]
impl KeyStore for MemoryKeyStore {
    async fn insert(&self, token_key_id: TokenKeyId, server: VoprfServer<NistP384>) {
        let mut keys = self.keys.lock().await;
        keys.insert(token_key_id, server);
    }

    async fn get(&self, token_key_id: &TokenKeyId) -> Option<VoprfServer<NistP384>> {
        self.keys.lock().await.get(token_key_id).cloned()
    }
}
