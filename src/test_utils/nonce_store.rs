//! Nonce store for testing purposes.
use async_trait::async_trait;
use std::collections::HashSet;
use tokio::sync::Mutex;

use crate::{Nonce, NonceStore};

/// Store that stores nonces in memory.
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
