//! Nonce store for testing purposes.
use async_trait::async_trait;
use std::collections::HashMap;
use tokio::sync::Mutex;

use crate::{Nonce, NonceStore};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NonceState {
    Reserved,
    Committed,
}

/// Store that stores nonces in memory.
#[derive(Default, Debug)]
pub struct MemoryNonceStore {
    nonces: Mutex<HashMap<Nonce, NonceState>>,
}

#[async_trait]
impl NonceStore for MemoryNonceStore {
    async fn reserve(&self, nonce: &Nonce) -> bool {
        use std::collections::hash_map::Entry;
        let mut nonces = self.nonces.lock().await;
        match nonces.entry(*nonce) {
            Entry::Vacant(e) => {
                e.insert(NonceState::Reserved);
                true
            }
            Entry::Occupied(_) => false,
        }
    }

    async fn commit(&self, nonce: &Nonce) {
        let mut nonces = self.nonces.lock().await;
        if let Some(state) = nonces.get_mut(nonce)
            && *state == NonceState::Reserved
        {
            *state = NonceState::Committed;
        }
    }

    async fn release(&self, nonce: &Nonce) {
        let mut nonces = self.nonces.lock().await;
        if nonces.get(nonce) == Some(&NonceState::Reserved) {
            nonces.remove(nonce);
        }
    }
}
