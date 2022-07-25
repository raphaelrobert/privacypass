use async_trait::async_trait;
use sha2::digest::{
    core_api::BlockSizeUser,
    typenum::{IsLess, IsLessOrEqual, U256},
    OutputSizeUser,
};
use std::collections::{HashMap, HashSet};
use tokio::sync::Mutex;
use voprf::*;

use privacypass::batched_tokens::server::*;
use privacypass::{KeyId, Nonce, NonceStore};

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
pub struct MemoryKeyStore<CS: CipherSuite>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    keys: Mutex<HashMap<KeyId, VoprfServer<CS>>>,
}

#[async_trait]
impl<CS: CipherSuite> KeyStore<CS> for MemoryKeyStore<CS>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
    <CS::Group as Group>::Scalar: Send,
    <CS::Group as Group>::Elem: Send,
{
    async fn insert(&mut self, key_id: KeyId, server: VoprfServer<CS>) {
        let mut keys = self.keys.lock().await;
        keys.insert(key_id, server);
    }

    async fn get(&self, key_id: &KeyId) -> Option<VoprfServer<CS>> {
        self.keys.lock().await.get(key_id).cloned()
    }
}
