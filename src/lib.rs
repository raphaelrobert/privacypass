mod auth;
pub mod private_tokens;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum TokenType {
    Voprf = 1,
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use sha2::{
        digest::{
            core_api::BlockSizeUser,
            typenum::{IsLess, IsLessOrEqual, U256},
            OutputSizeUser,
        },
        Digest, Sha256,
    };
    use std::collections::{HashMap, HashSet};
    use tokio::sync::Mutex;
    use voprf::*;

    use crate::{
        auth::TokenChallenge,
        private_tokens::{client::*, server::*, *},
        TokenType,
    };

    #[derive(Default)]
    struct MemoryNonceStore {
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
    struct MemoryKeyStore<CS: CipherSuite>
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

    #[tokio::test]
    async fn cycle() {
        // Server: Instantiate in-memory keystore and nonce store.
        let mut key_store = MemoryKeyStore::default();
        let mut nonce_store = MemoryNonceStore::default();

        // Server: Create server
        let mut server = Server::<Ristretto255>::new();

        // Server: Create a new keypair
        let public_key = server.create_keypair(&mut key_store, 1).await.unwrap();

        // Client: Create client
        let mut client = Client::<Ristretto255>::new(1, public_key);

        // Generate a challenge
        let challenge = TokenChallenge::new(
            TokenType::Voprf,
            "example.com",
            None,
            vec!["example.com".to_string()],
        );

        let challenge_digest = Sha256::digest(challenge.serialize()).to_vec();

        // Client: Prepare a TokenRequest after having received a challenge
        let (token_request, token_state) = client.issue_token_request(&challenge).unwrap();

        // Server: Issue a TokenResponse
        let token_response = server
            .issue_token_response(&key_store, token_request)
            .await
            .unwrap();

        // Client: Turn the TokenResponse into a Token
        let token = client.issue_token(token_response, token_state).unwrap();

        // Server: Compare the challenge digest
        assert_eq!(token.challenge_digest(), &challenge_digest);

        // Server: Redeem the token
        assert!(server
            .redeem_token(&mut key_store, &mut nonce_store, token.clone(),)
            .await
            .is_ok());

        // Server: Test double spend protection
        assert_eq!(
            server
                .redeem_token(&mut key_store, &mut nonce_store, token,)
                .await,
            Err(RedeemTokenError::DoubleSpending)
        );
    }
}
