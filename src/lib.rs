mod auth;
mod private_tokens;

#[cfg(test)]
mod tests {
    use voprf::Ristretto255;

    use crate::private_tokens::{Client, Server};

    #[test]
    fn cycle() {
        // Create server
        let mut server = Server::<Ristretto255>::new();
        server.create_keypair(1);

        // Get the server's public key for the client
        let public_key = server.get_key(1).unwrap();

        // Create client
        let mut client = Client::<Ristretto255>::new(1, public_key);

        // Client: Prepare a TokenRequest after having received a challenge
        let (token_request, token_state) = client.issue_token_request(&[]);

        // Server: Issue a TokenResponse
        let token_response = server.issue_token_response(token_request);

        // Client: Turn the TokenResponse into a Token
        let token = client.issue_token(token_response, token_state);

        // Server: Redeem the token
        assert!(server.redeem_token(token.clone()));

        // Test double spend protection
        assert!(!server.redeem_token(token));
    }

    #[test]
    fn key_store() {
        // Create server
        let mut server = Server::<Ristretto255>::new();
        server.create_keypair(1);

        // List keys
        let keys = server.list_keys();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0], 1);

        // Remove key
        server.remove_key(1);
        assert_eq!(server.list_keys().len(), 0);
    }
}
