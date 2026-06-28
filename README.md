# Privacy Pass

> **Warning:** This library has not been independently audited. It should
> not be used in production without a professional security review.

A Rust implementation of the [Privacy Pass](https://datatracker.ietf.org/wg/privacypass/documents/)
issuance protocols. The library implements both client and server sides
with an async API.

## Protocols

| Token type | Spec | Primitive | Cipher suites |
|---|---|---|---|
| Privately Verifiable | [RFC 9578 &sect;5](https://www.rfc-editor.org/rfc/rfc9578.html#section-5) | VOPRF | P384-SHA384, Ristretto255-SHA512 |
| Publicly Verifiable | [RFC 9578 &sect;6](https://www.rfc-editor.org/rfc/rfc9578.html#section-6) | Blind RSA | RSA-2048, SHA-384, PSS |
| Amortized (Batch VOPRF) | [draft-ietf-privacypass-batched-tokens &sect;5](https://www.ietf.org/archive/id/draft-ietf-privacypass-batched-tokens-04.html#section-5) | VOPRF | P384-SHA384, Ristretto255-SHA512 |
| Generic Batch | [draft-ietf-privacypass-batched-tokens &sect;6](https://www.ietf.org/archive/id/draft-ietf-privacypass-batched-tokens-04.html#section-6) | Mixed | All of the above |

The `auth` module provides construction and parsing of the HTTP
`WWW-Authenticate` / `Authorization` headers used in the Privacy Pass
challenge-redemption flow.

## Usage

Add the dependency to your `Cargo.toml`:

```toml
[dependencies]
privacypass = "0.2"
```

Privately verifiable token lifecycle (create keypair, challenge, request,
issue, finalize, redeem):

```rust
use p384::NistP384;
use privacypass::{
    auth::authenticate::TokenChallenge,
    common::private::PrivateCipherSuite,
    private_tokens::{TokenRequest, server::*},
};

// Server: create a keypair
let key_store = /* NonceKeyStore implementation */;
let nonce_store = /* NonceStore implementation */;
let server = Server::new();
let public_key = server.create_keypair(&key_store).await.unwrap();

// Client: build a token request from a challenge
let challenge = TokenChallenge::new(
    NistP384::token_type(),
    "example.com",
    None,
    &["example.com".to_string()],
);
let (token_request, token_state) =
    TokenRequest::new(public_key, &challenge).unwrap();

// Server: issue a token response
let token_response = server
    .issue_token_response(&key_store, token_request)
    .await
    .unwrap();

// Client: finalize the token
let token = token_response.issue_token(&token_state).unwrap();

// Server: redeem the token
server
    .redeem_token(&key_store, &nonce_store, token)
    .await
    .unwrap();
```

## Testing

```sh
cargo test
cargo test --all-features
cargo bench
```

## License

This project is licensed under the [MIT License](LICENSE).
