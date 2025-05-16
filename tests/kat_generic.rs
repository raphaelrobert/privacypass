use futures::stream::{self, StreamExt};
use kat_private::generate_kat_private_token;
use kat_public::generate_kat_public_token;
use p384::NistP384;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{fs::File, io::Write};
use tls_codec::{Deserialize as _, Serialize as TlsSerializeTrait};
use voprf::Ristretto255;

use privacypass::{
    TokenType,
    common::private::PrivateCipherSuite,
    generic_tokens::{
        GenericBatchTokenRequest, GenericBatchTokenResponse, GenericTokenRequest,
        GenericTokenResponse, OptionalTokenResponse,
    },
    private_tokens,
    public_tokens::{self},
};

mod kat_private;
mod kat_public;

mod option_hex {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(opt: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match opt {
            Some(bytes) => {
                let hex = hex::encode(bytes);
                serializer.serialize_str(&hex)
            }
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt = Option::<String>::deserialize(deserializer)?;
        match opt {
            Some(hex_str) => {
                let bytes = hex::decode(&hex_str).map_err(serde::de::Error::custom)?;
                Ok(Some(bytes))
            }
            None => Ok(None),
        }
    }
}

fn hex_str_to_u16<'de, D>(deserializer: D) -> Result<u16, D::Error>
where
    D: Deserializer<'de>,
{
    let s: &str = Deserialize::deserialize(deserializer)?;
    u16::from_str_radix(s, 16).map_err(serde::de::Error::custom)
}

fn u16_to_hex_str<S>(x: &u16, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let s = format!("{x:04x}");
    serializer.serialize_str(&s)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Issuance {
    #[serde(
        deserialize_with = "hex_str_to_u16",
        serialize_with = "u16_to_hex_str",
        alias = "type"
    )]
    token_type: u16,
    #[serde(with = "hex", alias = "skS")]
    sk_s: Vec<u8>,
    #[serde(with = "hex", alias = "pkS")]
    pk_s: Vec<u8>,
    #[serde(with = "hex")]
    token_challenge: Vec<u8>,
    #[serde(with = "hex")]
    nonce: Vec<u8>,
    #[serde(with = "hex")]
    blind: Vec<u8>,
    #[serde(with = "option_hex", default)]
    salt: Option<Vec<u8>>,
    #[serde(with = "hex")]
    token: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
struct GenericTokenTestVector {
    issuance: Vec<Issuance>,
    #[serde(with = "hex")]
    token_request: Vec<u8>,
    #[serde(with = "hex")]
    token_response: Vec<u8>,
}

#[tokio::test]
async fn read_kat_generic_token() {
    let list: Vec<GenericTokenTestVector> =
        serde_json::from_str(include_str!("kat_vectors/generic_rs.json").trim()).unwrap();

    evaluate_kat(list).await;

    let list: Vec<GenericTokenTestVector> =
        serde_json::from_str(include_str!("kat_vectors/generic_go.json").trim()).unwrap();

    evaluate_kat(list).await;

    // Waiting for TS implementation to catch up
    /* let list: Vec<GenericTokenTestVector> =
        serde_json::from_str(include_str!("kat_vectors/generic_ts.json").trim())
            .unwrap();

    evaluate_kat(list).await; */
}

async fn evaluate_kat(list: Vec<GenericTokenTestVector>) {
    for vector in list {
        let batch_token_request =
            GenericBatchTokenRequest::tls_deserialize(&mut vector.token_request.as_slice())
                .unwrap();
        let batch_token_response =
            GenericBatchTokenResponse::tls_deserialize(&mut vector.token_response.as_slice())
                .unwrap();

        stream::iter(
            vector
                .issuance
                .iter()
                .zip(batch_token_request.clone().token_requests)
                .zip(batch_token_response.clone().token_responses),
        )
        .for_each(
            async move |((issuance, generic_token_request), generic_token_response): (
                (&Issuance, GenericTokenRequest),
                OptionalTokenResponse,
            )| {
                match generic_token_request {
                    GenericTokenRequest::PrivateP384(token_request) => {
                        let generic_token_response = generic_token_response.token_response.unwrap();
                        let GenericTokenResponse::PrivateP384(token_response) =
                            generic_token_response
                        else {
                            unreachable!("Expected a PrivateTokenResponse");
                        };
                        let private_token_test_vector = kat_private::PrivateTokenTestVector {
                            sk_s: issuance.sk_s.clone(),
                            pk_s: issuance.pk_s.clone(),
                            token_challenge: issuance.token_challenge.clone(),
                            nonce: issuance.nonce.clone(),
                            blind: issuance.blind.clone(),
                            token_request: token_request.tls_serialize_detached().unwrap(),
                            token_response: token_response.tls_serialize_detached().unwrap(),
                            token: issuance.token.clone(),
                        };

                        kat_private::evaluate_vector::<NistP384>(private_token_test_vector).await;
                    }
                    GenericTokenRequest::Public(token_request) => {
                        let generic_token_response = generic_token_response.token_response.unwrap();
                        let GenericTokenResponse::Public(token_response) = generic_token_response
                        else {
                            unreachable!("Expected a PublicTokenResponse");
                        };
                        let public_token_test_vector = kat_public::PublicTokenTestVector {
                            sk_s: issuance.sk_s.clone(),
                            pk_s: issuance.pk_s.clone(),
                            token_challenge: issuance.token_challenge.clone(),
                            nonce: issuance.nonce.clone(),
                            blind: issuance.blind.clone(),
                            salt: issuance.salt.clone().unwrap(),
                            token_request: token_request.tls_serialize_detached().unwrap(),
                            token_response: token_response.tls_serialize_detached().unwrap(),
                            token: issuance.token.clone(),
                        };

                        kat_public::evaluate_vector(public_token_test_vector).await;
                    }
                    GenericTokenRequest::PrivateRistretto255(token_request) => {
                        let generic_token_response = generic_token_response.token_response.unwrap();
                        let GenericTokenResponse::PrivateRistretto255(token_response) =
                            generic_token_response
                        else {
                            unreachable!("Expected a PrivateTokenResponse");
                        };
                        let private_token_test_vector = kat_private::PrivateTokenTestVector {
                            sk_s: issuance.sk_s.clone(),
                            pk_s: issuance.pk_s.clone(),
                            token_challenge: issuance.token_challenge.clone(),
                            nonce: issuance.nonce.clone(),
                            blind: issuance.blind.clone(),
                            token_request: token_request.tls_serialize_detached().unwrap(),
                            token_response: token_response.tls_serialize_detached().unwrap(),
                            token: issuance.token.clone(),
                        };

                        kat_private::evaluate_vector::<Ristretto255>(private_token_test_vector)
                            .await;
                    }
                };
            },
        )
        .await;
    }
}

#[tokio::test]
async fn write_kat_generic_token() {
    let mut elements = Vec::new();

    for i in 1..4 {
        // Generate a new test vector
        let vector = match i {
            1 => generate_kat_generic_token_1().await,
            2 => generate_kat_generic_token_2().await,
            3 => generate_kat_generic_token_3().await,
            _ => unreachable!(),
        };

        elements.push(vector);
    }

    let data = serde_json::to_string_pretty(&elements).unwrap();

    println!("Evaluating KAT...");

    evaluate_kat(elements).await;

    let mut file = File::create("tests/kat_vectors/generic_rs-new.json").unwrap();
    file.write_all(data.as_bytes()).unwrap();
}

async fn generate_kat_generic_token_1() -> GenericTokenTestVector {
    let (issuance1, request1, response1) = generate_private_token::<NistP384>().await;
    let (issuance2, request2, response2) = generate_public_token().await;

    batch_generated_tokens(vec![
        (issuance1, request1, response1),
        (issuance2, request2, response2),
    ])
}

async fn generate_kat_generic_token_2() -> GenericTokenTestVector {
    let (issuance1, request1, response1) = generate_public_token().await;
    let (issuance2, request2, response2) = generate_private_token::<NistP384>().await;

    batch_generated_tokens(vec![
        (issuance1, request1, response1),
        (issuance2, request2, response2),
    ])
}

async fn generate_kat_generic_token_3() -> GenericTokenTestVector {
    let (issuance1, request1, response1) = generate_private_token::<NistP384>().await;
    let (issuance2, request2, response2) = generate_public_token().await;
    let (issuance3, request3, response3) = generate_private_token::<Ristretto255>().await;
    let (issuance4, request4, response4) = generate_public_token().await;

    batch_generated_tokens(vec![
        (issuance1, request1, response1),
        (issuance2, request2, response2),
        (issuance3, request3, response3),
        (issuance4, request4, response4),
    ])
}

fn batch_generated_tokens(
    batch: Vec<(Issuance, GenericTokenRequest, GenericTokenResponse)>,
) -> GenericTokenTestVector {
    let issuances = batch.iter().map(|(i, _, _)| i.to_owned()).collect();
    let requests = batch.iter().map(|(_, r, _)| r.clone()).collect();
    let responses = batch
        .iter()
        .map(|(_, _, r)| OptionalTokenResponse {
            token_response: Some(r.clone()),
        })
        .collect();

    let batch_token_request = GenericBatchTokenRequest {
        token_requests: requests,
    };
    let batch_token_response = GenericBatchTokenResponse {
        token_responses: responses,
    };

    GenericTokenTestVector {
        issuance: issuances,
        token_request: batch_token_request.tls_serialize_detached().unwrap(),
        token_response: batch_token_response.tls_serialize_detached().unwrap(),
    }
}

async fn generate_private_token<CS: PrivateCipherSuite>()
-> (Issuance, GenericTokenRequest, GenericTokenResponse) {
    let pv = generate_kat_private_token::<CS>().await;

    let issuance = Issuance {
        token_type: CS::token_type() as u16,
        sk_s: pv.sk_s,
        pk_s: pv.pk_s,
        token_challenge: pv.token_challenge,
        nonce: pv.nonce,
        blind: pv.blind,
        salt: None,
        token: pv.token,
    };

    match CS::token_type() {
        TokenType::PrivateP384 => {
            let token_request = private_tokens::TokenRequest::<NistP384>::tls_deserialize(
                &mut pv.token_request.as_slice(),
            )
            .unwrap();
            let token_response = private_tokens::TokenResponse::<NistP384>::tls_deserialize(
                &mut pv.token_response.as_slice(),
            )
            .unwrap();

            (
                issuance,
                GenericTokenRequest::PrivateP384(Box::new(token_request)),
                GenericTokenResponse::PrivateP384(Box::new(token_response)),
            )
        }
        TokenType::PrivateRistretto255 => {
            let token_request = private_tokens::TokenRequest::<Ristretto255>::tls_deserialize(
                &mut pv.token_request.as_slice(),
            )
            .unwrap();
            let token_response = private_tokens::TokenResponse::<Ristretto255>::tls_deserialize(
                &mut pv.token_response.as_slice(),
            )
            .unwrap();

            (
                issuance,
                GenericTokenRequest::PrivateRistretto255(Box::new(token_request)),
                GenericTokenResponse::PrivateRistretto255(Box::new(token_response)),
            )
        }
        _ => unreachable!(),
    }
}

async fn generate_public_token() -> (Issuance, GenericTokenRequest, GenericTokenResponse) {
    let pv = generate_kat_public_token().await;

    let token_request =
        public_tokens::TokenRequest::tls_deserialize(&mut pv.token_request.as_slice()).unwrap();
    let token_response =
        public_tokens::TokenResponse::tls_deserialize(&mut pv.token_response.as_slice()).unwrap();

    let issuance = Issuance {
        token_type: TokenType::Public as u16,
        sk_s: pv.sk_s,
        pk_s: pv.pk_s,
        token_challenge: pv.token_challenge,
        nonce: pv.nonce,
        blind: pv.blind,
        salt: Some(pv.salt),
        token: pv.token,
    };

    (
        issuance,
        GenericTokenRequest::Public(Box::new(token_request)),
        GenericTokenResponse::Public(Box::new(token_response)),
    )
}
