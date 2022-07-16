use crate::TokenType;

pub type RedemptionContext = [u8; 32];

// struct {
//     uint16_t token_type;
//     opaque issuer_name<1..2^16-1>;
//     opaque redemption_context<0..32>;
//     opaque origin_info<0..2^16-1>;
// } TokenChallenge;

pub struct TokenChallenge {
    token_type: TokenType,
    issuer_name: Vec<u8>,
    redemption_context: Option<RedemptionContext>,
    origin_info: Vec<u8>,
}

impl TokenChallenge {
    pub fn new(
        token_type: TokenType,
        issuer_name: &str,
        redemption_context: Option<RedemptionContext>,
        origin_info: Vec<String>,
    ) -> Self {
        Self {
            token_type,
            issuer_name: issuer_name.as_bytes().to_vec(),
            redemption_context,
            origin_info: origin_info.join(",").as_bytes().to_vec(),
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::new();
        buffer.extend_from_slice((self.token_type as u16).to_be_bytes().as_slice());
        buffer.extend_from_slice((self.issuer_name.len() as u16).to_be_bytes().as_slice());
        buffer.extend_from_slice(self.issuer_name.as_slice());
        match &self.redemption_context {
            Some(redemption_context) => {
                buffer.push(32u8);
                buffer.extend_from_slice(redemption_context.as_slice());
            }
            None => {
                buffer.push(0u8);
            }
        }
        buffer.extend_from_slice((self.origin_info.len() as u16).to_be_bytes().as_slice());
        buffer.extend_from_slice(self.origin_info.as_slice());
        buffer
    }

    pub fn to_base64(&self) -> String {
        // TODO: Padding?
        base64::encode(&self.serialize())
    }
}

pub struct TokenTypeData {
    value: u16,
    name: String,
    publicly_verifiable: bool,
    public_metadata: bool,
    private_metadata: bool,
    nk: usize,
    nid: usize,
}

struct WwwAuthenticateBuilder {}

impl WwwAuthenticateBuilder {
    pub fn build(
        token_challenge: TokenChallenge,
        token_key: u8,
        max_age: Option<usize>,
    ) -> (String, String) {
        todo!()
    }
}
