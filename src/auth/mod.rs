// struct {
//     uint16_t token_type;
//     opaque issuer_name<1..2^16-1>;
//     opaque redemption_context<0..32>;
//     opaque origin_info<0..2^16-1>;
// } TokenChallenge;

pub struct TokenChallenge {
    token_type: u16,
    issuer_name: Vec<u8>,
    redemption_context: Vec<u8>,
    origin_info: Vec<u8>,
}

impl TokenChallenge {
    pub fn new(
        token_type: u16,
        issuer_name: &[u8],
        redemption_context: Option<&[u8]>,
        origin_info: Option<&[u8]>,
    ) -> Self {
        Self {
            token_type,
            issuer_name: issuer_name.to_vec(),
            redemption_context: redemption_context.unwrap_or_default().to_vec(),
            origin_info: origin_info.unwrap_or_default().to_vec(),
        }
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
