use aes_gcm::{Aes256Gcm, Nonce, KeyInit};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::generic_array::typenum::U12;
use serde::{Deserialize, Serialize};
use hmac::{Hmac, Mac};
use sha2::{Sha256, Digest};
use base64::{Engine as _, alphabet, engine::{self, general_purpose}};
type HmacSha256 = Hmac<Sha256>;
pub const ENCODER : engine::GeneralPurpose = engine::GeneralPurpose::new(&alphabet::STANDARD,general_purpose::PAD);
pub const DECODER : engine::GeneralPurpose = engine::GeneralPurpose::new(&alphabet::STANDARD,general_purpose::PAD);

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct User {
    pub username: Vec<u8>,
    pub password: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UserInput {
    pub username: String,
    pub password: String,
}

pub struct AeadCipher {
    cipher: Aes256Gcm,
    nonce:  Nonce<U12>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CipherText {
    pub ct: Vec<u8>,
    pub nonce: Vec<u8>,
    pub ad: Vec<u8>,
}

impl User {
    pub fn from(user_input: UserInput) -> Self {
        let username = DECODER.decode(user_input.username.as_bytes()).expect("Invalid base64 string");
        let password = DECODER.decode(user_input.password.as_bytes()).expect("Invalid base64 string");
        User {
            username: username,
            password: password,
        }
    }
}

impl CipherText {
    pub fn recovery_code(&self)->String{
        let bytes_data =  bincode::serialize(self).unwrap();
        let recovery_code = ENCODER.encode(&bytes_data);
        return recovery_code;
    }

    pub fn from_recovery_code(recovery_code: &str)->Self{
        let bytes_data = DECODER.decode(recovery_code.as_bytes()).expect("Invalid base64 string");
        let cipher_text: CipherText = bincode::deserialize(&bytes_data).unwrap();
        return cipher_text;
    }
}

pub fn determinanistic_nonce(user: &User) -> Nonce<U12> {
    let mut hmac_sha256 = <HmacSha256 as Mac>::new_from_slice(user.username.as_slice()).unwrap();
    hmac_sha256.update(user.password.as_slice());
    let hashbytes = hmac_sha256.finalize().into_bytes();
    // 12 bytes nonce
    let mut nonce = [0u8; 12];
    let len = hashbytes.len().min(12);
    nonce[..len].copy_from_slice(&hashbytes[..len]);
    *Nonce::from_slice(&nonce)
}

impl AeadCipher {

    pub fn new(key: &[u8; 32], user: &User) -> Self {
        let cipher = Aes256Gcm::new(GenericArray::from_slice(key));
        let nonce = determinanistic_nonce(user);

        AeadCipher {
            cipher: cipher,
            nonce: nonce,
        }
    }

    pub fn from_key(key: &[u8; 32]) -> Self {
        let cipher = Aes256Gcm::new(GenericArray::from_slice(key));
        // zero nonce
        let nonce = Nonce::from_slice(&[0u8; 12]);
        AeadCipher {
            cipher: cipher,
            nonce: *nonce,
        }
    }

    fn next_nonce(&mut self) {
        let mut hasher = <Sha256 as Digest>::new();
        hasher.update(&self.nonce);
        let result = hasher.finalize();
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&result[..12]);
        self.nonce = *Nonce::from_slice(&nonce);
    }

    pub fn encrypt(&mut self, data: &Vec<u8>, admin: bool) -> CipherText {
        let mut ad = Vec::new();
        ad.extend_from_slice(b"admin=");
        ad.extend_from_slice(if admin { b"true" } else { b"false"});
        let nonce = self.nonce.clone();
        let payload = Payload {
            msg: &data,
            aad: &ad,
        };
        let ct = self.cipher.encrypt(&nonce, payload).expect("encryption failure!");
        self.next_nonce();
        CipherText{
            ct: ct,
            nonce: nonce.to_vec(),
            ad: ad,
        }
    }

    pub fn decrypt(&mut self, c: &CipherText) -> Result<Vec<u8>, aes_gcm::Error> {
        let nonce = c.nonce.as_ref();
        let data = c.ct.as_slice();
        let ad = c.ad.as_slice();
        self.cipher.decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: data,
                aad: ad,
            }
        )
    }
}