use wasm_bindgen::prelude::*;
use kyberlib::{KemCore, MlKem768};
use ml_dsa::{MlDsa65, KeyGen, SigningKey, VerifyingKey, Signature};
use ml_dsa::signature::{Signer, Verifier};
use rand::rngs::OsRng;
use rand::RngCore;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use argon2::Argon2;

// ==========================================
// ML-KEM (Kyber) - Key Exchange
// ==========================================

#[wasm_bindgen]
pub struct MlKemKeyPair {
    dk_bytes: Vec<u8>,
    ek_bytes: Vec<u8>,
}

#[wasm_bindgen]
impl MlKemKeyPair {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<MlKemKeyPair, JsValue> {
        let (dk, ek) = MlKem768::generate(&mut OsRng)
            .map_err(|e| JsValue::from_str(&format!("KeyGen error: {:?}", e)))?;
        
        let dk_bytes = dk.as_bytes().to_vec();
        let ek_bytes = ek.as_bytes().to_vec();
        
        Ok(MlKemKeyPair { dk_bytes, ek_bytes })
    }

    #[wasm_bindgen(js_name = exportKeys)]
    pub fn export_keys(&self) -> js_sys::Array {
        let arr = js_sys::Array::new();
        arr.push(&js_sys::Uint8Array::from(&self.dk_bytes[..]));
        arr.push(&js_sys::Uint8Array::from(&self.ek_bytes[..]));
        arr
    }

    #[wasm_bindgen(js_name = importKeys)]
    pub fn import_keys(dk_bytes: &[u8], ek_bytes: &[u8]) -> Result<MlKemKeyPair, JsValue> {
        Ok(MlKemKeyPair {
            dk_bytes: dk_bytes.to_vec(),
            ek_bytes: ek_bytes.to_vec(),
        })
    }

    #[wasm_bindgen(js_name = encapsulate)]
    pub fn encapsulate(&self) -> js_sys::Array {
        let (ct, ss) = kyberlib::encapsulate(&self.ek_bytes, &mut OsRng).unwrap();
        
        let arr = js_sys::Array::new();
        arr.push(&js_sys::Uint8Array::from(&ct[..]));
        arr.push(&js_sys::Uint8Array::from(&ss[..]));
        arr
    }

    #[wasm_bindgen(js_name = decapsulate)]
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<js_sys::Uint8Array, JsValue> {
        let ss = kyberlib::decapsulate(ciphertext, &self.dk_bytes)
            .map_err(|e| JsValue::from_str(&format!("Decapsulation error: {:?}", e)))?;
        
        Ok(js_sys::Uint8Array::from(&ss[..]))
    }
}

// ==========================================
// ML-DSA (Dilithium) - Signatures
// ==========================================

#[wasm_bindgen]
pub struct MlDsaKeyPair {
    sk: SigningKey<MlDsa65>,
    vk: VerifyingKey<MlDsa65>,
}

#[wasm_bindgen]
impl MlDsaKeyPair {
    #[wasm_bindgen(constructor)]
    pub fn new() -> MlDsaKeyPair {
        let keypair = MlDsa65::key_gen(&mut OsRng);
        let sk = keypair.signing_key().clone();
        let vk = keypair.verifying_key().clone();
        MlDsaKeyPair { sk, vk }
    }

    #[wasm_bindgen(js_name = exportKeys)]
    pub fn export_keys(&self) -> js_sys::Array {
        let sk_bytes = self.sk.encode();
        let vk_bytes = self.vk.encode();
        
        let arr = js_sys::Array::new();
        arr.push(&js_sys::Uint8Array::from(sk_bytes.as_slice()));
        arr.push(&js_sys::Uint8Array::from(vk_bytes.as_slice()));
        arr
    }

    #[wasm_bindgen(js_name = importKeys)]
    pub fn import_keys(sk_bytes: &[u8], vk_bytes: &[u8]) -> Result<MlDsaKeyPair, JsValue> {
        let sk_arr: &ml_dsa::EncodedSigningKey<MlDsa65> = sk_bytes.try_into()
            .map_err(|_| JsValue::from_str("Invalid SK length"))?;
        let vk_arr: &ml_dsa::EncodedVerifyingKey<MlDsa65> = vk_bytes.try_into()
            .map_err(|_| JsValue::from_str("Invalid VK length"))?;
            
        let sk = SigningKey::<MlDsa65>::decode(sk_arr);
        let vk = VerifyingKey::<MlDsa65>::decode(vk_arr);
        Ok(MlDsaKeyPair { sk, vk })
    }

    #[wasm_bindgen(js_name = sign)]
    pub fn sign(&self, message: &[u8]) -> js_sys::Uint8Array {
        let sig = self.sk.sign(message);
        let sig_bytes = sig.encode();
        js_sys::Uint8Array::from(sig_bytes.as_slice())
    }

    #[wasm_bindgen(js_name = verify)]
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        let sig_arr: &ml_dsa::EncodedSignature<MlDsa65> = match signature.try_into() {
            Ok(s) => s,
            Err(_) => return false,
        };
        let sig = match Signature::<MlDsa65>::decode(sig_arr) {
            Some(s) => s,
            None => return false,
        };
        self.vk.verify(message, &sig).is_ok()
    }
}

// ==========================================
// PASSPHRASE ENCRYPTION (For IndexedDB)
// ==========================================

#[wasm_bindgen]
pub fn encrypt_private_key(plaintext: &[u8], passphrase: &str) -> Vec<u8> {
    let mut salt_bytes = [0u8; 16];
    OsRng.fill_bytes(&mut salt_bytes);

    // Derive a proper 32-byte key using Argon2
    let argon2 = Argon2::default();
    let mut key_bytes = [0u8; 32];
    argon2.hash_password_into(passphrase.as_bytes(), &salt_bytes, &mut key_bytes)
        .expect("Argon2 hashing failed");
    
    let key = Key::from_slice(&key_bytes);

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = ChaCha20Poly1305::new(key);
    let ciphertext = cipher.encrypt(nonce, plaintext).expect("Encryption failed");

    let mut result = salt_bytes.to_vec();
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    result
}

#[wasm_bindgen]
pub fn decrypt_private_key(encrypted: &[u8], passphrase: &str) -> Vec<u8> {
    if encrypted.len() < 28 {
        return Vec::new();
    }

    let salt_bytes = &encrypted[0..16];
    let nonce_bytes = &encrypted[16..28];
    let nonce = Nonce::from_slice(nonce_bytes);
    let ciphertext = &encrypted[28..];

    // Derive the same 32-byte key using Argon2
    let argon2 = Argon2::default();
    let mut key_bytes = [0u8; 32];
    if argon2.hash_password_into(passphrase.as_bytes(), salt_bytes, &mut key_bytes).is_err() {
        return Vec::new();
    }
    
    let key = Key::from_slice(&key_bytes);

    let cipher = ChaCha20Poly1305::new(key);
    match cipher.decrypt(nonce, ciphertext) {
        Ok(plaintext) => plaintext,
        Err(_) => Vec::new(),
    }
}

// ==========================================
// TESTING EXPORTS
// ==========================================

#[wasm_bindgen]
pub fn test_mlkem() -> String {
    "ML-KEM WASM Loaded OK".to_string()
}

#[wasm_bindgen]
pub fn test_mldsa() -> String {
    "ML-DSA WASM Loaded OK".to_string()
}
