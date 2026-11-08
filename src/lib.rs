use cipherbox_pqc_core::{
    CipherboxError, MlDsaKeyPair as CoreDsa, MlKemKeyPair as CoreKem,
    decrypt_private_key as core_decrypt, encrypt_private_key as core_encrypt,
};
use wasm_bindgen::prelude::*;

fn err_to_js(e: CipherboxError) -> JsValue {
    JsValue::from_str(&e.to_string())
}

// ==========================================
// ML-KEM (Kyber) wrapper
// ==========================================

#[wasm_bindgen]
pub struct MlKemKeyPair {
    inner: CoreKem,
}

#[wasm_bindgen]
impl MlKemKeyPair {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<MlKemKeyPair, JsValue> {
        CoreKem::new()
            .map(|inner| MlKemKeyPair { inner })
            .map_err(err_to_js)
    }

    #[wasm_bindgen(js_name = exportKeys)]
    pub fn export_keys(&self) -> js_sys::Array {
        let (dk_seed, ek) = self.inner.export_keys();
        let arr = js_sys::Array::new();
        arr.push(&js_sys::Uint8Array::from(&dk_seed[..]));
        arr.push(&js_sys::Uint8Array::from(&ek[..]));
        arr
    }

    #[wasm_bindgen(js_name = importKeys)]
    pub fn import_keys(dk_seed: &[u8], ek: &[u8]) -> Result<MlKemKeyPair, JsValue> {
        CoreKem::import_keys(dk_seed, ek)
            .map(|inner| MlKemKeyPair { inner })
            .map_err(err_to_js)
    }

    #[wasm_bindgen(js_name = encapsulate)]
    pub fn encapsulate(&self) -> Result<js_sys::Array, JsValue> {
        let (ct, ss) = self.inner.encapsulate().map_err(err_to_js)?;
        let arr = js_sys::Array::new();
        arr.push(&js_sys::Uint8Array::from(&ct[..]));
        arr.push(&js_sys::Uint8Array::from(&ss[..]));
        Ok(arr)
    }

    #[wasm_bindgen(js_name = decapsulate)]
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<js_sys::Uint8Array, JsValue> {
        let ss = self.inner.decapsulate(ciphertext).map_err(err_to_js)?;
        Ok(js_sys::Uint8Array::from(&ss[..]))
    }
}

// ==========================================
// ML-DSA (Dilithium) wrapper
// ==========================================

#[wasm_bindgen]
pub struct MlDsaKeyPair {
    inner: CoreDsa,
}

#[wasm_bindgen]
impl MlDsaKeyPair {
    #[wasm_bindgen(constructor)]
    pub fn new() -> MlDsaKeyPair {
        MlDsaKeyPair {
            inner: CoreDsa::new(),
        }
    }

    #[wasm_bindgen(js_name = exportKeys)]
    pub fn export_keys(&self) -> js_sys::Array {
        let (seed, vk) = self.inner.export_keys();
        let arr = js_sys::Array::new();
        arr.push(&js_sys::Uint8Array::from(&seed[..]));
        arr.push(&js_sys::Uint8Array::from(&vk[..]));
        arr
    }

    #[wasm_bindgen(js_name = importKeys)]
    pub fn import_keys(seed: &[u8], vk: &[u8]) -> Result<MlDsaKeyPair, JsValue> {
        CoreDsa::import_keys(seed, vk)
            .map(|inner| MlDsaKeyPair { inner })
            .map_err(err_to_js)
    }

    #[wasm_bindgen(js_name = sign)]
    pub fn sign(&self, message: &[u8]) -> js_sys::Uint8Array {
        let sig = self.inner.sign(message);
        js_sys::Uint8Array::from(&sig[..])
    }

    #[wasm_bindgen(js_name = verify)]
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        self.inner.verify(message, signature)
    }
}

// ==========================================
// Free functions (passphrase encryption)
// ==========================================

#[wasm_bindgen]
pub fn encrypt_private_key(plaintext: &[u8], passphrase: &str) -> Result<Vec<u8>, JsValue> {
    core_encrypt(plaintext, passphrase).map_err(err_to_js)
}

#[wasm_bindgen]
pub fn decrypt_private_key(encrypted: &[u8], passphrase: &str) -> Result<Vec<u8>, JsValue> {
    core_decrypt(encrypted, passphrase).map_err(err_to_js)
}
