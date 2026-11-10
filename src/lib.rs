//! WebAssembly bindings for `cipherbox-pqc-core`.
//!
//! All cryptography lives in the core crate; this file only converts types.
//! Methods are camelCase in JS; free functions keep their snake_case names.

use cipherbox_pqc_core as pqc;
use cipherbox_pqc_core::{
    CipherboxError, HybridKeyPair as CoreHybrid, KemLevel, MlDsa87KeyPair as CoreDsa87,
    MlDsaKeyPair as CoreDsa, MlKemKeyPair as CoreKem,
    file::{self, FileDecryptor as CoreDec, FileEncryptor as CoreEnc},
};
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;

fn err_to_js(e: CipherboxError) -> JsValue {
    JsValue::from_str(&e.to_string())
}

fn js_err(msg: &str) -> JsValue {
    JsValue::from_str(msg)
}

/// `None` or 768 -> ML-KEM-768; 1024 -> ML-KEM-1024.
fn level_from(level: Option<u16>) -> Result<KemLevel, JsValue> {
    match level {
        None => Ok(KemLevel::MlKem768),
        Some(p) => KemLevel::from_param(p)
            .ok_or_else(|| js_err("unsupported ML-KEM level (use 768 or 1024)")),
    }
}

fn pair(a: &[u8], b: &[u8]) -> js_sys::Array {
    let arr = js_sys::Array::new();
    arr.push(&js_sys::Uint8Array::from(a));
    arr.push(&js_sys::Uint8Array::from(b));
    arr
}

// ==========================================
// ML-KEM (Kyber) key pair
// ==========================================

#[wasm_bindgen]
pub struct MlKemKeyPair {
    inner: CoreKem,
}

#[wasm_bindgen]
impl MlKemKeyPair {
    /// Generate a fresh key pair. `level` is 768 (default) or 1024.
    #[wasm_bindgen(constructor)]
    pub fn new(level: Option<u16>) -> Result<MlKemKeyPair, JsValue> {
        CoreKem::new_with_level(level_from(level)?)
            .map(|inner| MlKemKeyPair { inner })
            .map_err(err_to_js)
    }

    /// Rebuild a key pair from the 64-byte secret seed. The seed does not
    /// record the level: pass the same `level` (768 default, or 1024) the
    /// key was created with.
    #[wasm_bindgen(js_name = fromSeed)]
    pub fn from_seed(dk_seed: &[u8], level: Option<u16>) -> Result<MlKemKeyPair, JsValue> {
        CoreKem::from_seed_with_level(dk_seed, level_from(level)?)
            .map(|inner| MlKemKeyPair { inner })
            .map_err(err_to_js)
    }

    /// 768 or 1024.
    #[wasm_bindgen(js_name = level)]
    pub fn level(&self) -> u16 {
        self.inner.level().param()
    }

    /// Returns `[seed (64 bytes), publicKey (1184 or 1568 bytes)]`.
    #[wasm_bindgen(js_name = exportKeys)]
    pub fn export_keys(&self) -> js_sys::Array {
        let (dk_seed, ek) = self.inner.export_keys();
        pair(&dk_seed, &ek)
    }

    /// Import `(seed, publicKey)`; the level comes from the public key's
    /// length. Fails if they do not match.
    #[wasm_bindgen(js_name = importKeys)]
    pub fn import_keys(dk_seed: &[u8], ek: &[u8]) -> Result<MlKemKeyPair, JsValue> {
        CoreKem::import_keys(dk_seed, ek)
            .map(|inner| MlKemKeyPair { inner })
            .map_err(err_to_js)
    }

    #[wasm_bindgen(js_name = publicKey)]
    pub fn public_key(&self) -> Vec<u8> {
        self.inner.encapsulation_key().to_vec()
    }

    /// Encapsulate to this pair's own public key. Returns `[ct, sharedSecret]`.
    #[wasm_bindgen(js_name = encapsulate)]
    pub fn encapsulate(&self) -> Result<js_sys::Array, JsValue> {
        let (ct, ss) = self.inner.encapsulate().map_err(err_to_js)?;
        Ok(pair(&ct, &ss))
    }

    #[wasm_bindgen(js_name = decapsulate)]
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<js_sys::Uint8Array, JsValue> {
        let ss = self.inner.decapsulate(ciphertext).map_err(err_to_js)?;
        Ok(js_sys::Uint8Array::from(&ss[..]))
    }

    /// Unwrap a blob produced by `wrap_key`.
    #[wasm_bindgen(js_name = unwrapKey)]
    pub fn unwrap_key(&self, blob: &[u8]) -> Result<Vec<u8>, JsValue> {
        pqc::unwrap_key(&self.inner, blob).map_err(err_to_js)
    }

    /// Open a `wrap_room_key_for_user` JSON payload. `version` is its `v`
    /// field (use 1 when the field is absent: legacy format).
    #[wasm_bindgen(js_name = unwrapRoomKey)]
    pub fn unwrap_room_key(
        &self,
        version: u8,
        ct_b64: &str,
        iv_b64: &str,
        enc_aes_b64: &str,
    ) -> Result<String, JsValue> {
        pqc::unwrap_room_key(&self.inner, version, ct_b64, iv_b64, enc_aes_b64)
            .map_err(err_to_js)
    }
}

/// Encapsulate to someone else's public key (no private key needed).
/// Returns `[ct, sharedSecret]`.
#[wasm_bindgen]
pub fn encapsulate_to(public_key: &[u8]) -> Result<js_sys::Array, JsValue> {
    let (ct, ss) = pqc::encapsulate_to(public_key).map_err(err_to_js)?;
    Ok(pair(&ct, &ss))
}

/// Throws unless `public_key` is a valid public key: plain ML-KEM-768/1024
/// or an X25519 hybrid. Returns the ML-KEM level (768 or 1024).
#[wasm_bindgen]
pub fn validate_public_key(public_key: &[u8]) -> Result<u16, JsValue> {
    pqc::validate_public_key(public_key)
        .map(|s| s.level().param())
        .map_err(err_to_js)
}

/// Name of the suite a public key belongs to, e.g. `"ML-KEM-768"` or
/// `"X25519+ML-KEM-1024"`. Throws if the key is invalid.
#[wasm_bindgen]
pub fn public_key_suite(public_key: &[u8]) -> Result<String, JsValue> {
    pqc::validate_public_key(public_key)
        .map(|s| s.name().to_string())
        .map_err(err_to_js)
}

// ==========================================
// X25519 + ML-KEM hybrid
// ==========================================

#[wasm_bindgen]
pub struct HybridKeyPair {
    inner: CoreHybrid,
}

#[wasm_bindgen]
impl HybridKeyPair {
    /// Generate a hybrid key pair. `level` is 768 (default) or 1024.
    #[wasm_bindgen(constructor)]
    pub fn new(level: Option<u16>) -> Result<HybridKeyPair, JsValue> {
        CoreHybrid::new(level_from(level)?)
            .map(|inner| HybridKeyPair { inner })
            .map_err(err_to_js)
    }

    /// Restore from the 34-byte secret produced by `exportSecret()`; the
    /// level is part of the secret.
    #[wasm_bindgen(js_name = fromSecret)]
    pub fn from_secret(secret: &[u8]) -> Result<HybridKeyPair, JsValue> {
        CoreHybrid::from_secret(secret)
            .map(|inner| HybridKeyPair { inner })
            .map_err(err_to_js)
    }

    /// 34-byte secret (`version || level || seed`). Keep it private;
    /// protect it with `encrypt_private_key` before storing.
    #[wasm_bindgen(js_name = exportSecret)]
    pub fn export_secret(&self) -> Vec<u8> {
        self.inner.export_secret()
    }

    /// `ek_mlkem || x25519_pk` (1216 or 1600 bytes). Share this.
    #[wasm_bindgen(js_name = publicKey)]
    pub fn public_key(&self) -> Vec<u8> {
        self.inner.public_key().to_vec()
    }

    /// 768 or 1024.
    #[wasm_bindgen(js_name = level)]
    pub fn level(&self) -> u16 {
        self.inner.level().param()
    }

    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<Vec<u8>, JsValue> {
        self.inner.decapsulate(ciphertext).map_err(err_to_js)
    }

    #[wasm_bindgen(js_name = unwrapKey)]
    pub fn unwrap_key(&self, blob: &[u8]) -> Result<Vec<u8>, JsValue> {
        pqc::unwrap_key(&self.inner, blob).map_err(err_to_js)
    }

    #[wasm_bindgen(js_name = unwrapRoomKey)]
    pub fn unwrap_room_key(
        &self,
        version: u8,
        ct_b64: &str,
        iv_b64: &str,
        enc_aes_b64: &str,
    ) -> Result<String, JsValue> {
        pqc::unwrap_room_key(&self.inner, version, ct_b64, iv_b64, enc_aes_b64)
            .map_err(err_to_js)
    }
}

/// Encapsulate to a hybrid public key. Returns `[ct, sharedSecret]`.
#[wasm_bindgen]
pub fn hybrid_encapsulate_to(public_key: &[u8]) -> Result<js_sys::Array, JsValue> {
    let (ct, ss) = pqc::encapsulate_hybrid_to(public_key).map_err(err_to_js)?;
    Ok(pair(&ct, &ss))
}

// ==========================================
// Key wrapping
// ==========================================

#[wasm_bindgen]
pub fn wrap_key(public_key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, JsValue> {
    pqc::wrap_key(public_key, plaintext).map_err(err_to_js)
}

/// JSON: `{"v":2,"ct":"..","iv":"..","enc_aes":".."}`.
#[wasm_bindgen]
pub fn wrap_room_key_for_user(
    user_pk_b64: &str,
    room_key_plaintext: &str,
) -> Result<String, JsValue> {
    pqc::wrap_room_key_for_user(user_pk_b64, room_key_plaintext).map_err(err_to_js)
}

// ==========================================
// File encryption (streaming + one-shot)
// ==========================================

#[wasm_bindgen]
pub struct FileEncryptor {
    inner: Option<CoreEnc>,
}

#[wasm_bindgen]
impl FileEncryptor {
    /// `recipientPublicKey` may be a plain ML-KEM key (1184/1568 bytes) or a
    /// hybrid key (1216/1600 bytes). `chunkSize` defaults to 64 KiB.
    #[wasm_bindgen(constructor)]
    pub fn new(recipient_public_key: &[u8], chunk_size: Option<u32>) -> Result<FileEncryptor, JsValue> {
        let cs = chunk_size.map(|c| c as usize).unwrap_or(file::CHUNK_SIZE_DEFAULT);
        CoreEnc::new(recipient_public_key, cs)
            .map(|e| FileEncryptor { inner: Some(e) })
            .map_err(err_to_js)
    }

    /// Feed plaintext; returns ciphertext produced so far (may be empty).
    pub fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, JsValue> {
        let enc = self.inner.as_mut().ok_or_else(|| js_err("encryptor already finished"))?;
        let mut out = Vec::new();
        enc.update(data, &mut out).map_err(err_to_js)?;
        Ok(out)
    }

    /// Flush the final chunk. The encryptor cannot be used afterwards.
    pub fn finish(&mut self) -> Result<Vec<u8>, JsValue> {
        let enc = self.inner.take().ok_or_else(|| js_err("encryptor already finished"))?;
        let mut out = Vec::new();
        enc.finish(&mut out).map_err(err_to_js)?;
        Ok(out)
    }
}

#[wasm_bindgen]
pub struct FileDecryptor {
    inner: Option<CoreDec>,
}

#[wasm_bindgen]
impl FileDecryptor {
    /// `dkSeed` is the 64-byte secret seed from `exportKeys()[0]`. The
    /// ML-KEM level is read from the file header, so one decryptor class
    /// handles both 768 and 1024 files.
    #[wasm_bindgen(constructor)]
    pub fn new(dk_seed: &[u8]) -> Result<FileDecryptor, JsValue> {
        CoreDec::from_seed(dk_seed)
            .map(|d| FileDecryptor { inner: Some(d) })
            .map_err(err_to_js)
    }

    /// Decrypt files encrypted to a hybrid public key, using the 34-byte
    /// secret from `HybridKeyPair.exportSecret()`.
    #[wasm_bindgen(js_name = fromHybridSecret)]
    pub fn from_hybrid_secret(secret: &[u8]) -> Result<FileDecryptor, JsValue> {
        CoreDec::from_hybrid_secret(secret)
            .map(|d| FileDecryptor { inner: Some(d) })
            .map_err(err_to_js)
    }

    /// Feed ciphertext; returns plaintext of fully authenticated chunks.
    /// Treat output as untrusted until `finish()` succeeds: truncation is
    /// only detected there.
    pub fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, JsValue> {
        let dec = self.inner.as_mut().ok_or_else(|| js_err("decryptor already finished"))?;
        let mut out = Vec::new();
        dec.update(data, &mut out).map_err(err_to_js)?;
        Ok(out)
    }

    /// Verify and return the final chunk. Throws on truncation or tampering.
    pub fn finish(&mut self) -> Result<Vec<u8>, JsValue> {
        let dec = self.inner.take().ok_or_else(|| js_err("decryptor already finished"))?;
        let mut out = Vec::new();
        dec.finish(&mut out).map_err(err_to_js)?;
        Ok(out)
    }
}

#[wasm_bindgen]
pub fn encrypt_file(
    plaintext: &[u8],
    recipient_public_key: &[u8],
    chunk_size: Option<u32>,
) -> Result<Vec<u8>, JsValue> {
    let cs = chunk_size.map(|c| c as usize).unwrap_or(file::CHUNK_SIZE_DEFAULT);
    file::encrypt_file(plaintext, recipient_public_key, cs).map_err(err_to_js)
}

#[wasm_bindgen]
pub fn decrypt_file(ciphertext: &[u8], dk_seed: &[u8]) -> Result<Vec<u8>, JsValue> {
    file::decrypt_file_with_seed(ciphertext, dk_seed).map_err(err_to_js)
}

/// Decrypt a file that was encrypted to a hybrid public key.
#[wasm_bindgen]
pub fn decrypt_file_hybrid(ciphertext: &[u8], hybrid_secret: &[u8]) -> Result<Vec<u8>, JsValue> {
    file::decrypt_file_with_hybrid_secret(ciphertext, hybrid_secret).map_err(err_to_js)
}

// ==========================================
// ML-DSA-65 wrapper
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
        pair(&seed, &vk)
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

impl Default for MlDsaKeyPair {
    fn default() -> Self {
        Self::new()
    }
}

// ==========================================
// ML-DSA-87 wrapper (CNSA 2.0 level)
// ==========================================

#[wasm_bindgen]
pub struct MlDsa87KeyPair {
    inner: CoreDsa87,
}

#[wasm_bindgen]
impl MlDsa87KeyPair {
    #[wasm_bindgen(constructor)]
    pub fn new() -> MlDsa87KeyPair {
        MlDsa87KeyPair {
            inner: CoreDsa87::new(),
        }
    }

    #[wasm_bindgen(js_name = exportKeys)]
    pub fn export_keys(&self) -> js_sys::Array {
        let (seed, vk) = self.inner.export_keys();
        pair(&seed, &vk)
    }

    #[wasm_bindgen(js_name = importKeys)]
    pub fn import_keys(seed: &[u8], vk: &[u8]) -> Result<MlDsa87KeyPair, JsValue> {
        CoreDsa87::import_keys(seed, vk)
            .map(|inner| MlDsa87KeyPair { inner })
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

impl Default for MlDsa87KeyPair {
    fn default() -> Self {
        Self::new()
    }
}

// ==========================================
// Secret-derived rooms with a forward-secure ratchet
// ==========================================

fn arrays_to_vecs(arr: &js_sys::Array, what: &str) -> Result<Vec<Vec<u8>>, JsValue> {
    let mut out = Vec::with_capacity(arr.length() as usize);
    for v in arr.iter() {
        let u8a = v
            .dyn_into::<js_sys::Uint8Array>()
            .map_err(|_| js_err(&format!("{what} must be an array of Uint8Array")))?;
        out.push(u8a.to_vec());
    }
    Ok(out)
}

fn to_array32(b: &[u8], what: &str) -> Result<[u8; 32], JsValue> {
    b.try_into().map_err(|_| js_err(&format!("{what} must be 32 bytes")))
}

/// Root secret of a room, derived from shared sources (passphrase, photo
/// hash, ...). Order of sources does not matter.
#[wasm_bindgen]
pub struct RoomSecret {
    inner: pqc::room::RoomSecret,
}

#[wasm_bindgen]
impl RoomSecret {
    /// `sources`: array of Uint8Array (1 to 16, non-empty). Defaults to 64 MiB / 3 passes / 1 lane.
    /// All members must use identical `context` and cost parameters.
    #[wasm_bindgen(js_name = derive)]
    pub fn derive(
        context: &str,
        sources: js_sys::Array,
        m_kib: Option<u32>,
        t_cost: Option<u32>,
        p_cost: Option<u32>,
    ) -> Result<RoomSecret, JsValue> {
        let owned = arrays_to_vecs(&sources, "sources")?;
        let refs: Vec<&[u8]> = owned.iter().map(|v| v.as_slice()).collect();
        let d = pqc::room::RoomKdfParams::DEFAULT;
        let params = pqc::room::RoomKdfParams::new(
            m_kib.unwrap_or(d.m_kib),
            t_cost.unwrap_or(d.t_cost),
            p_cost.unwrap_or(d.p_cost),
        );
        pqc::room::RoomSecret::derive(context, &refs, params)
            .map(|inner| RoomSecret { inner })
            .map_err(err_to_js)
    }

    #[wasm_bindgen(js_name = fromRoot)]
    pub fn from_root(root: &[u8]) -> Result<RoomSecret, JsValue> {
        Ok(RoomSecret {
            inner: pqc::room::RoomSecret::from_root(to_array32(root, "root")?),
        })
    }

    /// 32-byte root. Store only encrypted (`encrypt_private_key`).
    #[wasm_bindgen(js_name = exportRoot)]
    pub fn export_root(&self) -> Vec<u8> {
        self.inner.root_bytes().to_vec()
    }

    /// Routing key to give the server.
    #[wasm_bindgen(js_name = roomId)]
    pub fn room_id(&self) -> Vec<u8> {
        self.inner.room_id().to_vec()
    }

    /// Bearer token proving you know the secret. Send it to the server when
    /// joining; the server stores only `roomAuthVerifier(token)`.
    #[wasm_bindgen(js_name = authToken)]
    pub fn auth_token(&self) -> Vec<u8> {
        self.inner.auth_token().to_vec()
    }
}

/// What a server should store to check an auth token without learning it.
#[wasm_bindgen]
pub fn room_auth_verifier(auth_token: &[u8]) -> Result<Vec<u8>, JsValue> {
    Ok(pqc::room::auth_verifier(&to_array32(auth_token, "auth token")?).to_vec())
}

/// A decrypted room message.
#[wasm_bindgen]
pub struct Opened {
    plaintext: Vec<u8>,
    sender_id: Vec<u8>,
    epoch: u32,
    index: u32,
    signed: bool,
}

#[wasm_bindgen]
impl Opened {
    #[wasm_bindgen(getter)]
    pub fn plaintext(&self) -> Vec<u8> {
        self.plaintext.clone()
    }
    #[wasm_bindgen(getter, js_name = senderId)]
    pub fn sender_id(&self) -> Vec<u8> {
        self.sender_id.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn epoch(&self) -> u32 {
        self.epoch
    }
    #[wasm_bindgen(getter)]
    pub fn index(&self) -> u32 {
        self.index
    }
    /// True if the envelope carried a signature (verified only by `openVerified`).
    #[wasm_bindgen(getter)]
    pub fn signed(&self) -> bool {
        self.signed
    }
}

fn opened(o: pqc::room::Opened) -> Opened {
    Opened {
        plaintext: o.plaintext,
        sender_id: o.sender_id.to_vec(),
        epoch: o.epoch,
        index: o.index,
        signed: o.signed,
    }
}

/// One member's ratchet state in a room. Treat as secret.
#[wasm_bindgen]
pub struct Room {
    inner: pqc::room::Room,
}

#[wasm_bindgen]
impl Room {
    /// Join with a fresh random sender id.
    #[wasm_bindgen(constructor)]
    pub fn new(secret: &RoomSecret) -> Result<Room, JsValue> {
        pqc::room::Room::join(&secret.inner)
            .map(|inner| Room { inner })
            .map_err(err_to_js)
    }

    /// Restore from `exportState()`.
    #[wasm_bindgen(js_name = importState)]
    pub fn import_state(state: &[u8]) -> Result<Room, JsValue> {
        pqc::room::Room::import_state(state)
            .map(|inner| Room { inner })
            .map_err(err_to_js)
    }

    /// Full ratchet state. Secret: encrypt before storing.
    #[wasm_bindgen(js_name = exportState)]
    pub fn export_state(&self) -> Vec<u8> {
        self.inner.export_state()
    }

    #[wasm_bindgen(js_name = roomId)]
    pub fn room_id(&self) -> Vec<u8> {
        self.inner.room_id().to_vec()
    }

    #[wasm_bindgen(js_name = senderId)]
    pub fn sender_id(&self) -> Vec<u8> {
        self.inner.sender_id().to_vec()
    }

    pub fn epoch(&self) -> u32 {
        self.inner.epoch()
    }

    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, JsValue> {
        self.inner.seal(plaintext).map_err(err_to_js)
    }

    /// Encrypt and sign with ML-DSA-65.
    #[wasm_bindgen(js_name = sealSigned)]
    pub fn seal_signed(&mut self, plaintext: &[u8], signer: &MlDsaKeyPair) -> Result<Vec<u8>, JsValue> {
        let sign = |m: &[u8]| signer.inner.sign(m);
        self.inner.seal_signed(plaintext, &sign).map_err(err_to_js)
    }

    /// Encrypt and sign with ML-DSA-87.
    #[wasm_bindgen(js_name = sealSigned87)]
    pub fn seal_signed_87(&mut self, plaintext: &[u8], signer: &MlDsa87KeyPair) -> Result<Vec<u8>, JsValue> {
        let sign = |m: &[u8]| signer.inner.sign(m);
        self.inner.seal_signed(plaintext, &sign).map_err(err_to_js)
    }

    /// Decrypt without checking a signature (a present signature is ignored).
    pub fn open(&mut self, envelope: &[u8]) -> Result<Opened, JsValue> {
        self.inner.open(envelope, None).map(opened).map_err(err_to_js)
    }

    /// Require a valid ML-DSA signature by `verifyingKey` (65 or 87, by length).
    #[wasm_bindgen(js_name = openVerified)]
    pub fn open_verified(&mut self, envelope: &[u8], verifying_key: &[u8]) -> Result<Opened, JsValue> {
        let vk = verifying_key.to_vec();
        let verify = move |m: &[u8], sig: &[u8]| pqc::ml_dsa_verify(&vk, m, sig);
        self.inner
            .open(envelope, Some(&verify))
            .map(opened)
            .map_err(err_to_js)
    }

    /// Start a new epoch with fresh randomness wrapped to each member's
    /// public key (plain ML-KEM or hybrid; do not include your own). Returns
    /// the signed bundle bytes to relay to members.
    pub fn rekey(&mut self, member_public_keys: js_sys::Array, signer: &MlDsaKeyPair) -> Result<Vec<u8>, JsValue> {
        let owned = arrays_to_vecs(&member_public_keys, "member_public_keys")?;
        let refs: Vec<&[u8]> = owned.iter().map(|v| v.as_slice()).collect();
        let sign = |m: &[u8]| signer.inner.sign(m);
        self.inner.rekey(&refs, &sign).map(|b| b.to_bytes()).map_err(err_to_js)
    }

    #[wasm_bindgen(js_name = rekey87)]
    pub fn rekey_87(&mut self, member_public_keys: js_sys::Array, signer: &MlDsa87KeyPair) -> Result<Vec<u8>, JsValue> {
        let owned = arrays_to_vecs(&member_public_keys, "member_public_keys")?;
        let refs: Vec<&[u8]> = owned.iter().map(|v| v.as_slice()).collect();
        let sign = |m: &[u8]| signer.inner.sign(m);
        self.inner.rekey(&refs, &sign).map(|b| b.to_bytes()).map_err(err_to_js)
    }

    /// Apply a bundle from another member. `senderVerifyingKey` is the ML-DSA
    /// key you trust for that member; the signature is checked first.
    #[wasm_bindgen(js_name = applyRekeyHybrid)]
    pub fn apply_rekey_hybrid(&mut self, bundle: &[u8], my_key: &HybridKeyPair, sender_verifying_key: &[u8]) -> Result<(), JsValue> {
        let b = pqc::room::RekeyBundle::from_bytes(bundle).map_err(err_to_js)?;
        let vk = sender_verifying_key.to_vec();
        let verify = move |m: &[u8], sig: &[u8]| pqc::ml_dsa_verify(&vk, m, sig);
        self.inner.apply_rekey(&b, &my_key.inner, &verify).map_err(err_to_js)
    }

    #[wasm_bindgen(js_name = applyRekeyKem)]
    pub fn apply_rekey_kem(&mut self, bundle: &[u8], my_key: &MlKemKeyPair, sender_verifying_key: &[u8]) -> Result<(), JsValue> {
        let b = pqc::room::RekeyBundle::from_bytes(bundle).map_err(err_to_js)?;
        let vk = sender_verifying_key.to_vec();
        let verify = move |m: &[u8], sig: &[u8]| pqc::ml_dsa_verify(&vk, m, sig);
        self.inner.apply_rekey(&b, &my_key.inner, &verify).map_err(err_to_js)
    }

    /// Delete keys of epochs older than `epoch` (forward secrecy for them).
    #[wasm_bindgen(js_name = forgetEpochsBefore)]
    pub fn forget_epochs_before(&mut self, epoch: u32) {
        self.inner.forget_epochs_before(epoch);
    }
}

/// Verify an ML-DSA signature with only a verifying key (65 or 87 by length).
#[wasm_bindgen]
pub fn ml_dsa_verify(verifying_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    pqc::ml_dsa_verify(verifying_key, message, signature)
}

// ==========================================
// Passphrase encryption
// ==========================================

/// Argon2id + ChaCha20-Poly1305. Output is a versioned blob (`CBPK`).
#[wasm_bindgen]
pub fn encrypt_private_key(plaintext: &[u8], passphrase: &str) -> Result<Vec<u8>, JsValue> {
    pqc::encrypt_private_key(plaintext, passphrase).map_err(err_to_js)
}

/// Throws on a wrong passphrase or tampered data (it no longer returns an
/// empty array). Also reads blobs written by 0.3.x.
#[wasm_bindgen]
pub fn decrypt_private_key(encrypted: &[u8], passphrase: &str) -> Result<Vec<u8>, JsValue> {
    pqc::decrypt_private_key(encrypted, passphrase).map_err(err_to_js)
}
