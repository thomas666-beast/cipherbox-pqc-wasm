# Cipherbox PQC WASM

**Post-Quantum Cryptography for the Web (WebAssembly)**

`cipherbox-pqc-wasm` provides a high-performance, memory-safe, WebAssembly wrapper around the NIST Post-Quantum Cryptography standards (FIPS 203 and FIPS 204). It is designed for zero-knowledge web applications, secure messaging, and E2EE file sharing.

## Features

- **ML-KEM (Kyber-768)**: For Post-Quantum Key Encapsulation (KEM).
- **ML-DSA (Dilithium-3)**: For Post-Quantum Digital Signatures.
- **ChaCha20-Poly1305**: For symmetric encryption (AEAD).
- **Argon2**: For memory-hard passphrase-based key derivation.
- **Zero-Knowledge Architecture**: Designed to keep private keys strictly inside the browser's memory or IndexedDB.

## Installation

You can build this crate from source using [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/).

First, clone the repository and navigate into the folder:

    git clone https://github.com/yourusername/cipherbox-pqc-wasm.git
    cd cipherbox-pqc-wasm

Then, build the WASM module:

    wasm-pack build --target web

This will generate a `pkg` folder containing the JavaScript bindings and the `.wasm` binary, which you can import directly into your frontend project.

## Usage (JavaScript / Vue.js)

### 1. Initialization

Import the generated JavaScript file and initialize the WASM module:

    import init, { MlKemKeyPair, MlDsaKeyPair } from './pkg/cipherbox_pqc_wasm.js';

    async function setup() {
        await init();
        console.log("WASM Loaded");
    }

### 2. Generate a Post-Quantum Identity (Keys)

You can generate ML-KEM (Kyber) keys for encryption and ML-DSA (Dilithium) keys for signatures:

    // Generate ML-KEM (Kyber) for Encryption
    const kemKeypair = new MlKemKeyPair();
    const kemKeys = kemKeypair.exportKeys();
    const kemSecret = new Uint8Array(kemKeys[0]);
    const kemPublic = new Uint8Array(kemKeys[1]);

    // Generate ML-DSA (Dilithium) for Signatures
    const dsaKeypair = new MlDsaKeyPair();
    const dsaKeys = dsaKeypair.exportKeys();
    const dsaSecret = new Uint8Array(dsaKeys[0]);
    const dsaPublic = new Uint8Array(dsaKeys[1]);

### 3. Encrypt Private Keys for Storage (Argon2 + ChaCha20)

Never store raw private keys. Encrypt them with a passphrase before saving to IndexedDB or LocalStorage:

    import { encrypt_private_key, decrypt_private_key } from './pkg/cipherbox_pqc_wasm.js';

    const passphrase = "my-super-secret-passphrase";

    // Encrypt
    const encryptedDsaSecret = encrypt_private_key(dsaSecret, passphrase);

    // Decrypt
    const decryptedDsaSecret = decrypt_private_key(encryptedDsaSecret, passphrase);
    if (decryptedDsaSecret.length === 0) {
        throw new Error("Wrong passphrase");
    }

### 4. Key Encapsulation (ML-KEM)

To share a secret with someone using their public key:

    // Sender side: Encapsulate a shared secret using the recipient's public key
    const kem = MlKemKeyPair.importKeys(new Uint8Array(0), recipientPublicKey);
    const result = kem.encapsulate();
    const ciphertext = new Uint8Array(result[0]);
    const sharedSecret = new Uint8Array(result[1]);

    // Recipient side: Decapsulate the shared secret
    const myKem = MlKemKeyPair.importKeys(myPrivateKey, myPublicKey);
    const decapsulatedSecret = myKem.decapsulate(ciphertext);

### 5. Digital Signatures (ML-DSA)

To sign a message and verify it:

    const keypair = MlDsaKeyPair.importKeys(dsaSecret, dsaPublic);
    const message = new TextEncoder().encode("Hello World");

    // Sign
    const signature = keypair.sign(message);

    // Verify
    const isValid = keypair.verify(message, signature);

## Security Considerations

- **Memory Management**: This library allocates WASM memory. If you are generating many keypairs in a loop, ensure you call `.free()` on the objects to prevent memory leaks.
- **Key Storage**: Private keys must be encrypted with `encrypt_private_key` before being saved to browser storage.
- **Side-Channels**: While the underlying Rust crates (`ml-kem`, `ml-dsa`) are designed to be constant-time, WebAssembly execution environments may introduce timing variations. Do not use this for high-frequency trading or hardware security modules (HSMs).

## License

This project is licensed under the MIT License.
