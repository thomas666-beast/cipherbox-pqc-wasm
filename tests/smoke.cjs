const assert = require("node:assert/strict");
const path = require("node:path");
const { webcrypto } = require("node:crypto");

globalThis.crypto ??= webcrypto;
const pqc = require(path.resolve(process.argv[2]));
const root = pqc.RoomSecret.generate();
const alice = new pqc.Room(root);
const bob = new pqc.Room(root);
const dsa = new pqc.MlDsa87KeyPair();
const [, vk] = dsa.exportKeys();
const message = new TextEncoder().encode("signed WASM room message");
const envelope = alice.sealSigned87(message, dsa);
assert.throws(() => bob.openFrom(envelope, bob.senderId(), vk));
const opened = bob.openFrom(envelope, alice.senderId(), vk);
assert.deepEqual(opened.plaintext, message);
assert.equal(opened.signatureVerified, true);
assert.throws(() => bob.openFrom(envelope, alice.senderId(), vk));
const relaxed = bob.open(alice.sealSigned87(message, dsa));
assert.equal(relaxed.signed, true);
assert.equal(relaxed.signatureVerified, false);

const deviceKey = webcrypto.getRandomValues(new Uint8Array(32));
const roomId = bob.roomId();
const snapshot = bob.exportEncryptedState(deviceKey);
const restored = pqc.Room.restoreEncryptedState(snapshot, deviceKey, roomId, 0);
assert.notDeepEqual(restored.senderId(), bob.senderId());
assert.throws(() => restored.openFrom(envelope, alice.senderId(), vk));
assert.throws(() => pqc.Room.restoreEncryptedState(snapshot, deviceKey, roomId, 1));
assert.throws(() => pqc.Room.restoreEncryptedState(snapshot, deviceKey, new Uint8Array(32), 0));

const kem = new pqc.HybridKeyPair(1024);
const encrypted = pqc.encrypt_file(message, kem.publicKey(), 64);
assert.deepEqual(pqc.decrypt_file_hybrid(encrypted, kem.exportSecret()), message);
console.log("WASM smoke passed: verified messages, replay, encrypted restore, hybrid file");
