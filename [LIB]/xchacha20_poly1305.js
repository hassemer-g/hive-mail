import { xchacha20poly1305 } from "@noble/ciphers/chacha";


// ==================================================================== //


// Encrypt using XChaCha20-Poly1305
export function encryptXChaCha20Poly1305(
    plaintext, // Uint8Array
    key, // Uint8Array
    nonce, // Uint8Array
) {

    // Ensure correct inputs
    if (!(plaintext instanceof Uint8Array)) {
        throw new Error("Plaintext is supposed to be a Uint8Array.");
    }
    if (!(key instanceof Uint8Array) || key.length !== 32) {
        throw new Error("Key is supposed to be 32-byte Uint8Array.");
    }
    if (!(nonce instanceof Uint8Array) || nonce.length !== 24) {
        throw new Error("Nonce is supposed to be 24-byte Uint8Array.");
    }

    const cipher = xchacha20poly1305(key, nonce);

    return cipher.encrypt(plaintext);  // returns Uint8Array
}


// Decrypt XChaCha20-Poly1305
export function decryptXChaCha20Poly1305(
    ciphertext, // Uint8Array
    key, // Uint8Array
    nonce, // Uint8Array
) {

    // Ensure correct inputs
    if (!(ciphertext instanceof Uint8Array)) {
        throw new Error("Ciphertext is supposed to be a Uint8Array.");
    }
    if (!(key instanceof Uint8Array) || key.length !== 32) {
        throw new Error("Key is supposed to be 32-byte Uint8Array.");
    }
    if (!(nonce instanceof Uint8Array) || nonce.length !== 24) {
        throw new Error("Nonce is supposed to be 24-byte Uint8Array.");
    }

    const cipher = xchacha20poly1305(key, nonce);

    return cipher.decrypt(ciphertext);  // returns Uint8Array
}


