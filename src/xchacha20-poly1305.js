import { xchacha20poly1305 } from "./noble-ciphers/chacha.mjs";

export function encryptXChaCha20Poly1305(
    plaintext,
    key,
    nonce,
) {
    const cipher = xchacha20poly1305(key, nonce);
    return cipher.encrypt(plaintext);
}

export function decryptXChaCha20Poly1305(
    ciphertext,
    key,
    nonce,
) {
    const cipher = xchacha20poly1305(key, nonce);
    return cipher.decrypt(ciphertext);
}
