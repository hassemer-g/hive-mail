import { gcmsiv } from "./noble-ciphers/aes.mjs";

export function encryptAesGcmSiv(
    plaintext,
    key,
    nonce,
) {
    const cipher = gcmsiv(key, nonce);
    return cipher.encrypt(plaintext);
}

export function decryptAesGcmSiv(
    ciphertext,
    key,
    nonce,
) {
    const cipher = gcmsiv(key, nonce);
    return cipher.decrypt(ciphertext);
}
