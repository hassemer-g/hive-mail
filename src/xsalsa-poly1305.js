import { xsalsa20poly1305 } from "./noble-ciphers/salsa.mjs";

export function encryptXSalsaPoly1305(
    plaintext,
    key,
    nonce,
) {

    const cipher = xsalsa20poly1305(key, nonce);

    return cipher.encrypt(plaintext);
}

export function decryptXSalsaPoly1305(
    ciphertext,
    key,
    nonce,
) {

    const cipher = xsalsa20poly1305(key, nonce);

    return cipher.decrypt(ciphertext);
}
